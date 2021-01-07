package injection

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("injection", parseCaddyfile)
}

type Middleware struct {
	// Regex to specify which kind of response should we filter
	ContentType string `json:"content_type"`
	Inject      string `json:"inject"`
	Before      string `json:"before"`

	compiledContentTypeRegex *regexp.Regexp

	Logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.injection",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.Logger = ctx.Logger(m)
	m.Logger.Info("Provisioning injection plugin",
		zap.String("ContentType", m.ContentType),
		zap.String("Inject", m.Inject))
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	var err error
	if m.compiledContentTypeRegex, err = regexp.Compile(m.ContentType); err != nil {
		return fmt.Errorf("invalid regex content_type: %w", err)
	}
	return nil
}

type ContentTypeStatus int

const (
	toBeChecked ContentTypeStatus = iota
	noMatch
	matches
)

type LineHandler interface {
	HandleLine(line string) (string, error)
}

type InjectedWriter struct {
	OriginalWriter    http.ResponseWriter
	Request           *http.Request
	RecordedHTML      bytes.Buffer
	totalBytesWritten int
	Logger            *zap.Logger
	contentTypeStatus ContentTypeStatus
	LineHandler       LineHandler
	cspNonce		  string
	M                 *Middleware
}

func (i InjectedWriter) Header() http.Header {
	return i.OriginalWriter.Header()
}

func (i *InjectedWriter) Write(bytes []byte) (int, error) {
	if i.LineHandler == nil {
		i.LineHandler = i
	}
	if i.contentTypeStatus == noMatch {
		return i.OriginalWriter.Write(bytes)
	} else if i.contentTypeStatus == toBeChecked && !i.M.compiledContentTypeRegex.MatchString(
		strings.Split(i.OriginalWriter.Header().Get("Content-Type"), ";")[0]) {
		i.contentTypeStatus = noMatch
		return i.OriginalWriter.Write(bytes)
	}
	i.contentTypeStatus = matches
	i.RecordedHTML.Write(bytes)
	recordedString := i.RecordedHTML.String()
	if strings.ContainsRune(recordedString, '\n') {
		i.RecordedHTML.Truncate(0)
		isLastLineComplete := false
		if strings.HasSuffix(recordedString, "\n") {
			isLastLineComplete = true
		}
		lines := strings.Split(recordedString, "\n")
		for index, line := range lines {
			if !isLastLineComplete && index == len(lines)-1 {
				// Write the incomplete line back into the buffer
				i.RecordedHTML.WriteString(line)
				break
			}
			newString, err := i.LineHandler.HandleLine(line)
			if err != nil {
				return 0, err
			}
			newString += "\n"
			newBytes := []byte(newString)
			bytesWritten, err := i.OriginalWriter.Write(newBytes)
			if err != nil {
				return 0, errors.Wrap(err, "error occurred while writing out response bytes")
			}
			if bytesWritten != len(newBytes) {
				return bytesWritten, errors.Wrap(err, "couldn't write out complete response bytes")
			}
			i.totalBytesWritten += bytesWritten
		}
	}
	return len(bytes), nil
}

func (i *InjectedWriter) textToInject() (string, error) {
	if len(i.M.Inject) == 0 {
		return "", nil
	}
	content, err := ioutil.ReadFile(i.M.Inject)
	if err != nil {
		i.Logger.Warn("Could not read file to inject!", zap.Error(err))
		return "", err
	}
	contentString := string(content)
	return contentString, nil
}

func (i *InjectedWriter) HandleLine(line string) (string, error) {
	if strings.Contains(line, i.M.Before) {
		textToInject, err := i.textToInject()
		textToInject = i.HandleCSPForText(textToInject)
		if err != nil {
			return line, nil
		}
		return strings.Replace(line, i.M.Before, textToInject+i.M.Before, 1), nil
	}
	return line, nil
}

func extractValueForDirective(csp string, name string) string {
	if !strings.Contains(csp, name + " ") {
		return ""
	}
	return strings.TrimSpace(
		strings.Split(strings.Split(csp, name + " ")[1], ";")[0])
}

func (i *InjectedWriter) HandleCSP() error {
	csp := i.OriginalWriter.Header().Get("Content-Security-Policy")
	if len(strings.TrimSpace(csp)) != 0 {
		var err error
		i.cspNonce, err = GenerateRandomStringURLSafe(6)
		if err != nil {
			return err
		}
		defaultSrc := extractValueForDirective(csp, "default-src")
		if len(defaultSrc) == 0 {
			defaultSrc = "'self' https: 'unsafe-eval' 'unsafe-inline' 'unsafe-hashes'"
			csp = fmt.Sprintf("default-src %s; %s", defaultSrc, csp)
		}
		cspSrcArg := fmt.Sprintf("'nonce-%s'", i.cspNonce)
		if strings.Contains(csp, "script-src ") {
			if !strings.Contains(
				extractValueForDirective(csp, "script-src"),
				"'unsafe-inline'",
			) {
				// we need to add a source instead of adding the entire directive
				csp = strings.Replace(csp, "script-src ", fmt.Sprintf("script-src %s ", cspSrcArg), 1)
			}
		} else {
			cspSrcArgFinal := cspSrcArg
			if strings.Contains(defaultSrc, "'unsafe-inline'") {
				// Skip nonce if unsafe-inline otherwise it will be disabled
				cspSrcArgFinal = ""
			}
			csp += fmt.Sprintf("; script-src %s %s", defaultSrc, cspSrcArgFinal)
		}
		if strings.Contains(csp, "style-src ") {
			if !strings.Contains(
				extractValueForDirective(csp, "style-src"),
				"'unsafe-inline'",
			) {
				// we need to add a source instead of adding the entire directive
				csp = strings.Replace(csp, "style-src ", fmt.Sprintf("style-src %s ", cspSrcArg), 1)
			}
		} else {
			cspSrcArgFinal := cspSrcArg
			if strings.Contains(defaultSrc, "'unsafe-inline'") {
				// Skip nonce if unsafe-inline otherwise it will be disabled
				cspSrcArgFinal = ""
			}
			csp += fmt.Sprintf("; style-src %s %s", defaultSrc, cspSrcArgFinal)
		}
		i.OriginalWriter.Header().Set("Content-Security-Policy", csp)
	}

	return nil
}

func (i *InjectedWriter) HandleCSPForText(line string) string {
	if len(i.cspNonce) == 0 {
		// Remove nonce attributes since CSP is not active
		return strings.ReplaceAll(line, " nonce=\"{{csp-nonce}}\"", "")
	}
	return strings.ReplaceAll(line, "{{csp-nonce}}", i.cspNonce)
}

func (i *InjectedWriter) Flush() error {
	var err error
	finalString := i.RecordedHTML.String()
	if len(finalString) > 0 {
		finalString, err = i.LineHandler.HandleLine(finalString)
		if err != nil {
			return err
		}
		n, err := i.OriginalWriter.Write([]byte(finalString))
		if err != nil {
			return err
		}
		i.totalBytesWritten += n
	}
	return nil
}

func (i *InjectedWriter) WriteHeader(statusCode int) {
	// Ignore error because it's not critical
	_ = i.HandleCSP()
	i.OriginalWriter.Header().Del("Content-Length")
	i.OriginalWriter.WriteHeader(statusCode)
}

func CreateInjectedWriter(
	w http.ResponseWriter, r *http.Request, m *Middleware,
) *InjectedWriter {
	iw := &InjectedWriter{
		OriginalWriter: w,
		Request:        r,
		RecordedHTML:   bytes.Buffer{},
		Logger:         m.Logger,
		M:              m,
	}
	if len(m.ContentType) == 0 {
		iw.contentTypeStatus = matches
	}
	return iw
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var err error

	r.Header.Set("Accept-Encoding", "identity")
	injectedWriter := CreateInjectedWriter(w, r, &m)

	err = next.ServeHTTP(injectedWriter, r)
	if err != nil {
		return err
	}
	if err := injectedWriter.Flush(); err != nil {
		return err
	}
	m.Logger.Debug("", zap.Int("total bytes written", injectedWriter.totalBytesWritten))
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following injection")
	}
	for d.NextBlock(0) {
		key := d.Val()
		var value string
		d.Args(&value)
		if d.NextArg() {
			return d.ArgErr()
		}
		switch key {
		case "content_type":
			m.ContentType = value
		case "inject":
			m.Inject = value
		case "before":
			m.Before = value
		default:
			return d.Err(fmt.Sprintf("invalid key for injection directive: %s", key))
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
