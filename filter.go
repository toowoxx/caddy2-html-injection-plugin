package filter

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const MaxSizeToFilter = 2 * 1024 * 1024

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("filter", parseCaddyfile)
}

// Middleware implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type Middleware struct {
	// Regex to specify which kind of response should we filter
	ContentType string `json:"content_type"`
	// Regex to specify which pattern to look up
	SearchPattern string `json:"search_pattern"`
	// A string specifying the string used to replace matches
	Replacement string `json:"replacement"`

	compiledContentTypeRegex *regexp.Regexp
	compiledSearchRegex      *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.filter",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(_ caddy.Context) error {
	var err error
	if m.compiledContentTypeRegex, err = regexp.Compile(m.ContentType); err != nil {
		return fmt.Errorf("invalid content_type: %w", err)
	}
	if m.compiledSearchRegex, err = regexp.Compile(m.SearchPattern); err != nil {
		return fmt.Errorf("invalid search_pattern: %w", err)
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return nil
}

// CappedSizeRecorder is like httptest.ResponseRecorder,
// but with a cap.
//
// When the size of body exceeds cap,
// CappedSizeRecorder flushes all contents in ResponseRecorder
// together with all subsequent writes into the ResponseWriter
type CappedSizeRecorder struct {
	overflowed bool
	recorder   *httptest.ResponseRecorder
	w          http.ResponseWriter
	cap        int
}

func NewCappedSizeRecorder(cap int, w http.ResponseWriter) *CappedSizeRecorder {
	return &CappedSizeRecorder{
		overflowed: false,
		recorder:   httptest.NewRecorder(),
		w:          w,
		cap:        cap,
	}
}

func (csr *CappedSizeRecorder) Overflowed() bool {
	return csr.overflowed
}

func (csr *CappedSizeRecorder) Header() http.Header {
	return csr.recorder.Header()
}

func (csr *CappedSizeRecorder) FlushHeaders() {
	if !csr.overflowed {
		log.Fatal("onOverflow called when overflowed is false")
	}
	for k, vs := range csr.recorder.Header() {
		for _, v := range vs {
			csr.w.Header().Add(k, v)
		}
	}
	csr.w.WriteHeader(csr.recorder.Code)
}

// Flush contents to writer
func (csr *CappedSizeRecorder) Flush() (int64, error) {
	csr.FlushHeaders()
	return io.Copy(csr.w, csr.recorder.Body)
}

func (csr *CappedSizeRecorder) Recorder() *httptest.ResponseRecorder {
	if csr.overflowed {
		log.Fatal("trying to get Recorder when overflowed")
	}
	return csr.recorder
}

func (csr *CappedSizeRecorder) Write(b []byte) (int, error) {
	if !csr.overflowed && len(b)+csr.recorder.Body.Len() > csr.cap {
		csr.overflowed = true
		if written, err := csr.Flush(); err != nil {
			return int(written), err
		}
	}
	if csr.overflowed {
		return csr.w.Write(b)
	} else {
		return csr.recorder.Write(b)
	}
}

func (csr *CappedSizeRecorder) WriteHeader(statusCode int) {
	if csr.overflowed {
		log.Fatal("CappedSizeRecorder overflowed on WriteHeader")
	}
	csr.recorder.WriteHeader(statusCode)
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	csr := NewCappedSizeRecorder(MaxSizeToFilter, w)
	nextErr := next.ServeHTTP(csr, r)
	if csr.Overflowed() {
		return nextErr
	}
	csr.FlushHeaders()
	if m.compiledContentTypeRegex.MatchString(csr.Recorder().Result().Header.Get("Content-Type")) {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(csr.Recorder().Result().Body); err != nil {
			return fmt.Errorf("failed to read from response body: %w", err)
		}
		replaced := m.compiledSearchRegex.ReplaceAll(buf.Bytes(), []byte(m.Replacement))
		if _, err := io.Copy(w, bytes.NewReader(replaced)); err != nil {
			return fmt.Errorf("error when copying replaced response body: %w", err)
		}
	} else {
		if _, err := io.Copy(w, csr.recorder.Body); err != nil {
			return fmt.Errorf("error when copying response body: %w", err)
		}
	}
	return nextErr
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.NextBlock(0) {
		for d.NextLine() {
			key := d.Token().Text
			if !d.NextArg() {
				return fmt.Errorf("missing val following %s", key)
			}
			value := d.Token().Text
			switch key {
			case "content_type":
				m.ContentType = value
			case "search_pattern":
				m.SearchPattern = value
			case "replacement":
				m.Replacement = value
			default:
				return fmt.Errorf("invalid key for filter directive: %s", key)
			}
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
