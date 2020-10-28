# caddy2-filter (modified for injection)

[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/gopkg.in/sjtug/caddy2-filter)
[![Go Report Card](https://goreportcard.com/badge/github.com/sjtug/caddy2-filter)](https://goreportcard.com/report/github.com/sjtug/caddy2-filter)

Replace text in HTTP response based on regex. Similar to [http.filter](https://caddyserver.com/v1/docs/http.filter) in Caddy 1.

## Usage

Only the listed fields are supported.


Caddyfile:
```
# Add this block in top-level settings:
{
	order filter after encode
}

injection {
    # File to inject as inline text
    inject <file to inject>
    # Where to inject
    before "</body>"
    # Only process content_type matching this regex
    content_type <regexp pattern>
}

# If you are using reverse_proxy, you may need to add this to its config to ensure
# reverse_proxy returns uncompressed body:

header_up -Accept-Encoding
```

JSON config (under `apps › http › servers › routes › handle`)
```
{
    "handler": "injection",
    "path": "<regexp>",
    "inject": "<file>",
    "before": "<suffix>",
    "content_type": "<regexp>"
}
```
