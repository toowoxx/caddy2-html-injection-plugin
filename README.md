# caddy2-filter (modified for injection)

[![GoDoc](http://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/gopkg.in/sjtug/caddy2-filter)
[![Go Report Card](https://goreportcard.com/badge/github.com/sjtug/caddy2-filter)](https://goreportcard.com/report/github.com/sjtug/caddy2-filter)

Replace text in HTTP response based on regex. Similar to [http.filter](https://caddyserver.com/v1/docs/http.filter) in Caddy 1.

Originally released on https://github.com/sjtug/caddy2-filter

## Usage

Only the listed fields are supported.


Caddyfile:
```
# Add this block in top-level settings:
{
	order injection after encode
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

## License

```
   Copyright 2020 Zheng Luo
   Copyright 2020 Toowoxx IT GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
