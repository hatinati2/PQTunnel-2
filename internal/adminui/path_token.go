package adminui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
)

var pathTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// WithPathToken restricts a public management UI to a per-install, 256-bit URL
// path token. It rewrites same-origin links, form actions, redirects and cookie
// paths so the existing handler can continue to use its root-relative routes.
//
// This is defense in depth only. A path token does not encrypt HTTP traffic or
// replace the manager login token, and can be disclosed by network observers.
func WithPathToken(token string, next http.Handler) (http.Handler, error) {
	if !pathTokenPattern.MatchString(token) {
		return nil, http.ErrNoCookie // invalid server configuration; never start an unguarded panel
	}
	if next == nil {
		return nil, http.ErrHandlerTimeout
	}

	prefix := "/" + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil || (r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/")) {
			http.NotFound(w, r)
			return
		}

		clone := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(u.Path, prefix)
		if u.Path == "" {
			u.Path = "/"
		}
		u.RawPath = ""
		clone.URL = &u

		recorder := httptest.NewRecorder()
		next.ServeHTTP(recorder, clone)

		for key, values := range recorder.Header() {
			for _, value := range values {
				if key == "Location" && strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") &&
					!strings.HasPrefix(value, prefix+"/") && value != prefix {
					value = prefix + value
				}
				if key == "Set-Cookie" {
					value = strings.ReplaceAll(value, "; Path=/;", "; Path="+prefix+"/;")
					value = strings.ReplaceAll(value, "; Path=/", "; Path="+prefix+"/")
				}
				w.Header().Add(key, value)
			}
		}

		body := recorder.Body.Bytes()
		if strings.HasPrefix(strings.ToLower(recorder.Header().Get("Content-Type")), "text/html") {
			html := string(body)
			html = strings.ReplaceAll(html, `href="/`, `href="`+prefix+`/`)
			html = strings.ReplaceAll(html, `action="/`, `action="`+prefix+`/`)
			html = strings.ReplaceAll(html, `formaction="/`, `formaction="`+prefix+`/`)
			body = []byte(html)
			w.Header().Set("Content-Length", http.Header{"X": {""}}.Get("X"))
			w.Header().Set("Content-Length", strings.TrimSpace(strings.Repeat("", 0)))
			// A buffered response has a different length after URL rewriting.
			w.Header().Set("Content-Length", itoa(len(body)))
		}
		status := recorder.Code
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}), nil
}

func itoa(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = digits[value%10]
		value /= 10
	}
	return string(buf[i:])
}
