package adminui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
)

func validPathToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// WithPathToken restricts a public management UI to a per-install, 256-bit URL
// path token. It rewrites same-origin links, form actions, redirects and cookie
// paths so the existing handler can continue to use its root-relative routes.
//
// This is defense in depth only. A path token does not encrypt HTTP traffic or
// replace the manager login token, and can be disclosed by network observers.
func WithPathToken(token string, next http.Handler) (http.Handler, error) {
	if !validPathToken(token) {
		return nil, errors.New("manager path token must be exactly 64 lowercase hexadecimal characters")
	}
	if next == nil {
		return nil, errors.New("manager handler is required")
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
					parts := strings.Split(value, ";")
					for i := 1; i < len(parts); i++ {
						if strings.EqualFold(strings.TrimSpace(parts[i]), "Path=/") {
							parts[i] = " Path=" + prefix + "/"
						}
					}
					value = strings.Join(parts, ";")
				}
				w.Header().Add(key, value)
			}
		}

		// Never disclose the secret path in a Referer header when the page
		// navigates to an external origin.
		w.Header().Set("Referrer-Policy", "same-origin")

		body := recorder.Body.Bytes()
		if strings.HasPrefix(strings.ToLower(recorder.Header().Get("Content-Type")), "text/html") {
			html := string(body)
			html = strings.ReplaceAll(html, `href="/`, `href="`+prefix+`/`)
			html = strings.ReplaceAll(html, `action="/`, `action="`+prefix+`/`)
			html = strings.ReplaceAll(html, `formaction="/`, `formaction="`+prefix+`/`)
			body = []byte(html)
			// The response was buffered for link rewriting, so discard any stale
			// content length and publish the exact rewritten length.
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		status := recorder.Code
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}), nil
}
