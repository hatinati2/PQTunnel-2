package adminui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
)

func TestWithPathTokenProtectsAndRewritesPanelRoutes(t *testing.T) {
	const pathToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const loginToken = "unit-test-manager-token-with-at-least-32-bytes"
	controller := &fakeManagerController{
		fakeController: &fakeController{},
		view: adminapi.ManagerSnapshot{Role: "gateway", ActiveState: "active"},
	}
	handler, err := New(loginToken, controller)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WithPathToken(pathToken, handler)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/", "/login", "/wrong/" + pathToken + "/"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:6100"+path, nil)
		resp := httptest.NewRecorder()
		wrapped.ServeHTTP(resp, req)
		if resp.Code != http.StatusNotFound {
			t.Errorf("request to %q status=%d, want 404", path, resp.Code)
		}
	}

	values := url.Values{"token": {loginToken}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:6100/"+pathToken+"/login", strings.NewReader(values.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://127.0.0.1:6100")
	loginResp := httptest.NewRecorder()
	wrapped.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusSeeOther || loginResp.Header().Get("Location") != "/"+pathToken+"/" {
		t.Fatalf("login status=%d location=%q", loginResp.Code, loginResp.Header().Get("Location"))
	}
	cookies := loginResp.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/"+pathToken+"/" || !cookies[0].HttpOnly {
		t.Fatalf("session cookie not scoped to secret path: %#v", cookies)
	}

	dashboardReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:6100/"+pathToken+"/", nil)
	dashboardReq.AddCookie(cookies[0])
	dashboardResp := httptest.NewRecorder()
	wrapped.ServeHTTP(dashboardResp, dashboardReq)
	body := dashboardResp.Body.String()
	if dashboardResp.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d body=%s", dashboardResp.Code, body)
	}
	if dashboardResp.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("secret path must not be sent in Referer headers, got %q", dashboardResp.Header().Get("Referrer-Policy"))
	}
	if !strings.Contains(body, `action="/`+pathToken+`/logout"`) ||
		!strings.Contains(body, `href="/`+pathToken+`/logs"`) {
		t.Fatalf("dashboard links were not kept under the secret path: %s", body)
	}
	if strings.Contains(body, `action="/logout"`) || strings.Contains(body, `href="/logs"`) {
		t.Fatal("dashboard exposed a root-relative admin route")
	}
}

func TestWithPathTokenRejectsMalformedTokens(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, err := WithPathToken(token, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
			t.Errorf("WithPathToken(%q) unexpectedly succeeded", token)
		}
	}
}
