package fleetui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
	"github.com/hatinati2/PQTunnel-2/internal/fleet"
)

type fakeCoordinator struct {
	snapshot fleet.DashboardSnapshot
	invite string
}

func (f *fakeCoordinator) Snapshot() fleet.DashboardSnapshot { return f.snapshot }
func (f *fakeCoordinator) CreateInvite() (string, time.Time, error) { return f.invite, time.Now().Add(15*time.Minute), nil }
func (f *fakeCoordinator) Execute(_ context.Context, role string, command fleet.Command) (fleet.CommandResult, error) {
	return fleet.CommandResult{Success: true, Logs: "test logs"}, nil
}
func (f *fakeCoordinator) PairNodes(context.Context, string, int, string, string) error { return nil }

func TestMobileFleetLoginDashboardAndInvite(t *testing.T) {
	const loginToken = "fleet-panel-login-token-with-at-least-32-bytes"
	const installRef = "0123456789abcdef0123456789abcdef01234567"
	coordinator := &fakeCoordinator{
		invite: strings.Repeat("a", 64),
		snapshot: fleet.DashboardSnapshot{
			Gateway: adminapi.ManagerSnapshot{
				Role: "gateway", ServiceUnit: "pqtunneld-transport.service",
				ActiveState: "active", SubState: "running", ConfigReady: true,
				Config: adminapi.TunnelConfiguration{
					ListenAddress: "0.0.0.0:8443", PeerIdentity: "10.66.0.2",
					PeerPrefixes: "10.66.0.2/32", LocalPrefixes: "10.66.0.1/32",
					AllowedDstPorts: "tcp:443",
				},
			},
			Dialer: fleet.NodeSnapshot{
				ID: "0123456789abcdef0123456789abcdef", Name: "dialer",
				Connected: true, LastSeen: time.Now(),
				Snapshot: adminapi.ManagerSnapshot{
					Role: "dialer", ServiceUnit: "pqtunnel-client-transport.service",
					ActiveState: "active", SubState: "running", ConfigReady: true,
					Config: adminapi.TunnelConfiguration{
						ServerAddress: "gateway.example:8443", ServerName: "gateway.example",
						LocalPrefixes: "10.66.0.2/32", RemotePrefixes: "10.66.0.1/32",
						AllowedDstPorts: "tcp:443",
					},
				},
			},
		},
	}
	h, err := New(loginToken, coordinator, "http://198.51.100.10:6100/"+strings.Repeat("b", 64), installRef)
	if err != nil { t.Fatal(err) }

	loginValues := url.Values{"token": {loginToken}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://198.51.100.10:6100/login", strings.NewReader(loginValues.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://198.51.100.10:6100")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusSeeOther { t.Fatalf("login status=%d body=%s", loginResp.Code, loginResp.Body.String()) }
	cookies := loginResp.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie not hardened: %#v", cookies)
	}

	dashReq := httptest.NewRequest(http.MethodGet, "http://198.51.100.10:6100/", nil)
	dashReq.AddCookie(cookies[0])
	dashResp := httptest.NewRecorder()
	h.ServeHTTP(dashResp, dashReq)
	body := dashResp.Body.String()
	if dashResp.Code != http.StatusOK { t.Fatalf("dashboard status=%d body=%s", dashResp.Code, body) }
	for _, want := range []string{"مرکز کنترل PQTunnel", "Gateway", "Dialer", "ساخت اتصال بین دو سرور", "اعمال تنظیمات Dialer"} {
		if !strings.Contains(body, want) { t.Errorf("dashboard missing %q", want) }
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if len(csrf) != 2 { t.Fatal("dashboard did not render CSRF values") }

	inviteValues := url.Values{"csrf": {csrf[1]}}
	inviteReq := httptest.NewRequest(http.MethodPost, "http://198.51.100.10:6100/invite", strings.NewReader(inviteValues.Encode()))
	inviteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inviteReq.Header.Set("Origin", "http://198.51.100.10:6100")
	inviteReq.AddCookie(cookies[0])
	inviteResp := httptest.NewRecorder()
	h.ServeHTTP(inviteResp, inviteReq)
	if inviteResp.Code != http.StatusOK { t.Fatalf("invite status=%d body=%s", inviteResp.Code, inviteResp.Body.String()) }
	if !strings.Contains(inviteResp.Body.String(), "scripts/pqtunnel-control-install.sh") ||
		!strings.Contains(inviteResp.Body.String(), coordinator.invite) {
		t.Fatal("invite response did not include the pinned Dialer one-line install command")
	}
}

func TestMobileFleetRejectsCrossOriginActions(t *testing.T) {
	const loginToken = "fleet-panel-login-token-with-at-least-32-bytes"
	coordinator := &fakeCoordinator{snapshot: fleet.DashboardSnapshot{Gateway: adminapi.ManagerSnapshot{Role: "gateway"}}}
	h, err := New(loginToken, coordinator, "http://198.51.100.10:6100/"+strings.Repeat("c", 64), strings.Repeat("d", 40))
	if err != nil { t.Fatal(err) }
	loginValues := url.Values{"token": {loginToken}}
	loginReq := httptest.NewRequest(http.MethodPost, "http://198.51.100.10:6100/login", strings.NewReader(loginValues.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "http://198.51.100.10:6100")
	loginResp := httptest.NewRecorder()
	h.ServeHTTP(loginResp, loginReq)
	cookie := loginResp.Result().Cookies()[0]

	values := url.Values{"role": {"gateway"}, "action": {"stop"}, "confirm": {"yes"}}
	req := httptest.NewRequest(http.MethodPost, "http://198.51.100.10:6100/action", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://attacker.invalid")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden { t.Fatalf("cross-origin action status=%d", resp.Code) }
}
