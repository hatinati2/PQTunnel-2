package fleetui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel-2/internal/adminapi"
	"github.com/hatinati2/PQTunnel-2/internal/fleet"
)

const (
	sessionCookie = "pqtunnel_fleet_session"
	sessionTTL = 12 * time.Hour
)

type Coordinator interface {
	Snapshot() fleet.DashboardSnapshot
	CreateInvite() (string, time.Time, error)
	Execute(context.Context, string, fleet.Command) (fleet.CommandResult, error)
	PairNodes(context.Context, string, int, string, string) error
}

type session struct {
	CSRF string
	Expires time.Time
}

type NodeView struct {
	Role string
	Label string
	AgentOnline bool
	AgentStatus string
	ServiceStatus string
	SubState string
	TransportConnected bool
	ConfigReady bool
	ConfigError string
	LastSeen string
	Snapshot adminapi.ManagerSnapshot
}

type inviteView struct {
	Token string
	Expires string
	Command string
}

type pageData struct {
	CSRF string
	Error string
	Notice string
	Gateway NodeView
	Dialer NodeView
	Invite *inviteView
	LogsTitle string
	Logs string
	PanelBaseURL string
	InstallRef string
	CanInvite bool
	CanPair bool
}

type Handler struct {
	token []byte
	coordinator Coordinator
	panelBaseURL string
	installRef string
	mu sync.Mutex
	sessions map[string]session
	failures map[string]loginFailure
}

type loginFailure struct {
	Count int
	BlockedUntil time.Time
}

var pageTemplate = template.Must(template.New("fleet").Parse(`<!doctype html>
<html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b1020"><title>PQTunnel Control Center</title>
<style>
:root{color-scheme:dark;--line:#2b3954;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--good:#86efac;--bad:#fca5a5;--warn:#fcd34d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#1a2d49,#0b1020 58%);color:var(--text);font:15px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{width:min(1120px,calc(100% - 18px));margin:14px auto 45px}header{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:14px}
h1{font-size:1.4rem;margin:0}h2{font-size:1.05rem;margin:0 0 11px}.muted,small{color:var(--muted);font-size:.88rem}
.card,.section{background:linear-gradient(145deg,#17243b,#111a2c);border:1px solid var(--line);border-radius:15px;padding:14px;margin:11px 0;min-width:0}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.stat{background:#0d1729;border:1px solid #24334e;border-radius:11px;padding:12px}.stat span{display:block;color:var(--muted);font-size:.82rem}.stat b{font-size:1.05rem;overflow-wrap:anywhere}
.row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.actions{display:flex;gap:7px;flex-wrap:wrap;margin:9px 0}.refresh{border:1px solid #40516f;border-radius:9px;padding:8px 12px;color:var(--text);text-decoration:none;display:inline-flex;align-items:center}
button{border:1px solid #40516f;background:#1b2b45;color:var(--text);border-radius:9px;padding:9px 12px;font:inherit;font-weight:700;cursor:pointer;min-height:41px}button.primary{background:var(--accent);color:#082033;border-color:transparent}button.danger{background:#3a1d2c;border-color:#783b48;color:#fecaca}button:disabled{opacity:.45;cursor:not-allowed}
label{display:block;font-size:.88rem;font-weight:650;margin:7px 0}input,select{display:block;width:100%;margin-top:5px;padding:10px;border:1px solid #3a4a68;border-radius:9px;background:#0b1527;color:var(--text);font:inherit;min-width:0}
input[type=number]{max-width:220px}form{margin:0}.notice{border:1px solid #31536c;background:#102a3b;color:#c8edff;padding:11px;border-radius:10px;margin:9px 0;overflow-wrap:anywhere}.error{border-color:#793e4a;background:#341d2a;color:#fecaca}
pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;background:#081222;border:1px solid #28364e;border-radius:9px;padding:11px;max-height:420px;overflow:auto;font:12px/1.6 ui-monospace,monospace}
.kv{display:grid;grid-template-columns:125px minmax(0,1fr);gap:4px 9px;font-size:.88rem}.kv span:nth-child(odd){color:var(--muted)}.code{font-family:ui-monospace,monospace;direction:ltr;text-align:left;overflow-wrap:anywhere}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--bad);margin-left:6px}.up{background:var(--good);box-shadow:0 0 10px #86efac66}.warn{color:var(--warn)}.good{color:var(--good)}.bad{color:var(--bad)}
.login{width:min(430px,calc(100% - 24px));margin:12vh auto;background:#141c2f;border:1px solid var(--line);border-radius:17px;padding:22px}
@media(max-width:700px){.grid{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}.section,.card{padding:12px}button{flex:1}}
@media(max-width:420px){.grid{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.kv span:nth-child(odd){margin-top:6px}}
</style></head><body>
{{if .CSRF}}
<main class="wrap"><header><div><h1>مرکز کنترل PQTunnel</h1><p class="muted">مدیریت Gateway و Dialer از یک پنل موبایل‌محور</p></div>
<div class="actions"><a class="refresh" href="/">به‌روزرسانی وضعیت</a>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>خروج</button></form></div></header>
{{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
<section class="grid">
<div class="stat"><span>Gateway · سرویس</span><b><i class="dot {{if eq .Gateway.ServiceStatus "active"}}up{{end}}"></i>{{.Gateway.ServiceStatus}}</b></div>
<div class="stat"><span>Dialer · Agent</span><b><i class="dot {{if .Dialer.AgentOnline}}up{{else}}warn{{end}}"></i>{{.Dialer.AgentStatus}}</b></div>
<div class="stat"><span>اتصال تونل</span><b>{{if and .Gateway.TransportConnected .Dialer.Snapshot.TransportConnected}}<span class="good">متصل</span>{{else}}<span class="warn">نامشخص / قطع</span>{{end}}</b></div>
</section>
<section class="section"><h2>Gateway · سرور مرکزی</h2>
<div class="kv"><span>systemd</span><b>{{.Gateway.ServiceStatus}} / {{.Gateway.SubState}}</b><span>PID</span><b>{{.Gateway.Snapshot.MainPID}}</b><span>Listen</span><b class="code">{{.Gateway.Snapshot.Config.ListenAddress}}</b><span>Peer prefixes</span><b class="code">{{.Gateway.Snapshot.Config.PeerPrefixes}}</b><span>Local prefixes</span><b class="code">{{.Gateway.Snapshot.Config.LocalPrefixes}}</b></div>
<div class="actions">
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="gateway"><input type="hidden" name="action" value="start"><input type="hidden" name="confirm" value="yes"><button class="primary">روشن</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="gateway"><input type="hidden" name="action" value="restart"><input type="hidden" name="confirm" value="yes"><button>اتصال مجدد</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="gateway"><input type="hidden" name="action" value="stop"><input type="hidden" name="confirm" value="yes"><button class="danger">خاموش</button></form>
</div></section>
<section class="section"><h2>Dialer · سرور راه‌دور</h2>
<div class="kv"><span>Agent</span><b>{{.Dialer.AgentStatus}}</b><span>آخرین ارتباط</span><b>{{.Dialer.LastSeen}}</b><span>systemd</span><b>{{.Dialer.ServiceStatus}} / {{.Dialer.SubState}}</b><span>PID</span><b>{{.Dialer.Snapshot.MainPID}}</b><span>Gateway</span><b class="code">{{.Dialer.Snapshot.Config.ServerAddress}}</b><span>نام گواهی</span><b>{{.Dialer.Snapshot.Config.ServerName}}</b></div>
<div class="actions">
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="dialer"><input type="hidden" name="action" value="start"><input type="hidden" name="confirm" value="yes"><button class="primary" {{if not .Dialer.AgentOnline}}disabled{{end}}>روشن</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="dialer"><input type="hidden" name="action" value="restart"><input type="hidden" name="confirm" value="yes"><button {{if not .Dialer.AgentOnline}}disabled{{end}}>اتصال مجدد</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="dialer"><input type="hidden" name="action" value="stop"><input type="hidden" name="confirm" value="yes"><button class="danger" {{if not .Dialer.AgentOnline}}disabled{{end}}>خاموش</button></form>
</div>
{{if not .Dialer.AgentOnline}}<p class="muted">Agent راه‌دور آفلاین است. نصب اولیهٔ آن با دستور یک‌خطی دعوت انجام می‌شود. تونل اصلی برای کانال مدیریتی Agent لازم نیست.</p>{{end}}</section>
<section class="section"><h2>ساخت اتصال بین دو سرور</h2><p class="muted">پروفایل‌های عمومی بین دو سرور منتقل می‌شوند؛ کلیدهای خصوصی روی همان سرور ساخته و نگهداری می‌شوند. سرویس تونل پس از جفت‌سازی همچنان خاموش می‌ماند.</p>
<form method="post" action="/pair"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="confirm" value="yes">
<div class="row"><label>IP یا DNS عمومی Gateway<input name="public_name" placeholder="gateway.example.com یا IP" required maxlength="253"></label><label>پورت TCP شنونده<input name="listen_port" type="number" min="1" max="65535" value="8443" required></label></div>
<div class="row"><label>پورت‌های TCP مقصد<input name="tcp_ports" value="443" placeholder="443,80 یا none"></label><label>پورت‌های UDP مقصد<input name="udp_ports" value="53,123" placeholder="53,123 یا none"></label></div>
<button class="primary" type="submit" {{if not .Dialer.AgentOnline}}disabled{{end}}>جفت‌سازی دو سرور</button></form></section>
<section class="section"><h2>تنظیمات Gateway</h2><form method="post" action="/config">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="gateway"><input type="hidden" name="confirm" value="yes">
<label>Listen address<input name="listen_address" value="{{.Gateway.Snapshot.Config.ListenAddress}}" required></label>
<label>Peer prefixes<input name="peer_prefixes" value="{{.Gateway.Snapshot.Config.PeerPrefixes}}" required></label>
<label>Local prefixes<input name="local_prefixes" value="{{.Gateway.Snapshot.Config.LocalPrefixes}}" required></label>
<label>Peer certificate identity<input name="peer_identity" value="{{.Gateway.Snapshot.Config.PeerIdentity}}" required></label>
<label>Allowed destination ports<input name="allowed_dst_ports" value="{{.Gateway.Snapshot.Config.AllowedDstPorts}}"></label>
<button class="primary" type="submit" {{if not .Gateway.ConfigReady}}disabled{{end}}>اعمال تنظیمات Gateway</button>
</form></section>
<section class="section"><h2>تنظیمات Dialer</h2><form method="post" action="/config">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="dialer"><input type="hidden" name="confirm" value="yes">
<label>Gateway address:port<input name="server_address" value="{{.Dialer.Snapshot.Config.ServerAddress}}" required></label>
<label>Gateway certificate name<input name="server_name" value="{{.Dialer.Snapshot.Config.ServerName}}" required></label>
<label>Local prefixes<input name="local_prefixes" value="{{.Dialer.Snapshot.Config.LocalPrefixes}}" required></label>
<label>Remote prefixes<input name="remote_prefixes" value="{{.Dialer.Snapshot.Config.RemotePrefixes}}" required></label>
<label>Allowed destination ports<input name="allowed_dst_ports" value="{{.Dialer.Snapshot.Config.AllowedDstPorts}}"></label>
<button class="primary" type="submit" {{if not .Dialer.AgentOnline}}disabled{{end}}>اعمال تنظیمات Dialer</button>
</form></section>
<section class="section"><h2>افزودن Dialer به مرکز کنترل</h2><p class="muted">دعوت یک‌بارمصرف ۱۵ دقیقه اعتبار دارد و پس از اولین ثبت موفق باطل می‌شود.</p>
<form method="post" action="/invite"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="primary" type="submit" {{if not .CanInvite}}disabled{{end}}>ساخت دستور نصب Dialer</button></form>
{{if .Invite}}<div class="notice">کد یک‌بارمصرف:
<div class="code">{{.Invite.Token}}</div><small>انقضا: {{.Invite.Expires}}</small></div><p class="muted">این دستور را فقط روی سرور Dialer اجرا کن:</p><pre>{{.Invite.Command}}</pre>{{end}}</section>
<section class="section"><h2>گزارش سرویس</h2><form method="post" action="/logs"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><label>سرور<select name="role"><option value="gateway">Gateway</option><option value="dialer">Dialer</option></select></label><label>&nbsp;<button type="submit">دریافت لاگ‌ها</button></label></div></form>{{if .LogsTitle}}<h3>{{.LogsTitle}}</h3><pre>{{.Logs}}</pre>{{end}}</section>
<footer><small>این نسخه آزمایشی است. قبل از تغییر شبکهٔ سرور عملیاتی، دسترسی بازیابی خارج از تونل را حفظ کن.</small></footer>
</main>
{{else}}<main class="login"><h1>ورود به مرکز کنترل PQTunnel</h1><p class="muted">توکن مدیریتی را وارد کن.</p>{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
<form method="post" action="/login"><label>توکن ورود<input type="password" name="token" autocomplete="current-password" required autofocus></label><button class="primary" type="submit">ورود</button></form></main>{{end}}
</body></html>`))

func New(token string, coordinator Coordinator, panelBaseURL, installRef string) (*Handler, error) {
	if len([]byte(token)) < 32 {
		return nil, errors.New("fleet panel token must contain at least 32 bytes")
	}
	if coordinator == nil {
		return nil, errors.New("fleet coordinator is required")
	}
	h := &Handler{
		token: []byte(token), coordinator: coordinator, panelBaseURL: strings.TrimRight(panelBaseURL, "/"),
		installRef: installRef, sessions: make(map[string]session), failures: make(map[string]loginFailure),
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	switch r.URL.Path {
	case "/login":
		if r.Method == http.MethodGet { h.render(w, pageData{Error: ""}); return }
		if r.Method == http.MethodPost { h.login(w, r); return }
		methodNotAllowed(w, "GET, POST")
	case "/":
		if r.Method != http.MethodGet { methodNotAllowed(w, "GET"); return }
		_, current, ok := h.sessionFor(r)
		if !ok { http.Redirect(w, r, "/login", http.StatusSeeOther); return }
		h.renderDashboard(w, r, current.CSRF, "", "", nil, "", "")
	case "/logout":
		if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
		id, current, ok := h.requirePost(w, r)
		if !ok { return }
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) { http.Error(w, "invalid request", http.StatusForbidden); return }
		h.mu.Lock(); delete(h.sessions, id); h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case "/invite":
		if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
		_, current, ok := h.requirePost(w, r); if !ok { return }
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) { http.Error(w, "invalid request", http.StatusForbidden); return }
		token, expires, err := h.coordinator.CreateInvite()
		if err != nil { h.renderDashboard(w, r, current.CSRF, "", err.Error(), nil, "", ""); return }
		command, err := h.dialerInstallCommand(token)
		if err != nil { h.renderDashboard(w, r, current.CSRF, "", err.Error(), nil, "", ""); return }
		invite := &inviteView{Token: token, Expires: expires.Format(time.RFC3339), Command: command}
		h.renderDashboard(w, r, current.CSRF, "دعوت یک‌بارمصرف ساخته شد. آن را فقط روی Dialer اجرا کن.", "", invite, "", "")
	case "/action":
		h.handleAction(w, r)
	case "/config":
		h.handleConfig(w, r)
	case "/logs":
		h.handleLogs(w, r)
	case "/pair":
		h.handlePair(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) dialerInstallCommand(token string) (string, error) {
	if len(h.installRef) != 40 {
		return "", errors.New("این نسخه شناسهٔ commit نصب ثابت ندارد؛ دستور Dialer ساخته نشد")
	}
	for _, c := range h.installRef {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') { return "", errors.New("install commit ref is invalid") }
	}
	u, err := url.Parse(h.panelBaseURL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" {
		return "", errors.New("آدرس عمومی پنل در تنظیمات نصب نشده است؛ PANEL URL را در تنظیمات Gateway ذخیره کن")
	}
	rawURL := u.String()
	script := "https://raw.githubusercontent.com/hatinati2/PQTunnel-2/" + h.installRef + "/scripts/pqtunnel-control-install.sh"
	return fmt.Sprintf("curl -fsSL %q | sudo bash -s -- --ref %s --role dialer --control-url %q --pair-token %s", script, h.installRef, rawURL, token), nil
}

func (h *Handler) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
	_, current, ok := h.requirePost(w, r); if !ok { return }
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, "invalid request", http.StatusBadRequest); return
	}
	role, action := r.PostForm.Get("role"), r.PostForm.Get("action")
	if (action != "start" && action != "stop" && action != "restart") || (role != "gateway" && role != "dialer") {
		http.Error(w, "unsupported operation", http.StatusBadRequest); return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second); defer cancel()
	_, err := h.coordinator.Execute(ctx, role, fleet.Command{Action: action})
	notice := role + " " + action + " completed"
	detail := ""
	if err != nil { notice = ""; detail = err.Error() }
	h.renderDashboard(w, r, current.CSRF, notice, detail, nil, "", "")
}

func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
	_, current, ok := h.requirePost(w, r); if !ok { return }
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, "invalid request", http.StatusBadRequest); return
	}
	role := r.PostForm.Get("role")
	if role != "gateway" && role != "dialer" { http.Error(w, "invalid role", http.StatusBadRequest); return }
	config := adminapi.TunnelConfiguration{
		ListenAddress: r.PostForm.Get("listen_address"),
		MaxClients: 1,
		PeerPrefixes: r.PostForm.Get("peer_prefixes"),
		LocalPrefixes: r.PostForm.Get("local_prefixes"),
		PeerIdentity: r.PostForm.Get("peer_identity"),
		ServerAddress: r.PostForm.Get("server_address"),
		ServerName: r.PostForm.Get("server_name"),
		RemotePrefixes: r.PostForm.Get("remote_prefixes"),
		AllowedDstPorts: r.PostForm.Get("allowed_dst_ports"),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second); defer cancel()
	_, err := h.coordinator.Execute(ctx, role, fleet.Command{Action: "config", Config: config})
	notice := role + " configuration applied"
	detail := ""
	if err != nil { notice = ""; detail = err.Error() }
	h.renderDashboard(w, r, current.CSRF, notice, detail, nil, "", "")
}

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
	_, current, ok := h.requirePost(w, r); if !ok { return }
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) {
		http.Error(w, "invalid request", http.StatusBadRequest); return
	}
	role := r.PostForm.Get("role")
	if role != "gateway" && role != "dialer" { http.Error(w, "invalid role", http.StatusBadRequest); return }
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second); defer cancel()
	result, err := h.coordinator.Execute(ctx, role, fleet.Command{Action: "logs"})
	detail, logs := "", ""
	if err != nil { detail = err.Error() } else { logs = result.Logs }
	h.renderDashboard(w, r, current.CSRF, "", detail, nil, role+" logs", logs)
}

func (h *Handler) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
	_, current, ok := h.requirePost(w, r); if !ok { return }
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil || !h.validCSRF(r, current) || r.PostForm.Get("confirm") != "yes" {
		http.Error(w, "invalid request", http.StatusBadRequest); return
	}
	port, err := strconv.Atoi(r.PostForm.Get("listen_port"))
	if err != nil || port < 1 || port > 65535 { h.renderDashboard(w, r, current.CSRF, "", "پورت شنونده نامعتبر است", nil, "", ""); return }
	publicName := strings.TrimSpace(r.PostForm.Get("public_name"))
	tcpPorts := strings.TrimSpace(r.PostForm.Get("tcp_ports"))
	udpPorts := strings.TrimSpace(r.PostForm.Get("udp_ports"))
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute); defer cancel()
	err = h.coordinator.PairNodes(ctx, publicName, port, tcpPorts, udpPorts)
	notice, detail := "پروفایل‌های Gateway و Dialer با موفقیت جفت شدند. برای برقراری اتصال، سرویس‌ها را از همین پنل روشن کن.", ""
	if err != nil { notice = ""; detail = err.Error() }
	h.renderDashboard(w, r, current.CSRF, notice, detail, nil, "", "")
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) { http.Error(w, "origin rejected", http.StatusForbidden); return }
	key := remoteKey(r.RemoteAddr)
	h.mu.Lock()
	if f := h.failures[key]; time.Now().Before(f.BlockedUntil) { h.mu.Unlock(); http.Error(w, "too many login attempts", http.StatusTooManyRequests); return }
	h.mu.Unlock()
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil { http.Error(w, "invalid request", http.StatusBadRequest); return }
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("token")), h.token) != 1 {
		h.mu.Lock()
		f := h.failures[key]; f.Count++
		if f.Count >= 5 { f.BlockedUntil = time.Now().Add(time.Minute); f.Count = 0 }
		h.failures[key] = f
		h.mu.Unlock()
		h.render(w, pageData{Error: "توکن ورود نادرست است."})
		return
	}
	h.mu.Lock(); delete(h.failures, key); h.mu.Unlock()
	id, err := randomToken(); if err != nil { http.Error(w, "session creation failed", http.StatusInternalServerError); return }
	csrf, err := randomToken(); if err != nil { http.Error(w, "session creation failed", http.StatusInternalServerError); return }
	expires := time.Now().Add(sessionTTL)
	h.mu.Lock()
	for old, s := range h.sessions { if time.Now().After(s.Expires) { delete(h.sessions, old) } }
	h.sessions[id] = session{CSRF: csrf, Expires: expires}
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) renderDashboard(w http.ResponseWriter, r *http.Request, csrf, notice, detail string, invite *inviteView, logsTitle, logs string) {
	snapshot := h.coordinator.Snapshot()
	gateway := nodeView("gateway", "Gateway", true, snapshot.Gateway, time.Time{})
	dialer := nodeView("dialer", "Dialer", snapshot.Dialer.Connected, snapshot.Dialer.Snapshot, snapshot.Dialer.LastSeen)
	data := pageData{
		CSRF: csrf, Notice: notice, Error: detail, Gateway: gateway, Dialer: dialer, Invite: invite,
		LogsTitle: logsTitle, Logs: logs, PanelBaseURL: h.panelBaseURL, InstallRef: h.installRef,
		CanInvite: h.panelBaseURL != "" && len(h.installRef) == 40,
		CanPair: snapshot.Dialer.Connected,
	}
	if err := pageTemplate.Execute(w, data); err != nil { return }
}

func nodeView(role, label string, online bool, snapshot adminapi.ManagerSnapshot, lastSeen time.Time) NodeView {
	agentStatus := "مرکز کنترل"
	if role == "dialer" {
		agentStatus = "آفلاین"
		if online { agentStatus = "آنلاین" }
	}
	serviceStatus := snapshot.ActiveState
	if serviceStatus == "" { serviceStatus = "نامشخص" }
	last := "—"
	if !lastSeen.IsZero() { last = lastSeen.Local().Format("2006-01-02 15:04:05") }
	return NodeView{
		Role: role, Label: label, AgentOnline: online, AgentStatus: agentStatus,
		ServiceStatus: serviceStatus, SubState: snapshot.SubState,
		TransportConnected: snapshot.TransportConnected, ConfigReady: snapshot.ConfigReady,
		ConfigError: snapshot.ConfigError, LastSeen: last, Snapshot: snapshot,
	}
}

func (h *Handler) sessionFor(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil { return "", session{}, false }
	h.mu.Lock(); defer h.mu.Unlock()
	current, ok := h.sessions[cookie.Value]
	if !ok || time.Now().After(current.Expires) { delete(h.sessions, cookie.Value); return "", session{}, false }
	return cookie.Value, current, true
}

func (h *Handler) requirePost(w http.ResponseWriter, r *http.Request) (string, session, bool) {
	if !sameOrigin(r) { http.Error(w, "origin rejected", http.StatusForbidden); return "", session{}, false }
	id, current, ok := h.sessionFor(r)
	if !ok { http.Redirect(w, r, "/login", http.StatusSeeOther); return "", session{}, false }
	return id, current, true
}

func (h *Handler) validCSRF(r *http.Request, current session) bool {
	return subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(current.CSRF)) == 1
}

func (h *Handler) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, data)
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil { return false }
	expectedScheme := "http"
	if r.TLS != nil { expectedScheme = "https" }
	return strings.EqualFold(u.Host, r.Host) && strings.EqualFold(u.Scheme, expectedScheme)
}

func remoteKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil { return "unknown" }
	return host
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil { return "", err }
	return hex.EncodeToString(value), nil
}

func methodNotAllowed(w http.ResponseWriter, allow string) { w.Header().Set("Allow", allow); http.Error(w, "method not allowed", http.StatusMethodNotAllowed) }
