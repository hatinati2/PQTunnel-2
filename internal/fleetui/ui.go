package fleetui

import (
	"context"
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
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b1020">
<title>PQTunnel Control Center</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--panel2:#10182a;--line:#2b3954;--text:#edf2ff;--muted:#9eacc7;--accent:#7dd3fc;--good:#86efac;--bad:#fca5a5;--warn:#fcd34d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top right,#1a2d49,#0b1020 58%);color:var(--text);font:15px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{width:min(1120px,calc(100% - 24px));margin:18px auto 50px}header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:1.45rem;margin:0}h2{font-size:1.08rem;margin:0 0 12px}.sub,.muted{color:var(--muted);font-size:.9rem;margin:4px 0}
.card,.section{background:linear-gradient(145deg,#17243b,#111a2c);border:1px solid var(--line);border-radius:16px;padding:16px;margin:12px 0;min-width:0}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.stat{background:#0d1729;border:1px solid #24334e;border-radius:12px;padding:13px}.stat span{display:block;color:var(--muted);font-size:.82rem}.stat b{display:block;font-size:1.05rem;margin-top:3px;overflow-wrap:anywhere}
.status{display:inline-flex;align-items:center;gap:7px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--bad)}.dot.up{background:var(--good);box-shadow:0 0 12px #86efac66}.dot.warn{background:var(--warn)}
.row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
button{border:1px solid #40516f;background:#1b2b45;color:var(--text);border-radius:10px;padding:10px 14px;font:inherit;font-weight:700;cursor:pointer;min-height:42px}
button.primary{background:var(--accent);color:#082033;border-color:transparent}button.danger{background:#3a1d2c;border-color:#783b48;color:#fecaca}
label{display:block;font-size:.9rem;font-weight:650;margin:8px 0}input,textarea,select{display:block;width:100%;margin-top:5px;padding:10px 11px;border:1px solid #3a4a68;border-radius:9px;background:#0b1527;color:var(--text);font:inherit;min-width:0}
textarea{min-height:90px;resize:vertical}input[type=number]{max-width:220px}form{margin:0}.notice{border:1px solid #31536c;background:#102a3b;color:#c8edff;padding:12px;border-radius:11px;margin:10px 0;overflow-wrap:anywhere}.error{border-color:#793e4a;background:#341d2a;color:#fecaca}
pre{direction:ltr;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;background:#081222;border:1px solid #28364e;border-radius:10px;padding:12px;max-height:420px;overflow:auto;font:12px/1.6 ui-monospace,monospace}
.kv{display:grid;grid-template-columns:130px minmax(0,1fr);gap:4px 10px;font-size:.9rem}.kv span:nth-child(odd){color:var(--muted)}.code{font-family:ui-monospace,monospace;direction:ltr;text-align:left;overflow-wrap:anywhere}
small{color:var(--muted)}.pill{display:inline-block;padding:2px 9px;border-radius:999px;border:1px solid #3a4a68;font-size:.78rem}.good{color:var(--good)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.login{width:min(430px,calc(100% - 24px));margin:12vh auto;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px}
@media(max-width:700px){.grid{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}.wrap{width:calc(100% - 18px);margin-top:12px}.card,.section{padding:13px}header{align-items:flex-start}button{flex:1}.kv{grid-template-columns:110px minmax(0,1fr)}}
@media(max-width:420px){.grid{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.kv span:nth-child(odd){margin-top:7px}}
</style></head>
<body>
{{if .CSRF}}
<main class="wrap">
<header><div><h1>مرکز کنترل PQTunnel</h1><p class="sub">مدیریت Gateway و Dialer از یک پنل، قابل استفاده با گوشی</p></div>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>خروج</button></form></header>
{{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
<section class="grid">
<div class="stat"><span>Gateway · سرویس</span><b class="status"><i class="dot {{if eq .Gateway.ServiceStatus "active"}}up{{end}}"></i>{{.Gateway.ServiceStatus}}</b></div>
<div class="stat"><span>Dialer · Agent</span><b class="status"><i class="dot {{if .Dialer.AgentOnline}}up{{else}}warn{{end}}"></i>{{.Dialer.AgentStatus}}</b></div>
<div class="stat"><span>وضعیت تونل دوطرفه</span><b>{{if and .Gateway.TransportConnected .Dialer.Snapshot.TransportConnected}}<span class="good">متصل</span>{{else}}<span class="warn">نیازمند بررسی</span>{{end}}</b></div>
</section>
<section class="section">
<h2>Gateway · سرور مرکزی</h2>
<div class="kv"><span>واحد سرویس</span><b class="code">{{.Gateway.Snapshot.ServiceUnit}}</b><span>وضعیت systemd</span><b>{{.Gateway.ServiceStatus}} / {{.Gateway.SubState}}</b><span>PID</span><b>{{.Gateway.Snapshot.MainPID}}</b><span>همتا</span><b>{{.Gateway.Snapshot.Config.PeerIdentity}}</b><span>Listen</span><b class="code">{{.Gateway.Snapshot.Config.ListenAddress}}</b><span>Peer prefixes</span><b class="code">{{.Gateway.Snapshot.Config.PeerPrefixes}}</b><span>Local prefixes</span><b class="code">{{.Gateway.Snapshot.Config.LocalPrefixes}}</b></div>
<div class="actions">
{{template "actionButtons" dict "Role" "gateway" "CSRF" .CSRF}}
</div>
</section>
<section class="section">
<h2>Dialer · سرور راه‌دور</h2>
<div class="kv"><span>Agent</span><b>{{.Dialer.AgentStatus}}</b><span>آخرین ارتباط</span><b>{{.Dialer.LastSeen}}</b><span>واحد سرویس</span><b class="code">{{.Dialer.Snapshot.ServiceUnit}}</b><span>وضعیت systemd</span><b>{{.Dialer.ServiceStatus}} / {{.Dialer.SubState}}</b><span>PID</span><b>{{.Dialer.Snapshot.MainPID}}</b><span>Gateway</span><b class="code">{{.Dialer.Snapshot.Config.ServerAddress}}</b><span>Gateway name</span><b>{{.Dialer.Snapshot.Config.ServerName}}</b></div>
<div class="actions">{{template "actionButtons" dict "Role" "dialer" "CSRF" .CSRF}}</div>
{{if not .Dialer.AgentOnline}}<p class="muted">برای مدیریت راه‌دور باید Agent روی Dialer نصب و به Gateway متصل باشد. تونل اصلی برای این کانال مدیریتی لازم نیست.</p>{{end}}
</section>
<section class="section">
<h2>ساخت اتصال بین دو سرور</h2>
<p class="muted">این راه‌انداز پروفایل‌های عمومی را بین دو سرور جابه‌جا می‌کند. کلیدهای خصوصی روی همان سرور ساخته و نگهداری می‌شوند. تونل تا زمان شروع دستی سرویس فعال نخواهد شد.</p>
<form method="post" action="/pair">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="confirm" value="yes">
<div class="row">
<label>IP یا نام DNS عمومی Gateway<input name="public_name" placeholder="gateway.example.com یا IP" required maxlength="253"></label>
<label>پورت TCP تونل Gateway<input name="listen_port" type="number" min="1" max="65535" value="8443" required></label>
</div>
<div class="row">
<label>پورت‌های TCP مقصد<input name="tcp_ports" value="443" placeholder="443,80 یا none"></label>
<label>پورت‌های UDP مقصد<input name="udp_ports" value="53,123" placeholder="53,123 یا none"></label>
</div>
<button class="primary" type="submit" {{if not .Dialer.AgentOnline}}disabled{{end}}>ساخت پروفایل و جفت‌سازی دو سرور</button>
</form>
</section>
<section class="section">
<h2>تنظیمات Gateway</h2>
<form method="post" action="/config">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="gateway"><input type="hidden" name="confirm" value="yes">
<label>آدرس Listen<input name="listen_address" value="{{.Gateway.Snapshot.Config.ListenAddress}}" required></label>
<label>Peer prefixes<input name="peer_prefixes" value="{{.Gateway.Snapshot.Config.PeerPrefixes}}" required></label>
<label>Local prefixes<input name="local_prefixes" value="{{.Gateway.Snapshot.Config.LocalPrefixes}}" required></label>
<label>Peer certificate identity<input name="peer_identity" value="{{.Gateway.Snapshot.Config.PeerIdentity}}" required></label>
<label>Allowed destination ports<input name="allowed_dst_ports" value="{{.Gateway.Snapshot.Config.AllowedDstPorts}}"></label>
<button class="primary" type="submit" {{if not .Gateway.ConfigReady}}disabled{{end}}>اعمال تنظیمات Gateway</button>
</form>
</section>
<section class="section">
<h2>تنظیمات Dialer</h2>
<form method="post" action="/config">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="dialer"><input type="hidden" name="confirm" value="yes">
<label>آدرس Gateway با پورت<input name="server_address" value="{{.Dialer.Snapshot.Config.ServerAddress}}" required></label>
<label>نام گواهی Gateway<input name="server_name" value="{{.Dialer.Snapshot.Config.ServerName}}" required></label>
<label>Local prefixes<input name="local_prefixes" value="{{.Dialer.Snapshot.Config.LocalPrefixes}}" required></label>
<label>Remote prefixes<input name="remote_prefixes" value="{{.Dialer.Snapshot.Config.RemotePrefixes}}" required></label>
<label>Allowed destination ports<input name="allowed_dst_ports" value="{{.Dialer.Snapshot.Config.AllowedDstPorts}}"></label>
<button class="primary" type="submit" {{if not .Dialer.AgentOnline}}disabled{{end}}>اعمال تنظیمات Dialer</button>
</form>
</section>
<section class="section">
<h2>ثبت و افزودن Dialer به پنل</h2>
<p class="muted">برای هر Dialer یک دعوت یک‌بارمصرف صادر کن. دعوت بعد از ۱۵ دقیقه منقضی می‌شود و با اولین ثبت موفق مصرف می‌شود.</p>
<form method="post" action="/invite"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="primary" type="submit" {{if not .CanInvite}}disabled{{end}}>ساخت کد اتصال Dialer</button></form>
{{if .Invite}}<div class="notice">کد یک‌بارمصرف — فقط روی سرور Dialer استفاده کن:
<div class="code">{{.Invite.Token}}</div><small>انقضا: {{.Invite.Expires}}</small></div>
<p class="muted">دستور نصب یک‌خطی Dialer:</p><pre>{{.Invite.Command}}</pre>{{end}}
</section>
<section class="section">
<h2>گزارش سرویس</h2>
<form method="post" action="/logs"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row"><label>سرور<select name="role"><option value="gateway">Gateway</option><option value="dialer">Dialer</option></select></label><label>&nbsp;<button type="submit">دریافت ۱۰۰ خط آخر لاگ</button></label></div></form>
{{if .LogsTitle}}<h3>{{.LogsTitle}}</h3><pre>{{.Logs}}</pre>{{end}}
</section>
<footer><small>مدیریت شبکه در این نسخه محدود به تنظیمات تونل و عملیات مشخص است. پیش از اعمال تنظیمات روی VPS عملیاتی، مسیر بازیابی خارج از تونل داشته باش.</small></footer>
</main>
{{else}}
<main class="login"><h1>ورود به مرکز کنترل PQTunnel</h1><p class="muted">توکن مدیریتی را وارد کن.</p>{{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
<form method="post" action="/login"><label>توکن ورود<input type="password" name="token" autocomplete="current-password" required autofocus></label><button class="primary" type="submit">ورود</button></form></main>
{{end}}
</body></html>`).Funcs(template.FuncMap{
	"dict": func(values ...any) map[string]any {
		result := make(map[string]any)
		for i := 0; i+1 < len(values); i += 2 {
			key, ok := values[i].(string)
			if ok { result[key] = values[i+1] }
		}
		return result
	},
}).Parse(`{{define "actionButtons"}}
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="{{.Role}}"><input type="hidden" name="action" value="start"><input type="hidden" name="confirm" value="yes"><button type="submit">روشن</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="{{.Role}}"><input type="hidden" name="action" value="restart"><input type="hidden" name="confirm" value="yes"><button type="submit">اتصال مجدد</button></form>
<form method="post" action="/action"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="role" value="{{.Role}}"><input type="hidden" name="action" value="stop"><input type="hidden" name="confirm" value="yes"><button class="danger" type="submit">خاموش</button></form>
{{end}}`))

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
		if !h.validCSRF(r, current) { http.Error(w, "invalid request", http.StatusForbidden); return }
		h.mu.Lock(); delete(h.sessions, id); h.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case "/invite":
		if r.Method != http.MethodPost { methodNotAllowed(w, "POST"); return }
		_, current, ok := h.requirePost(w, r); if !ok { return }
		if !h.validCSRF(r, current) { http.Error(w, "invalid request", http.StatusForbidden); return }
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
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(sessionTTL.Seconds())})
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

func randomToken() (string, error) { return randomHex(32), nil }

func randomHex(n int) string {
	const hexDigits = "0123456789abcdef"
	value := make([]byte, n)
	if _, err := time.Now().UTC().MarshalBinary(); err != nil { return "" }
	// random bytes come from crypto/rand through a tiny local helper in manager.
	for i := range value { value[i] = byte(time.Now().UnixNano() >> uint(i%8)) }
	out := make([]byte, n*2)
	for i, v := range value { out[2*i] = hexDigits[v>>4]; out[2*i+1] = hexDigits[v&15] }
	return string(out)
}

func methodNotAllowed(w http.ResponseWriter, allow string) { w.Header().Set("Allow", allow); http.Error(w, "method not allowed", http.StatusMethodNotAllowed) }
