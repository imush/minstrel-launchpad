package console

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/discovery"
	"github.com/imush/minstrel-launchpad/internal/server"
	"github.com/imush/minstrel-launchpad/internal/settings"
)

type fakeRegistry struct{ manual []string }

func (f *fakeRegistry) Servers() []discovery.Server {
	return []discovery.Server{{UDN: "uuid:1", Name: "MinimServer", Location: "http://192.168.1.9:9791/desc.xml"}}
}
func (f *fakeRegistry) Refresh()             {}
func (f *fakeRegistry) SetManual(m []string) { f.manual = m }

type env struct {
	h       http.Handler
	c       *Console
	store   *auth.Store
	reg     *fakeRegistry
	cookie  string
	pairing *server.Pairing
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	store, _ := auth.Open(filepath.Join(dir, "devices.json"))
	access, _ := OpenAccess(filepath.Join(dir, "console.json"))
	pairing := &server.Pairing{Fingerprint: "fp", Port: "7443", Store: store}
	pairing.SetName("NAS")
	reg := &fakeRegistry{}
	c := &Console{
		Version: "test", Fingerprint: "fp",
		Pairing: pairing, Store: store, Registry: reg,
		Settings: settings.Open(filepath.Join(dir, "settings.json")),
		Access:   access, Limiter: auth.NewLimiter(), Log: slog.New(slog.DiscardHandler),
	}
	return &env{h: c.Handler(), c: c, store: store, reg: reg, pairing: pairing}
}

func (e *env) do(method, path, body string, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://192.168.1.12:7444"+path, strings.NewReader(body))
	r.RemoteAddr = "192.168.1.30:50000"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if e.cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: e.cookie})
	}
	for _, m := range mod {
		m(r)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			e.cookie = c.Value
		}
	}
	return rec
}

func (e *env) login(t *testing.T) {
	code := e.c.Access.SetupCode()
	if rec := e.do("POST", "/api/setup", `{"code":"`+code+`","password":"correct horse"}`); rec.Code != 204 {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
}

func TestPasswordSetupAndLogin(t *testing.T) {
	e := setup(t)
	if body := e.do("GET", "/api/session", "").Body.String(); !strings.Contains(body, `"setup"`) {
		t.Errorf("before setup: %s", body)
	}
	if rec := e.do("GET", "/api/state", ""); rec.Code != 401 {
		t.Errorf("state without login: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/setup", `{"code":"guess","password":"correct horse"}`); rec.Code != 403 {
		t.Errorf("setup with a bad code: %d", rec.Code)
	}
	code := e.c.Access.SetupCode()
	if rec := e.do("POST", "/api/setup", `{"code":"`+code+`","password":"short"}`); rec.Code != 403 {
		t.Errorf("short password accepted: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/setup", `{"code":"`+code+`","password":"correct horse"}`); rec.Code != 204 || e.cookie == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/api/state", ""); rec.Code != 200 {
		t.Errorf("state after setup: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/setup", `{"code":"`+code+`","password":"another one"}`); rec.Code != 403 {
		t.Errorf("setup code reused: %d", rec.Code)
	}

	e.do("POST", "/api/logout", "{}")
	e.cookie = ""
	if body := e.do("GET", "/api/session", "").Body.String(); !strings.Contains(body, `"login"`) {
		t.Errorf("after logout: %s", body)
	}
	if rec := e.do("POST", "/api/login", `{"password":"wrong password"}`); rec.Code != 403 {
		t.Errorf("wrong password: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/login", `{"password":"correct horse"}`); rec.Code != 204 {
		t.Errorf("login: %d", rec.Code)
	}

	// The password survives a restart.
	a2, _ := OpenAccess(e.c.Access.path)
	if _, err := a2.Login("correct horse"); err != nil {
		t.Errorf("reloaded: %v", err)
	}
}

func TestHomeNetworkOnly(t *testing.T) {
	e := setup(t)
	rec := e.do("GET", "/", "", func(r *http.Request) { r.RemoteAddr = "203.0.113.7:4000" })
	if rec.Code != 403 {
		t.Errorf("outside client: %d", rec.Code)
	}
	if rec := e.do("GET", "/", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>") {
		t.Errorf("page: %d", rec.Code)
	}
}

func TestCrossOriginRefused(t *testing.T) {
	e := setup(t)
	e.login(t)
	rec := e.do("POST", "/api/invitations", `{}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != 403 {
		t.Errorf("cross-origin: %d", rec.Code)
	}
	if rec := e.do("POST", "/api/invitations", `{}`, func(r *http.Request) { r.Header.Set("Origin", "http://192.168.1.12:7444") }); rec.Code != 200 {
		t.Errorf("same origin: %d %s", rec.Code, rec.Body)
	}
	// DNS rebinding: a public name pointed at the launchpad.
	rec = e.do("GET", "/api/session", "", func(r *http.Request) { r.Host = "evil.example:7444" })
	if rec.Code != 403 {
		t.Errorf("rebound host: %d", rec.Code)
	}
	for _, h := range []string{"nas:7444", "nas.local:7444", "localhost:7444", "[fd00::1]:7444"} {
		if rec := e.do("GET", "/api/session", "", func(r *http.Request) { r.Host = h }); rec.Code != 200 {
			t.Errorf("host %s: %d", h, rec.Code)
		}
	}
	rec = e.do("POST", "/api/invitations", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
	if rec.Code != 415 {
		t.Errorf("form post: %d", rec.Code)
	}
}

func TestInvitationsAndDevices(t *testing.T) {
	e := setup(t)
	e.login(t)
	rec := e.do("POST", "/api/invitations", `{"label":"Anna's iPad","valid":"7d"}`)
	var inv struct{ ID, URI, Code, QR, File string }
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil || rec.Code != 200 {
		t.Fatalf("invite: %d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(inv.QR, "data:image/png;base64,") || !strings.Contains(inv.URI, "c="+inv.Code) || inv.File != "NAS-Annas-iPad.minstrel" {
		t.Errorf("invitation %+v", inv)
	}

	var st struct {
		Invitations []struct{ ID, Label string }
		Devices     []auth.Device
	}
	json.Unmarshal(e.do("GET", "/api/state", "").Body.Bytes(), &st)
	if len(st.Invitations) != 1 || st.Invitations[0].Label != "Anna's iPad" {
		t.Errorf("listed: %+v", st.Invitations)
	}

	token, dev, err := e.store.Pair(inv.Code, "iPad")
	if err != nil {
		t.Fatal(err)
	}
	e.store.Authenticate(token, "203.0.113.50")
	body := e.do("GET", "/api/state", "").Body.String()
	json.Unmarshal([]byte(body), &st)
	if len(st.Invitations) != 0 || len(st.Devices) != 1 || st.Devices[0].LastAddr != "203.0.113.50" || st.Devices[0].Label != "Anna's iPad" {
		t.Errorf("after pairing: %s", body)
	}
	if strings.Contains(body, "tokenHash") {
		t.Errorf("token hash sent to the page")
	}
	if rec := e.do("DELETE", "/api/devices/"+dev.ID, "{}"); rec.Code != 204 {
		t.Errorf("revoke: %d", rec.Code)
	}
	if _, ok := e.store.Authenticate(token, ""); ok {
		t.Errorf("revoked device still accepted")
	}

	rec = e.do("POST", "/api/invitations", `{"valid":"10m"}`)
	json.Unmarshal(rec.Body.Bytes(), &inv)
	if rec := e.do("DELETE", "/api/invitations/"+inv.ID, "{}"); rec.Code != 204 {
		t.Errorf("cancel: %d", rec.Code)
	}
	if _, _, err := e.store.Pair(inv.Code, "x"); err == nil {
		t.Errorf("cancelled invitation used")
	}
}

func TestSettings(t *testing.T) {
	e := setup(t)
	e.login(t)
	rec := e.do("PUT", "/api/settings", `{"public":["myhome.example.net:443","https://203.0.113.5:8443/", "home2.example.net"]}`)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	want := []string{"myhome.example.net:443", "203.0.113.5:8443", "home2.example.net:7443"}
	if got := e.pairing.Public(); !slices.Equal(got, want) {
		t.Errorf("public %v", got)
	}
	inv, _ := e.pairing.New("", 60e9)
	if !strings.Contains(inv.URI, "a=myhome.example.net%3A443") {
		t.Errorf("new address not in invitations: %s", inv.URI)
	}
	if set, _ := e.c.Settings.Load(); !slices.Equal(set.Public, want) {
		t.Errorf("saved %v", set.Public)
	}

	for _, bad := range []string{`{"public":["bad host!:443"]}`, `{"public":["x.net:99999"]}`, `{"servers":["http://8.8.8.8/desc.xml"]}`} {
		if rec := e.do("PUT", "/api/settings", bad); rec.Code != 400 {
			t.Errorf("%s accepted: %d", bad, rec.Code)
		}
	}
	if rec := e.do("PUT", "/api/settings", `{"servers":["http://192.168.1.9:9791/desc.xml"]}`); rec.Code != 200 ||
		!slices.Equal(e.reg.manual, []string{"http://192.168.1.9:9791/desc.xml"}) {
		t.Errorf("servers: %d %v", rec.Code, e.reg.manual)
	}

	if rec := e.do("PUT", "/api/settings", `{"name":"  Lake   house "}`); rec.Code != 200 || e.pairing.Name() != "Lake house" {
		t.Errorf("name: %d %q", rec.Code, e.pairing.Name())
	}
	if inv, _ := e.pairing.New("", 60e9); !strings.Contains(inv.URI, "n=Lake+house") {
		t.Errorf("new name not in invitations: %s", inv.URI)
	}
	for _, bad := range []string{`{"name":"   "}`, `{"name":"` + strings.Repeat("x", 41) + `"}`, `{"name":"a\u0007b"}`} {
		if rec := e.do("PUT", "/api/settings", bad); rec.Code != 400 {
			t.Errorf("%s accepted: %d", bad, rec.Code)
		}
	}

	e.c.NameLocked = true
	if rec := e.do("PUT", "/api/settings", `{"name":"Other"}`); rec.Code != 409 {
		t.Errorf("locked name changed: %d", rec.Code)
	}
	e.c.PublicLocked = true
	if rec := e.do("PUT", "/api/settings", `{"public":[]}`); rec.Code != 409 {
		t.Errorf("locked setting changed: %d", rec.Code)
	}
}
