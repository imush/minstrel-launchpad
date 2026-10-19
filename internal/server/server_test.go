package server

import (
	"encoding/json"
	"github.com/imush/minstrel-launchpad/internal/transcode"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/discovery"
)

type fakeRegistry struct {
	origin  string
	learned []string
}

func (f *fakeRegistry) Servers() []discovery.Server {
	return []discovery.Server{{UDN: "uuid:1", Name: "Music", Location: "http://" + f.origin + "/desc.xml"}}
}
func (f *fakeRegistry) Allowed(hp string) bool { return hp == f.origin }
func (f *fakeRegistry) Learn(hp, _ string) bool {
	f.learned = append(f.learned, hp)
	return true
}
func (f *fakeRegistry) Refresh() {}

const audio = "fLaC....http://192.168.1.9:9790/not-a-url-in-audio"

// backend is a stand-in media server on 127.0.0.1.
func backend(t *testing.T) (*httptest.Server, *[]http.Header) {
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		self := "http://" + r.Host
		switch r.URL.Path {
		case "/desc.xml":
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			io.WriteString(w, `<root xmlns="urn:schemas-upnp-org:device-1-0"><device>`+
				`<serviceList><service><controlURL>/cd/control</controlURL></service></serviceList>`+
				`<iconList><icon><url>`+self+`/icon.png</url></icon></iconList></device></root>`)
		case "/cd/control":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/xml")
			// Echo the request, plus a result with a URL on another LAN port.
			io.WriteString(w, `<echo>`+strings.ReplaceAll(string(body), "http://", "received:")+`</echo><res>http://192.168.1.9:9790/a.flac</res>`)
		case "/a.flac":
			w.Header().Set("Content-Type", "audio/flac")
			http.ServeContent(w, r, "a.flac", time.Time{}, strings.NewReader(audio))
		case "/b.mp3":
			w.Header().Set("Content-Type", "audio/mpeg")
			http.ServeContent(w, r, "b.mp3", time.Time{}, strings.NewReader("ID3 lossy"))
		case "/redirect":
			http.Redirect(w, r, self+"/a.flac", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func setup(t *testing.T) (*Handler, *fakeRegistry, string, string) {
	be, _ := backend(t)
	origin := strings.TrimPrefix(be.URL, "http://")
	store, err := auth.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistry{origin: origin}
	h := &Handler{
		Version: "test", Registry: reg, Store: store,
		Limiter: auth.NewLimiter(), Log: slog.New(slog.DiscardHandler), Transport: NewTransport(),
	}
	code, _ := store.NewCode(time.Minute)
	rec := do(h, "POST", "/api/pair", "", `{"code":"`+code+`","name":"phone"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("pair: %d %s", rec.Code, rec.Body)
	}
	var resp struct{ Token string }
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return h, reg, origin, resp.Token
}

func do(h http.Handler, method, path, token, body string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://home.example.net:8443"+path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:5000"
	for k, v := range header {
		r.Header[k] = v
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAuth(t *testing.T) {
	h, _, origin, _ := setup(t)
	if rec := do(h, "GET", "/api/info", "", "", nil); rec.Code != 404 || rec.Body.Len() > 20 {
		t.Errorf("no token: %d %q", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/u/"+origin+"/desc.xml", "", "", nil); rec.Code != 404 {
		t.Errorf("relay without token: %d", rec.Code)
	}
	for range 10 {
		if rec := do(h, "GET", "/api/info", "mlp_wrong", "", nil); rec.Code != 401 {
			t.Fatalf("bad token: %d", rec.Code)
		}
	}
	if rec := do(h, "GET", "/api/info", "mlp_wrong", "", nil); rec.Code != 429 {
		t.Errorf("not blocked after 10 failures: %d", rec.Code)
	}
}

func TestPairCodeGuessing(t *testing.T) {
	h, _, _, _ := setup(t)
	for range 10 {
		do(h, "POST", "/api/pair", "", `{"code":"guess","name":"x"}`, nil)
	}
	if rec := do(h, "POST", "/api/pair", "", `{"code":"guess","name":"x"}`, nil); rec.Code != 429 {
		t.Errorf("pairing not rate limited: %d", rec.Code)
	}
}

func TestInfo(t *testing.T) {
	h, _, origin, token := setup(t)
	rec := do(h, "GET", "/api/info", token, "", nil)
	var info struct {
		Device  struct{ Name string }
		Servers []struct{ Name, Description string }
	}
	json.Unmarshal(rec.Body.Bytes(), &info)
	if info.Device.Name != "phone" || len(info.Servers) != 1 ||
		info.Servers[0].Description != "https://home.example.net:8443/u/"+origin+"/desc.xml" {
		t.Errorf("info: %s", rec.Body)
	}
}

func TestRelayDescription(t *testing.T) {
	h, _, origin, token := setup(t)
	rec := do(h, "GET", "/u/"+origin+"/desc.xml", token, "", nil)
	body := rec.Body.String()
	for _, want := range []string{
		"<controlURL>/u/" + origin + "/cd/control</controlURL>",
		"<url>https://home.example.net:8443/u/" + origin + "/icon.png</url>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if rec.Header().Get("Content-Length") != "" && rec.Header().Get("Content-Length") != itoa(len(body)) {
		t.Errorf("stale Content-Length %s for %d bytes", rec.Header().Get("Content-Length"), len(body))
	}
}

func TestRelaySOAP(t *testing.T) {
	h, reg, origin, token := setup(t)
	soap := `<CurrentURI>https://home.example.net:8443/u/192.168.1.9:9790/a.flac</CurrentURI>`
	rec := do(h, "POST", "/u/"+origin+"/cd/control", token, soap,
		http.Header{"Content-Type": {"text/xml"}, "Soapaction": {`"urn:x#Browse"`}})
	body := rec.Body.String()
	if !strings.Contains(body, "<echo><CurrentURI>received:192.168.1.9:9790/a.flac</CurrentURI></echo>") {
		t.Errorf("request URL not turned back to LAN form: %s", body)
	}
	if !strings.Contains(body, "<res>https://home.example.net:8443/u/192.168.1.9:9790/a.flac</res>") {
		t.Errorf("response URL not rewritten: %s", body)
	}
	if len(reg.learned) == 0 || reg.learned[0] != "192.168.1.9:9790" {
		t.Errorf("learned %v", reg.learned)
	}
}

func TestRelayStripsCredentials(t *testing.T) {
	be, seen := backend(t)
	origin := strings.TrimPrefix(be.URL, "http://")
	h, _, _, token := setup(t)
	h.Registry = &fakeRegistry{origin: origin}
	do(h, "GET", "/u/"+origin+"/desc.xml", token, "", http.Header{"Cookie": {"a=b"}})
	if len(*seen) != 1 {
		t.Fatalf("backend saw %d requests", len(*seen))
	}
	for _, k := range []string{"Authorization", "Cookie", "X-Forwarded-For"} {
		if v := (*seen)[0].Get(k); v != "" {
			t.Errorf("%s forwarded to server: %q", k, v)
		}
	}
}

func TestRelayMediaRange(t *testing.T) {
	h, _, origin, token := setup(t)
	rec := do(h, "GET", "/u/"+origin+"/a.flac", token, "", http.Header{"Range": {"bytes=4-"}})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != audio[4:] {
		t.Errorf("range: %d %q", rec.Code, rec.Body)
	}
}

func TestRelayRedirect(t *testing.T) {
	h, _, origin, token := setup(t)
	rec := do(h, "GET", "/u/"+origin+"/redirect", token, "", nil)
	if loc := rec.Header().Get("Location"); loc != "https://home.example.net:8443/u/"+origin+"/a.flac" {
		t.Errorf("Location %q", loc)
	}
}

func TestRelayUnknownServer(t *testing.T) {
	h, _, _, token := setup(t)
	for _, p := range []string{"/u/192.168.1.1:80/", "/u/example.com:80/", "/u/garbage/x"} {
		rec := do(h, "GET", p, token, "", nil)
		if rec.Code != 404 || rec.Header().Get("X-Launchpad-Error") != errUnknownServer {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestRelayServerDown(t *testing.T) {
	h, reg, _, token := setup(t)
	reg.origin = "127.0.0.1:1"
	rec := do(h, "GET", "/u/127.0.0.1:1/desc.xml", token, "", nil)
	if rec.Code != 502 || rec.Header().Get("X-Launchpad-Error") != errUnreachable {
		t.Errorf("down server: %d %v", rec.Code, rec.Header())
	}
}

func TestInvitation(t *testing.T) {
	store, _ := auth.Open(filepath.Join(t.TempDir(), "d.json"))
	p := &Pairing{Fingerprint: "abc", Port: "8443", Store: store}
	p.SetName("My NAS")
	p.SetPublic([]string{"home.example.net", "203.0.113.5:443"})
	inv, err := p.New("", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(inv.URI)
	if err != nil || u.Scheme != "minstrel" {
		t.Fatal(inv.URI)
	}
	q := u.Query()
	a := q["a"]
	if q.Get("n") != "My NAS" || q.Get("fp") != "abc" || q.Get("c") != inv.Code ||
		len(a) < 2 || a[0] != "home.example.net:8443" || a[1] != "203.0.113.5:443" {
		t.Errorf("invitation %s", inv.URI)
	}
	if _, _, err := store.Pair(inv.Code, "x"); err != nil {
		t.Errorf("invitation code unusable: %v", err)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestClientBase(t *testing.T) {
	h, _, origin, token := setup(t)
	rec := do(h, "GET", "/u/"+origin+"/desc.xml", token, "", http.Header{"X-Minstrel-Base": {"http://127.0.0.1:47380/h/abc"}})
	if !strings.Contains(rec.Body.String(), "<controlURL>/h/abc/u/"+origin+"/cd/control</controlURL>") {
		t.Errorf("base not applied: %s", rec.Body)
	}
	// Only loopback bases: a token holder can't make the launchpad write
	// arbitrary hosts into responses.
	rec = do(h, "GET", "/u/"+origin+"/desc.xml", token, "", http.Header{"X-Minstrel-Base": {"https://evil.example"}})
	if strings.Contains(rec.Body.String(), "evil") {
		t.Errorf("foreign base accepted")
	}
}

// fakeFFmpeg stands in for ffmpeg: it upper-cases what it reads.
func fakeFFmpeg(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntr a-z A-Z\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTranscode(t *testing.T) {
	h, _, origin, token := setup(t)
	be := origin
	h.Transcoder = transcode.New(fakeFFmpeg(t), t.TempDir(), 2, 1<<20, h.Log)
	if h.Transcoder == nil {
		t.Fatal("no transcoder")
	}
	ask := http.Header{transcode.Header: {"aac-192"}, "Range": {"bytes=4-"}}

	rec := do(h, "GET", "/u/"+be+"/a.flac", token, "", ask)
	if rec.Code != 200 || rec.Body.String() != strings.ToUpper(audio) {
		t.Fatalf("first: %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") != transcode.ContentType || rec.Header().Get("X-Minstrel-Transcoded") != "aac-192" ||
		rec.Header().Get("Content-Length") != "" || rec.Header().Get("Accept-Ranges") != "" {
		t.Errorf("first headers: %v", rec.Header())
	}

	// Kept: now served from disk, with ranges.
	rec = do(h, "GET", "/u/"+be+"/a.flac", token, "", ask)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != strings.ToUpper(audio)[4:] ||
		rec.Header().Get("Content-Type") != transcode.ContentType {
		t.Errorf("cached: %d %q %v", rec.Code, rec.Body, rec.Header())
	}

	// Another profile is another conversion.
	other := http.Header{transcode.Header: {"aac-128"}}
	if rec := do(h, "GET", "/u/"+be+"/a.flac", token, "", other); rec.Code != 200 || rec.Header().Get("X-Minstrel-Transcoded") != "aac-128" {
		t.Errorf("other profile: %d %v", rec.Code, rec.Header())
	}

	// Lossy files pass through, ranges and all.
	rec = do(h, "GET", "/u/"+be+"/b.mp3", token, "", http.Header{transcode.Header: {"aac-192"}})
	if rec.Code != 200 || rec.Body.String() != "ID3 lossy" || rec.Header().Get("X-Minstrel-Transcoded") != "" {
		t.Errorf("lossy: %d %q %v", rec.Code, rec.Body, rec.Header())
	}

	// Unknown profiles are ignored.
	rec = do(h, "GET", "/u/"+be+"/a.flac", token, "", http.Header{transcode.Header: {"mp3-999"}})
	if rec.Code != 200 || rec.Body.String() != audio {
		t.Errorf("unknown profile: %d %q", rec.Code, rec.Body)
	}

	var info struct{ Transcode []string }
	json.Unmarshal(do(h, "GET", "/api/info", token, "", nil).Body.Bytes(), &info)
	if !slices.Equal(info.Transcode, transcode.Profiles) {
		t.Errorf("info transcode: %v", info.Transcode)
	}
}

func TestNoTranscoderSendsOriginal(t *testing.T) {
	be, seen := backend(t)
	origin := strings.TrimPrefix(be.URL, "http://")
	h, _, _, token := setup(t)
	h.Registry = &fakeRegistry{origin: origin}
	rec := do(h, "GET", "/u/"+origin+"/a.flac", token, "", http.Header{transcode.Header: {"aac-192"}, "Range": {"bytes=4-"}})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != audio[4:] {
		t.Errorf("without ffmpeg: %d %q", rec.Code, rec.Body)
	}
	if last := (*seen)[len(*seen)-1]; last.Get(transcode.Header) != "" {
		t.Error("transcode header passed on to the media server")
	}
	var info struct{ Transcode []string }
	json.Unmarshal(do(h, "GET", "/api/info", token, "", nil).Body.Bytes(), &info)
	if info.Transcode == nil || len(info.Transcode) != 0 {
		t.Errorf("info transcode without ffmpeg: %v", info.Transcode)
	}
}
