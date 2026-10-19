package rewrite

import (
	"strings"
	"testing"
)

func keepAll(string) bool { return true }

func TestToClient(t *testing.T) {
	const base = "https://home.example.net:8443"
	cases := []struct{ in, want string }{
		{"http://192.168.1.9:9790/minimserver/a.flac", base + "/u/192.168.1.9:9790/minimserver/a.flac"},
		{"<res>http://10.0.0.2/x.mp3</res>", "<res>" + base + "/u/10.0.0.2:80/x.mp3</res>"},
		// Escaped DIDL inside SOAP: the URL itself is unchanged by escaping.
		{"&lt;res&gt;http://192.168.1.9:9790/a?x=1&amp;y=2&lt;/res&gt;", "&lt;res&gt;" + base + "/u/192.168.1.9:9790/a?x=1&amp;y=2&lt;/res&gt;"},
		{"http://8.8.8.8/x", "http://8.8.8.8/x"},             // public: untouched
		{"http://192.168.1.999/x", "http://192.168.1.999/x"}, // not an address
		{"https://192.168.1.9/x", "https://192.168.1.9/x"},   // only http is relayed
		{"a http://192.168.1.9:1 b http://192.168.1.10:2 c", "a " + base + "/u/192.168.1.9:1 b " + base + "/u/192.168.1.10:2 c"},
	}
	for _, c := range cases {
		if got := string(ToClient([]byte(c.in), base, keepAll)); got != c.want {
			t.Errorf("ToClient(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestToClientKeep(t *testing.T) {
	in := "http://192.168.1.9:9790/a http://192.168.1.20:5000/admin"
	got := string(ToClient([]byte(in), "https://h", func(hp string) bool { return hp == "192.168.1.9:9790" }))
	if want := "https://h/u/192.168.1.9:9790/a http://192.168.1.20:5000/admin"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestToLANRoundTrip(t *testing.T) {
	lan := `<CurrentURI>http://192.168.1.9:9790/minimserver/a.flac</CurrentURI>`
	out := ToClient([]byte(lan), "https://home.example.net:443", keepAll)
	if got := string(ToLAN(out)); got != lan {
		t.Errorf("round trip: got %q", got)
	}
	// From a different public address than the one it was rewritten for.
	if got := string(ToLAN([]byte("https://203.0.113.5:8443/u/192.168.1.9:9790/a.flac"))); got != "http://192.168.1.9:9790/a.flac" {
		t.Errorf("got %q", got)
	}
}

func TestBodyDeviceDescription(t *testing.T) {
	desc := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
<iconList><icon><url>/icon.png</url></icon></iconList>
<serviceList><service>
<SCPDURL>/cd.xml</SCPDURL><controlURL>/cd/control</controlURL><eventSubURL>relative/event</eventSubURL>
</service></serviceList>
<presentationURL>http://192.168.1.9:9791/</presentationURL>
</device></root>`
	got := string(Body([]byte(desc), "https://h", "192.168.1.9:9791", keepAll))
	for _, want := range []string{
		"<url>/u/192.168.1.9:9791/icon.png</url>",
		"<SCPDURL>/u/192.168.1.9:9791/cd.xml</SCPDURL>",
		"<controlURL>/u/192.168.1.9:9791/cd/control</controlURL>",
		"<eventSubURL>relative/event</eventSubURL>",
		"<presentationURL>https://h/u/192.168.1.9:9791/</presentationURL>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestBodyURLBase(t *testing.T) {
	desc := `<root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>http://192.168.1.5:50001/</URLBase>
<device><serviceList><service><controlURL>/ctl</controlURL></service></serviceList></device></root>`
	got := string(Body([]byte(desc), "https://h", "192.168.1.5:50000", keepAll))
	for _, want := range []string{"<URLBase>https://h/u/192.168.1.5:50001/</URLBase>", "<controlURL>/u/192.168.1.5:50001/ctl</controlURL>"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

func TestRewritable(t *testing.T) {
	for ct, want := range map[string]bool{
		`text/xml; charset="utf-8"`: true,
		"application/xml":           true,
		"application/json":          true,
		"audio/x-mpegurl":           true,
		"audio/flac":                false,
		"image/jpeg":                false,
		"":                          false,
	} {
		if Rewritable(ct) != want {
			t.Errorf("Rewritable(%q) = %v", ct, !want)
		}
	}
}

func TestLoopbackBase(t *testing.T) {
	const base = "http://127.0.0.1:47380/h/abc123"
	desc := `<root xmlns="urn:schemas-upnp-org:device-1-0"><device><controlURL>/ctl</controlURL>` +
		`<url>http://192.168.1.9:9791/i.png</url></device></root>`
	got := string(Body([]byte(desc), base, "192.168.1.9:9791", keepAll))
	for _, want := range []string{"<controlURL>/h/abc123/u/192.168.1.9:9791/ctl</controlURL>", "<url>" + base + "/u/192.168.1.9:9791/i.png</url>"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if got := string(ToLAN([]byte(base + "/u/192.168.1.9:9790/a.flac"))); got != "http://192.168.1.9:9790/a.flac" {
		t.Errorf("ToLAN: %q", got)
	}
}
