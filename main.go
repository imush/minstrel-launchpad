// minstrel-launchpad makes a home's UPnP media servers reachable by the
// Minstrel app from anywhere, over one HTTPS port, with paired devices only.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/imush/minstrel-launchpad/internal/auth"
	"github.com/imush/minstrel-launchpad/internal/certs"
	"github.com/imush/minstrel-launchpad/internal/console"
	"github.com/imush/minstrel-launchpad/internal/discovery"
	"github.com/imush/minstrel-launchpad/internal/lan"
	"github.com/imush/minstrel-launchpad/internal/satellite"
	"github.com/imush/minstrel-launchpad/internal/server"
	"github.com/imush/minstrel-launchpad/internal/settings"
	"github.com/imush/minstrel-launchpad/internal/transcode"
)

var version = "dev"

const usage = `usage: minstrel-launchpad [command] [flags]

commands:
  serve            run the launchpad (the default)
  pair             show a QR code to pair the Minstrel app
  console          print a link to set the console password
  devices          list paired devices
  revoke <id>      unpair a device
  status           show addresses, certificate pin and media servers
  version          print the version

Run "minstrel-launchpad <command> -h" for a command's flags. Every flag can
also be set by environment, e.g. LAUNCHPAD_PUBLIC for -public.
`

func main() {
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "pair":
		err = pair(args)
	case "console":
		err = consoleLink(args)
	case "devices":
		err = devices(args)
	case "revoke":
		err = revoke(args)
	case "status":
		err = status(args)
	case "version":
		fmt.Println(version)
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "minstrel-launchpad:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func dataFlag(fs *flag.FlagSet) *string {
	def := env("LAUNCHPAD_DATA", "")
	if def == "" {
		if d, err := os.UserConfigDir(); err == nil {
			def = filepath.Join(d, "minstrel-launchpad")
		} else {
			def = "."
		}
	}
	return fs.String("data", def, "directory for the certificate and paired devices (LAUNCHPAD_DATA)")
}

func split(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func serve(args []string) error {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := dataFlag(fs)
	listen := fs.String("listen", env("LAUNCHPAD_LISTEN", ":7443"), "address to serve HTTPS on (LAUNCHPAD_LISTEN)")
	consoleAddr := fs.String("console", env("LAUNCHPAD_CONSOLE", ":7444"),
		"address for the web console, home network only; \"off\" to disable (LAUNCHPAD_CONSOLE)")
	consoleTLS := fs.Bool("console-tls", env("LAUNCHPAD_CONSOLE_TLS", "") != "",
		"serve the console over HTTPS with the launchpad's certificate; browsers will warn about it (LAUNCHPAD_CONSOLE_TLS)")
	public := fs.String("public", env("LAUNCHPAD_PUBLIC", ""),
		"comma-separated host[:port] where the app reaches this launchpad from outside:\n"+
			"a static IP or dynamic DNS name, with the router's forwarded port;\n"+
			"when set, it can't be changed on the console (LAUNCHPAD_PUBLIC)")
	servers := fs.String("servers", env("LAUNCHPAD_SERVERS", ""),
		"comma-separated description URLs of media servers discovery doesn't find;\n"+
			"when set, they can't be changed on the console (LAUNCHPAD_SERVERS)")
	name := fs.String("name", env("LAUNCHPAD_NAME", host), "name shown in the app (LAUNCHPAD_NAME)")
	satLink := fs.String("satellite", env("LAUNCHPAD_SATELLITE", ""),
		"minstrel-satellite invitation link, for homes the app can't reach directly;\n"+
			"when set, it can't be changed on the console (LAUNCHPAD_SATELLITE)")
	ffmpeg := fs.String("ffmpeg", env("LAUNCHPAD_FFMPEG", "ffmpeg"),
		"ffmpeg to compress lossless audio with, when the app asks; \"off\" to never (LAUNCHPAD_FFMPEG)")
	tcParallel := fs.Int("transcode-jobs", envInt("LAUNCHPAD_TRANSCODE_JOBS", 2),
		"most conversions at once; past that the original is sent (LAUNCHPAD_TRANSCODE_JOBS)")
	tcCache := fs.Int("transcode-cache", envInt("LAUNCHPAD_TRANSCODE_CACHE", 1024),
		"MB of converted tracks to keep for replays and seeking; 0 keeps none (LAUNCHPAD_TRANSCODE_CACHE)")
	verbose := fs.Bool("v", env("LAUNCHPAD_DEBUG", "") != "", "debug logging (LAUNCHPAD_DEBUG)")
	_ = fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := os.MkdirAll(*data, 0o700); err != nil {
		return err
	}
	cert, err := certs.LoadOrCreate(*data, *name)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	store, err := auth.Open(filepath.Join(*data, "devices.json"))
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}

	// Flags and environment win over what's set on the console.
	setFile := settings.Open(filepath.Join(*data, "settings.json"))
	set, err := setFile.Load()
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	// A name given explicitly wins; otherwise the console's, else the host's.
	nameLocked := os.Getenv("LAUNCHPAD_NAME") != ""
	fs.Visit(func(f *flag.Flag) { nameLocked = nameLocked || f.Name == "name" })
	homeName := *name
	if !nameLocked && set.Name != "" {
		homeName = set.Name
	}
	publicList, serverList := split(*public), split(*servers)
	publicLocked, serversLocked := len(publicList) > 0, len(serverList) > 0
	if !publicLocked {
		publicList = set.Public
	}
	if !serversLocked {
		serverList = set.Servers
	}
	satelliteLocked := *satLink != ""
	if !satelliteLocked {
		*satLink = set.Satellite
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := discovery.New(serverList, log)
	go reg.Run(ctx)

	fp := certs.Fingerprint(cert)
	pairing := &server.Pairing{Fingerprint: fp, Port: port, Store: store}
	pairing.SetName(homeName)
	pairing.SetPublic(publicList)
	limiter := auth.NewLimiter()
	var tc *transcode.Transcoder
	if *ffmpeg != "off" {
		tc = transcode.New(*ffmpeg, filepath.Join(*data, "transcoded"), *tcParallel, int64(*tcCache)<<20, log)
		if tc != nil {
			log.Info("compression available", "ffmpeg", tc.Path())
		} else {
			log.Info("no ffmpeg: lossless audio is always sent as is")
		}
	}
	h := &server.Handler{
		Transcoder: tc,
		Version:    version,
		Pairing:    pairing,
		Registry:   reg,
		Store:      store,
		Limiter:    limiter,
		Log:        log,
		Transport:  server.NewTransport(),
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// TLS errors from scanners would otherwise fill the log.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	sat := &satellite.Manager{
		Cert: cert, Name: pairing.Name, Log: log,
		Serve: func(l net.Listener) { _ = srv.ServeTLS(l, "", "") },
		Saved: func(link string) {
			if satelliteLocked {
				return
			}
			set, err := setFile.Load()
			if err == nil {
				set.Satellite = link
				err = setFile.Save(set)
			}
			if err != nil {
				log.Error("saving the satellite link", "err", err)
			}
		},
	}
	pairing.Relays = sat.Hosts
	if err := sat.Set(*satLink); err != nil {
		return fmt.Errorf("satellite: %w", err)
	}
	defer sat.Close()
	access, err := console.OpenAccess(filepath.Join(*data, "console.json"))
	if err != nil {
		return fmt.Errorf("console password: %w", err)
	}
	var consoleURL func(code string) string
	served := make(chan error, 2)
	if *consoleAddr != "off" {
		cln, err := net.Listen("tcp", *consoleAddr)
		if err != nil {
			return fmt.Errorf("-console: %w", err)
		}
		_, cport, _ := net.SplitHostPort(cln.Addr().String())
		consoleURL = func(code string) string {
			host := "localhost"
			if ifs := lan.IPv4(); len(ifs) > 0 {
				host = ifs[0].Addr.String()
			}
			scheme := "http"
			if *consoleTLS {
				scheme = "https"
			}
			u := scheme + "://" + net.JoinHostPort(host, cport) + "/"
			if code != "" {
				u += "#setup=" + code
			}
			return u
		}
		c := &console.Console{
			Version: version, Fingerprint: fp,
			Pairing: pairing, Store: store, Registry: reg, Settings: setFile,
			Access: access, Limiter: limiter, Log: log,
			Satellite:  sat,
			NameLocked: nameLocked, PublicLocked: publicLocked, ServersLocked: serversLocked,
			SatelliteLocked: satelliteLocked, TLS: *consoleTLS,
		}
		csrv := &http.Server{
			Handler:           c.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		if *consoleTLS {
			csrv.TLSConfig = tlsConfig
			go func() { served <- csrv.ServeTLS(cln, "", "") }()
		} else {
			go func() { served <- csrv.Serve(cln) }()
		}
		defer csrv.Close()
	}
	admin := &server.Admin{
		Pairing: pairing, Store: store, Registry: reg,
		Version: version, Fingerprint: fp, CurlPin: certs.CurlPin(cert),
		ConsoleLink: func() (string, bool) {
			if consoleURL == nil {
				return "", false
			}
			return consoleURL(access.SetupCode()), true
		},
	}
	if err := server.ListenAdmin(ctx, adminSocket(*data), admin); err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	go func() { served <- srv.ServeTLS(ln, "", "") }()

	log.Info("launchpad ready", "name", homeName, "version", version, "listen", *listen, "data", *data, "fingerprint", fp)
	if len(pairing.Public()) == 0 && *satLink == "" {
		log.Warn("no outside address: the app can pair and play at home only; forward a port on the router " +
			"and set its static IP or dynamic DNS name on the console, or join a satellite there")
	}
	if consoleURL != nil {
		if access.HasPassword() {
			log.Info("console ready", "url", consoleURL(""))
		} else {
			fmt.Fprintf(os.Stderr, "\nTo set up the launchpad, open this link on the home network (valid for an hour):\n  %s\n\n",
				consoleURL(access.SetupCode()))
		}
	}
	if len(store.Devices()) == 0 {
		if inv, err := pairing.New("", 30*time.Minute); err == nil {
			printInvitation(os.Stderr, inv)
		}
	}

	flush := time.NewTicker(5 * time.Minute)
	defer flush.Stop()
	for {
		select {
		case <-flush.C:
			if err := store.Flush(); err != nil {
				log.Error("saving devices", "err", err)
			}
		case err := <-served:
			return err
		case <-ctx.Done():
			log.Info("shutting down")
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdown)
			return store.Flush()
		}
	}
}

func printInvitation(w io.Writer, inv server.Invitation) {
	fmt.Fprintln(w, "\nTo pair the Minstrel app, scan this code in the app (Add home → Scan code):")
	if q, err := qrcode.New(inv.URI, qrcode.Low); err == nil {
		fmt.Fprint(w, q.ToSmallString(false))
	}
	fmt.Fprintf(w, "Code: %s (single use, valid until %s)\n", inv.Code, inv.Expires.Local().Format("15:04"))
	fmt.Fprintf(w, "Addresses: %s\n", strings.Join(inv.Addresses, ", "))
	if len(inv.Relays) > 0 {
		fmt.Fprintf(w, "Through the satellite: %s\n", strings.Join(inv.Relays, ", "))
	}
	fmt.Fprintf(w, "Or copy this link into the app: %s\n\n", inv.URI)
}

// adminSocket is where the admin socket for data lives: in it, unless that
// path is too long for a Unix socket (about 100 bytes), then in the temp
// directory under a name derived from it.
func adminSocket(data string) string {
	p := filepath.Join(data, "admin.sock")
	if len(p) < 100 {
		return p
	}
	abs, _ := filepath.Abs(data)
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(os.TempDir(), fmt.Sprintf("minstrel-launchpad-%x.sock", sum[:6]))
}

// adminCall makes a request to the running launchpad over its admin socket.
func adminCall(data, method, path string, out any) error {
	sock := adminSocket(data)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
	req, err := http.NewRequest(method, "http://launchpad"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the running launchpad at %s (is it running, with the same -data?): %w", sock, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return errors.New(strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func pair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	var inv server.Invitation
	if err := adminCall(*data, http.MethodPost, "/pair", &inv); err != nil {
		return err
	}
	printInvitation(os.Stdout, inv)
	return nil
}

func consoleLink(args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	var out struct {
		URL string `json:"url"`
	}
	if err := adminCall(*data, http.MethodPost, "/console-link", &out); err != nil {
		return err
	}
	fmt.Printf("Open this link on the home network within an hour to set the console password:\n  %s\n", out.URL)
	return nil
}

func devices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	var list []auth.Device
	if err := adminCall(*data, http.MethodGet, "/devices", &list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("No paired devices. Run \"minstrel-launchpad pair\" to add one.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tPAIRED\tLAST SEEN\tFROM")
	for _, d := range list {
		seen := "never"
		if !d.LastSeen.IsZero() {
			seen = d.LastSeen.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.Created.Local().Format("2006-01-02"), seen, d.LastAddr)
	}
	return tw.Flush()
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: minstrel-launchpad revoke <device id>")
	}
	if err := adminCall(*data, http.MethodPost, "/revoke?id="+fs.Arg(0), nil); err != nil {
		return err
	}
	fmt.Println("Revoked", fs.Arg(0))
	return nil
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	data := dataFlag(fs)
	_ = fs.Parse(args)
	var st struct {
		Name        string             `json:"name"`
		Version     string             `json:"version"`
		Fingerprint string             `json:"fingerprint"`
		CurlPin     string             `json:"curlPin"`
		Addresses   []string           `json:"addresses"`
		Relays      []string           `json:"relays"`
		Servers     []discovery.Server `json:"servers"`
		Devices     int                `json:"devices"`
	}
	if err := adminCall(*data, http.MethodGet, "/status", &st); err != nil {
		return err
	}
	fmt.Printf("%s (launchpad %s)\n", st.Name, st.Version)
	fmt.Printf("Addresses:   %s\n", strings.Join(st.Addresses, ", "))
	if len(st.Relays) > 0 {
		fmt.Printf("Satellite:   %s\n", strings.Join(st.Relays, ", "))
	}
	fmt.Printf("Fingerprint: %s\n", st.Fingerprint)
	fmt.Printf("curl pin:    --pinnedpubkey %s\n", st.CurlPin)
	fmt.Printf("Paired devices: %d\n", st.Devices)
	fmt.Printf("Media servers (%d):\n", len(st.Servers))
	for _, s := range st.Servers {
		fmt.Printf("  %s  %s\n", s.Name, s.Location)
	}
	return nil
}
