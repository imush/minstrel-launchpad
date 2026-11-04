# minstrel-launchpad

The home companion for [Minstrel](https://github.com/imush/minstrel). It makes the UPnP/DLNA
media servers in your home (MinimServer, and any other) playable from the
Minstrel app anywhere: over cellular, at work, in the car.

It does one narrow job:

- finds the media servers on the LAN (SSDP), or uses ones you list;
- serves HTTPS on one port, with a self-signed certificate the app pins;
- lets in only paired app installs, each with its own revocable token, and
  blocks clients after repeated failed attempts;
- relays requests to those media servers only, never as an open proxy, and
  rewrites the LAN URLs in their responses to point back through itself.

No cloud account, no VPN, no certificate authority. Audio is passed through
as the server sends it, unless the app asks for compression (below).

## Compression

For listening over mobile data, the app can ask for lossless files (FLAC,
WAV, AIFF, DSD, APE, WavPack) as AAC at 128 to 320 kbit/s; it is a setting
in the app, off by default. Players and the app at home always get the
original, and lossy files pass through untouched.

It needs ffmpeg on the launchpad's machine (`-ffmpeg`, default: from
PATH); without it the launchpad sends originals, and the console says so
(installing it: below). Playback
starts while ffmpeg works. Conversions run at low priority and at most
four times playback speed, so a small NAS or router isn't swamped: about a
quarter of one Atom C2750 core per listener. Finished conversions are
kept (`-transcode-cache`, 1024 MB, a week) so replays and seeking are
served from disk.

## Direct mode

The app connects straight to the launchpad. For listening away from home,
forward one TCP port on the router to the launchpad, and give it the
address the outside world sees: a static IP or a dynamic DNS name. Without
that the app can still pair and play at home.

Use 443 as the external port if you can: hotel and office networks that
block other ports usually let HTTPS through.

Over IPv6 there is nothing to forward. The launchpad has its own routable
address, so the router only has to allow inbound TCP to port 7443 -- a
firewall rule, not a redirect. It finds its global IPv6 addresses itself and
offers them to the app with the rest, and the app uses whichever answers
first, so there is nothing to configure and a changed prefix is picked up on
the next connection at home.

That is the one route that works behind carrier-grade NAT, where no IPv4 port
exists to forward. It needs a provider that routes IPv6 and does not filter
inbound, and a mobile network that has IPv6 at the other end.

## Running it

Docker (most NAS boxes). Host networking is needed for discovery, and the
data directory has to be a path you choose -- an unnamed volume is replaced
when the container is recreated, which silently unpairs every device:

    docker run -d --name launchpad --network host --restart unless-stopped \
      -v /srv/launchpad:/data imush/minstrel-launchpad:latest

Or with the `docker-compose.yml` in this repository, `docker compose up -d`.
The image carries ffmpeg, so compression works without anything further.

Or the binary, on Linux, FreeBSD, macOS or Windows:

    minstrel-launchpad serve

On first start it prints a setup link for the console to its log
(`docker logs launchpad`). Open it in a browser at home, set the console
password, and the rest is done there.

### ffmpeg, for compression

Optional: without it everything works and lossless files are sent as they
are, which is what you want at home anyway. To let the app ask for a
smaller copy over mobile data, install ffmpeg where the launchpad runs and
restart it:

    apt install ffmpeg      # Debian, Ubuntu, Raspberry Pi OS
    pkg install ffmpeg      # FreeBSD, jails
    brew install ffmpeg     # macOS

It arrives with a long tail of dependencies; that is normal, and any build
that reads FLAC and writes AAC will do.

The console's **Compression** card says which ffmpeg was found and what
version it is, or why there is none — check there first. If it says there
is none although you installed one, PATH is the usual reason: a service
manager hands down its own, often without `/usr/local/bin`. Either fix
that or name the binary:

    minstrel-launchpad serve -ffmpeg /usr/local/bin/ffmpeg

`LAUNCHPAD_FFMPEG` does the same, and `-ffmpeg off` never converts.

In Docker it has to be in the image, where you can't install it yourself --
which is why the published image carries it.

## The console

A web page on port 7444, for the home network only:

- **Outside access**: the static IP or dynamic DNS name (and router port)
  the app uses away from home. Paired devices pick up a change the next
  time they connect.
- **Satellite**: instead of a forwarded port, or as well, paste an invitation
  link from a [minstrel-satellite](https://github.com/imush/minstrel-satellite).
  The launchpad connects out to it, and the app goes through it only when
  it can't reach home directly. TLS stays end to end; the satellite only
  passes the bytes on.
- **Pair a device**: an invitation as a QR code to scan now (valid ten
  minutes), or a pairing file to send (valid a day or a week), opened in
  the app with Add home → Open pairing file. Label it with who it's for.
  Unused invitations are listed and can be cancelled. Tick *Can invite
  others* for your own phone (see below).
- **Paired devices**: name, access, who invited it, when paired, last
  access and from which address; revoke any of them.
- **Media servers**: what discovery found, and servers to add by hand.

### Inviting people while away

Devices either **listen**, or also **share**: a sharing device can invite
people from the app (the home's menu → Invite someone), wherever it is,
with a QR code or a pairing file sent through any messaging app. Its
invitations make listening devices only, so access can't spread further.
In the app it sees every paired device, and can revoke the ones it
invited; the rest is for the console. Only the console, at home, makes a
device a sharer: tick *Can invite others* on its invitation, or *Allow
inviting* on a device already paired. The first device paired with a new
launchpad shares.

An invitation carries a one-time code, not a token: the app exchanges the
code for its own token when it pairs, so a used QR code or file is
worthless, and each device can be revoked alone.

The console password protects the console only; the app never needs it.
It is plain HTTP so browsers don't warn about the launchpad's self-signed
certificate; add `-console-tls` to serve it over HTTPS instead. It answers
only home-network addresses (and refuses requests by public host names, so a
web page can't reach it through DNS rebinding), and never on the port the
router forwards. Forgot the password:

    minstrel-launchpad console         # prints a new setup link

The same things from the command line:

    minstrel-launchpad pair            # docker exec launchpad /minstrel-launchpad pair
    minstrel-launchpad pair -share     # the paired device may invite others
    minstrel-launchpad devices         # list paired devices
    minstrel-launchpad revoke <id>     # unpair one
    minstrel-launchpad share <id>      # let a paired device invite others; unshare to stop
    minstrel-launchpad status          # addresses, certificate pin, servers

### Flags

| Flag       | Environment         | Default                     |                                                     |
|------------|---------------------|-----------------------------|-----------------------------------------------------|
| `-listen`  | `LAUNCHPAD_LISTEN`  | `:7443`                     | where to serve HTTPS                                |
| `-console` | `LAUNCHPAD_CONSOLE` | `:7444`                     | where to serve the console; `off` to disable        |
| `-console-tls` | `LAUNCHPAD_CONSOLE_TLS` |                     | serve the console over HTTPS                        |
| `-public`  | `LAUNCHPAD_PUBLIC`  |                             | host[:port] for outside access, comma-separated; overrides the console |
| `-servers` | `LAUNCHPAD_SERVERS` |                             | description URLs of servers discovery misses; overrides the console |
| `-name`    | `LAUNCHPAD_NAME`    | host name                   | shown in the app                                    |
| `-data`    | `LAUNCHPAD_DATA`    | user config dir             | certificate, key, devices, settings, console password |
| `-v`       | `LAUNCHPAD_DEBUG`   |                             | debug logging                                       |

Back up the data directory: losing the key means pairing every device again.

## The API

All over HTTPS; everything except pairing needs `Authorization: Bearer <token>`.
Requests without a token get a bare 404.

| Request                   | Does                                                         |
|---------------------------|--------------------------------------------------------------|
| `POST /api/pair`          | `{"code", "name"}` → `{"token", "device": {"id", "name"}, "name"}` |
| `GET /api/info`           | launchpad name and version, its current addresses, and the media servers with their description URLs |
| `POST /api/refresh`       | scan the LAN now                                             |
| `* /u/<ip>:<port>/<path>` | relay to a media server                                      |

The pairing QR code holds
`minstrel://pair?v=1&n=<name>&fp=<key hash>&c=<code>&a=<host:port>&a=...`,
where `fp` is the base64url SHA-256 of the certificate's public key and the
`a` values are the public addresses, then the LAN ones.

Relayed responses have every `http://<LAN IP>[:port]` in text bodies (XML,
JSON, playlists) and headers rewritten to `https://<the host the app
used>/u/<ip>:<port>`, and launchpad URLs in request bodies turned back into
LAN form. A client can instead ask for URLs relative to a loopback base
with `X-Minstrel-Base: http://127.0.0.1:<port>/<path>`; the app's local
proxy does, so it can pass responses through unchanged. Audio and images
pass through untouched, with range requests.
When the server behind the launchpad fails, the response carries
`X-Launchpad-Error: server-unreachable` (or `unknown-server`), so the app
can tell that apart from the launchpad itself being unreachable.

## Building

    make test
    make build
    make dist      # all platforms, into dist/
    make docker

## License

BSD 3-Clause; see [LICENSE](LICENSE).
