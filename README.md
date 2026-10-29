# RustDoS

A multi-layer (L1-L7) DDoS stress tester with a terminal UI, written in Rust,
plus a native SwiftUI iOS app (see [iOS app](#ios-app)).

You give it one thing — an IP, a domain, or a URL — and an optional port. It
resolves the target, scans every port when you do not name one, fingerprints
what is actually listening, picks the matching attack vectors, and lets you
fire. An optional time limit stops the run for you.

```
┌──────────────────────────────────────────────────────────────────┐
│ RustDoS  L1-L7 stress tester                              [ARMED] │
└──────────────────────────────────────────────────────────────────┘
```

## Inputs

| Field | Meaning |
|-------|---------|
| target | IP, domain or URL. Required. |
| port | Optional. Leave empty to scan all 65535 ports and pick the best service. |
| minutes | Optional. `2` = two minutes, `0` or empty = unlimited. |

## Flow

1. Enter a target and press `Enter`.
2. Subdomains are loaded from crt.sh **first, always**. If crt.sh fails, the
   run carries on with your own domain.
3. If subdomains were found you are asked whether to attack them too. `y`
   opens a list to pick from; `n` continues with your domain alone.
4. A layer screen lists every domain with `L1`-`L7`. Layers are pre-filled
   automatically from the detected service. Move with `Up`/`Down` and
   `Left`/`Right`, toggle with `Space`, or use `a` (auto for all), `s` (all
   layers), `n` (none).
5. `Enter` reviews, `Enter` again starts.

## Health probe

While an attack runs, a background prober connects to the target port every
500 ms and reports latency, success ratio and a state (`up`, `degraded`,
`down`). This is the signal that the target is actually suffering rather than
just that packets are leaving.

## Bypass

- **Subdomain discovery** — names come from certificate transparency (crt.sh),
  loaded before any port work. Only names that still resolve are offered, and
  you are asked whether to attack them at all. Selected subdomains are attacked
  alongside the primary target.
- **CDN detection** by Cloudflare's published ranges and by response headers
  (Cloudflare, Fastly, CloudFront, Akamai, Varnish).
- **Origin discovery** — resolves ~34 likely subdomains, drops any that still
  point at the CDN, and confirms candidates by requesting the site with the
  real `Host` header. Press `o` to retarget at a found origin.
- **Challenge detection** — Cloudflare JS challenges and Anubis proof-of-work
  are identified. Anubis is actually solved (SHA-256 PoW) and the resulting
  cookie is reused by the HTTP vectors.
- **Edge evasion** — HTTP vectors send a random query string to defeat caching,
  rotate a browser `User-Agent`, send `Cache-Control: no-cache`, and back off
  when the target answers 429/403/503.

### JavaScript challenges

A JS engine (Boa) runs the challenge page's scripts against a shimmed DOM, so
inline scripts and the scripts they load dynamically both execute, and any
cookie they set is captured and reused.

Honest limits: this is not a browser. Cloudflare's managed challenge runs a
heavily obfuscated orchestrate script that expects a real DOM, canvas and
WebGL, and it does not currently complete — so no `cf_clearance` is produced
against live Cloudflare. The mechanism is proven against a controlled
challenge page (inline script, dynamic load, cookie capture). Turnstile needs
a real browser and is only detected.

## Vectors

| Layer | Vector        | What it does                              |
|-------|---------------|-------------------------------------------|
| L1    | `eth-flood`   | raw ethernet frame flood                  |
| L2    | `arp-flood`   | ARP request storm to the gateway          |
| L3    | `icmp-flood`  | ICMP echo request flood                   |
| L3    | `ip-frag`     | tiny IP fragment flood                    |
| L3    | `udp-raw`     | spoofed-source UDP datagrams              |
| L4    | `syn-flood`   | TCP SYN flood, random source ports        |
| L4    | `ack-flood`   | TCP ACK flood                             |
| L4    | `rst-flood`   | TCP RST flood                             |
| L4    | `tcp-connect` | full TCP handshake flood                  |
| L4    | `udp-flood`   | kernel UDP `sendto` flood                 |
| L7    | `http-get`    | HTTP GET request flood                    |
| L7    | `http-post`   | HTTP POST body flood                      |
| L7    | `slowloris`   | slow header exhaustion                    |
| L7    | `tls-flood`   | TLS ClientHello handshake flood           |
| L7    | `dns-flood`   | random-subdomain DNS query flood          |

## Build

```sh
cargo build --release
```

The binary lands at `target/release/rustdos`.

## Run

Raw sockets need root:

```sh
sudo ./target/release/rustdos
```

Without root the tool still runs, but the L1-L4 raw vectors are disabled and
greyed out in the list.

### Keys

| Context | Keys |
|---------|------|
| Input   | type target, `Tab`/`Shift-Tab` cycle fields, `Enter` scan, `Esc` clear, `Ctrl-C` quit |
| Subdomains? | `y` pick subdomains, `n` primary domain only |
| Subdomains | `Up`/`Down` move, `Space` select, `a` all, `Enter` confirm, `Esc` skip |
| Layers  | `Up`/`Down` domain, `Left`/`Right` layer, `Space` toggle, `a` auto, `s` all, `n` none, `Enter` review, `Esc` edit |
| Review  | `Enter` start, `o` retarget at origin, `Esc` back to layers |
| Running | `Enter` or `x` stop, `q` quit |
| Stopped | `Enter` restart, `Esc` edit, `q` quit |

## Layout

The UI adapts to the terminal. Large terminals get two columns and a log
panel; medium ones stack and drop the log; tiny ones keep only the three input
fields, the vector list and the rate line. Descriptions and the gauge drop away
as space shrinks.

## How the target is handled

1. Input is normalised — `https://example.com/path` becomes `example.com`,
   the scheme sets TLS, and a `:port` suffix is split off.
2. Domains are resolved to IPv4.
3. With no port, a quick pass over common ports runs first, then the full
   1-65535 range is swept with 1200 concurrent probes. Open ports stream into
   the UI as they are found. With a port, only that port is probed and its
   banner classified.
4. The most interesting open port decides the service, and a focused vector set
   is selected for it. `a` arms everything instead.

## Headless mode

Useful for scripting and for checking a target without the TUI:

```sh
./rustdos --list
./rustdos --test example.com 443 10
./rustdos --test 1.1.1.1 80 5 syn-flood http-get
./rustdos --test 127.0.0.1 "" 5          # empty port = full port scan
```

`--test <target> [port] [seconds] [vectors...]` prints open ports, per-second
counters and a per-vector breakdown. If vectors are omitted the auto-plan is
used. The headless mode takes seconds, not minutes.

## Rate control

Raw vectors are capped by a per-vector token bucket. This is deliberate: an
uncapped raw flood saturates the interface and starves the L7 vectors, and
SYN-ACK replies also force the kernel to emit a RST for every packet, which
makes SYN floods disproportionately expensive. Defaults:

| Vector | pps cap |
|--------|---------|
| `syn-flood` | 2 000 |
| `ack-flood`, `rst-flood` | 6 000 |
| `icmp-flood`, `eth-flood`, `arp-flood`, `ip-frag` | 8 000 |
| `udp-raw` | 15 000 |

Raise them in `raw_rate()` in `src/attack.rs` if your link and upstream can
take more.

## iOS app

`ios/` is a SwiftUI port of the same tool, built with
[xtool](https://github.com/xtool-org/xtool). It is a native app, not a terminal
emulator: target entry, a live port grid, per-layer vector toggles, live
packet/throughput counters and a health pill.

```sh
cd ios
xtool dev build -c release --ipa   # -> ios/xtool/RustDoS.ipa
```

`.github/workflows/ios.yml` builds an **unsigned** IPA on every push that
touches `ios/` and uploads it as the `RustDoS-unsigned-ipa` artifact. Install it
with AltStore/Sideloadly, or sign it with your own certificate.

The workflow runs on Ubuntu with a pinned Swift/xtool pair and a prebuilt
Darwin SDK from the `ios-sdk` release, so it needs no Xcode.xip and no Apple
ID. Rebuild that asset with `xtool sdk build Xcode.xip <dir>` if the pinned
xtool version moves.

Differences from the desktop build:

- **No L1/L2.** iOS has no `AF_PACKET`, so `eth-flood` and `arp-flood` are
  gone. L3-L7 raw vectors use `SOCK_RAW` + `IP_HDRINCL`, which works in the app
  sandbox without root.
- **No JavaScript challenge solving.** The Boa engine has no iOS counterpart
  here; Cloudflare/Anubis challenges are detected but not solved.
- **Subdomains are opt-in.** crt.sh names are listed and verified, but the app
  attacks the primary host unless you select them.
- Origin discovery is listed, not auto-retargeted.

## Notes and limits

- IPv4 only.
- Raw vectors use the interface carrying the default route; the gateway MAC is
  read from `/proc/net/arp` and falls back to broadcast.
- Spoofed source ports stay below the kernel ephemeral range
  (`32768-60999`) so SYN-ACK/RST replies do not collide with real sockets.
- `tls-flood` skips certificate verification on purpose — it is a handshake
  flood, not a client.
- The L7 vectors are plain TCP/UDP; they do not follow redirects or handle
  HTTP keep-alive. Each request is a fresh connection, which is the point.
- Measured on a 4-vCPU container behind NAT: ~60k pps with every vector armed,
  ~17k pps on the default HTTP plan with L7 still responsive.

## Layout

```
src/main.rs      entry point, TUI loop, headless mode
src/app.rs       state machine, deadline, auto/manual
src/ui.rs        responsive ratatui rendering
src/target.rs    parsing, resolution, port scan, fingerprinting
src/vectors.rs   vector catalogue and auto-plan
src/attack.rs    worker loops, budgets
src/bypass.rs    CDN detection, origin discovery, crt.sh, challenge solving
src/js.rs        Boa-based challenge script runner
src/health.rs    target health prober
src/tls.rs       rustls config (no certificate verification)
src/net/raw.rs   AF_PACKET socket, checksums, packet builders
src/stats.rs     lock-free counters
```
