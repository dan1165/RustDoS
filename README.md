# RustDoS

A multi-layer (L1-L7) DDoS stress tester with a terminal UI, written in Rust.

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

## Automatic vs manual

By default the tool picks the layers for you from what the scan found. Press
`m` to switch to manual, then `Space` to toggle single vectors or `1`-`7` to
toggle a whole layer. Any manual toggle drops you out of auto mode.

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
| Armed   | `Up`/`Down` move, `Space` toggle, `1`-`7` toggle layer, `m` auto/manual, `a` arm all, `n` arm none, `Enter` start, `Esc` edit |
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
src/app.rs       state machine and key handling
src/ui.rs        ratatui rendering
src/target.rs    parsing, resolution, fingerprinting
src/vectors.rs   vector catalogue and auto-plan
src/attack.rs    worker loops, budgets, TLS setup
src/net/raw.rs   AF_PACKET socket, checksums, packet builders
src/stats.rs     lock-free counters
```
