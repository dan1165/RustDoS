# AGENTS.md

RustDoS: a Rust TUI DDoS stress tester, L1-L7. Single binary, no tests, no git repo.

## Build and verify

```sh
cargo build            # fast-ish; use this while iterating
cargo build --release  # ~6 min: LTO + codegen-units=1
```

There are no unit or integration tests. `cargo build` is the only compile gate. Verify behaviour with the headless mode, never by eyeballing the TUI alone:

```sh
./target/debug/rustdos --list
./target/debug/rustdos --test example.com 80 4
./target/debug/rustdos --test 1.1.1.1 80 4 syn-flood http-get   # explicit vectors
```

`--test <target> [port] [seconds] [vectors...]` prints per-second counters and a per-vector breakdown.

**TUI renders nothing without a sized pty.** `script` alone gives a 0x0 pty and ratatui draws empty frames. Always set the size:

```sh
script -q -c "stty rows 45 cols 130; timeout 3 ./target/debug/rustdos" /dev/null
```

Drive keys by piping with sleeps (`printf 'example.com'; sleep 0.3; printf '\r'`). Enter is `\r`.

## Root

Raw L1-L4 vectors need `CAP_NET_RAW`. Without root they are disabled and greyed in the list (a log line says so) — the tool still runs with L7 only. When testing raw vectors, confirm `raw=ok` in `--test` output.

## Adding a vector

The vector count is hardcoded in two places. Adding one without touching both is a compile error (array length) or a runtime panic in `Stats::hit` (index out of bounds):

- `src/vectors.rs`: `pub const ALL: [Spec; 15]`
- `src/stats.rs`: `packets: [AtomicU64; 15]`, `bytes: [AtomicU64; 15]`

Then wire it up in `src/attack.rs`: `workers()`, `raw_rate()`, and either `raw_worker()` or `async_worker()`. `Ctx.budgets` is indexed by `Vector::index()`, so every vector needs a budget entry — that is built from `ALL` in both `app.rs` and `main.rs`.

`Ctx` is constructed twice (`app.rs::begin_attack`, `main.rs::selftest`). Change both.

## Constraints that look arbitrary but are not

- **Raw vectors are rate-capped** (`raw_rate()`). Uncapped, they saturate the interface and starve L7. SYN floods are capped lowest because every SYN-ACK comes back and forces the kernel to emit a RST, so they are disproportionately expensive. Don't remove the caps to "go faster" without re-measuring L7 throughput.
- **Spoofed source ports stay below 32768** (`rand_port()`). The kernel ephemeral range is 32768-60999; overlapping ports make spoofed SYN-ACKs reset real connections.
- **Interface discovery prefers the default route** (`raw::discover`). Picking the first up interface selects a Docker bridge and nothing reaches the target.
- **`tls-flood` skips cert verification on purpose** — it is a handshake flood, not a client. `rustls` is pinned to the `ring` provider because `aws-lc-rs` needs cmake.
- **HTTP vectors do not read responses.** They connect, write, drop. Adding a read back costs several-fold throughput.

## Layout

`main.rs` entry + TUI loop + headless mode · `app.rs` state machine · `ui.rs` ratatui · `target.rs` parse/resolve/fingerprint · `vectors.rs` catalogue + auto-plan · `attack.rs` workers/budgets/TLS · `net/raw.rs` AF_PACKET, checksums, packet builders · `stats.rs` counters.

Platform is Alpine/musl/aarch64; `gcc` and `musl-dev` are required for linking.
