# udp2raw-hardened

A security-audited and stealth-hardened fork of
[wangyu-/udp2raw](https://github.com/wangyu-/udp2raw) (branch `unified`, base commit `4208db6`, 2025-10-12).

udp2raw turns UDP traffic into fake-TCP/ICMP packets via raw sockets, letting UDP-based
tools (hysteria2, WireGuard, OpenVPN) pass networks that block or throttle UDP.

Upstream is largely dormant (last functional release 2023-02). This fork carries the
results of a full source audit (10.2k LOC) plus targeted improvements, focused on
**running hysteria2 through fake-TCP on lossy CN-to-international paths**.

## What changed

### Security audit fixes

| Bug | Fix |
|---|---|
| Unbounded `sscanf()` of `-k` into `char[1000]`, then a second unbounded `strcat` in key derivation | Bounded parsing + hard length check (1..900 B), fails cleanly |
| `recv_raw_tcp()` returned **success** on malformed TCP header length, leaving caller's `payload`/`payload_len` uninitialized | Returns `-1` |
| IP-header IHL check was commented out — headers claiming 0-byte length passed validation | Restored `ihl >= 5` check |
| MAC verification used plain `memcmp` | Constant-time comparison for all four auth modes |
| TCP checksum failures silently accepted | Dropped, except in `--fix-gro` mode (NAT path) |
| **The shared key was printed in the logs** — twice: in the "important variables" line and in the argv echo | Key masked (`S***(len=14)` / `-k ***`) |
| Windows build seeded mt19937 from a clock, with only 32 bits reaching the state | Seeded via `std::seed_seq` from **CryptGenRandom** (CSPRNG), all 19937 bits set |

Startup now also prints an advisory when the auth mode is `md5`/`simple`/`crc32` —
**all unkeyed**, i.e. not authentication at all (upstream default is `md5`).
Use `--auth-mode hmac_sha1 --cipher-mode aes128cbc`.

### Stealth hardening

- **TCP timestamps** now carry uptime-style ticks (random per-process base, 1000 Hz,
  monotonic) instead of **unix epoch seconds** — a passive fingerprint that gave away
  the fake stack. Echo semantics unchanged.
- **Heartbeats no longer beacon**: length randomized 80–1400 B per beat (upstream sent
  exactly 1200 B every 600 ms, both directions — a textbook machine-traffic signature),
  payload randomized, interval jittered ±150 ms. Receiver ignores heartbeat content,
  so this is wire-compatible with unpatched peers in the server→client direction…
  client→client must match (see compatibility notes below).
- Verified packet cosmetics: SYN option order matches Linux (`mss 1460, sackOK, TS,
  nop, wscale`), TTL 64, DF set, randomized IP IDs, plausible randomized windows.

### Windows client fixes (`UDP2RAW_MP`)

The upstream Windows path had three bugs that each broke or weakened the client:

1. **First handshake SYN sent from `0.0.0.0`** — `send_info.new_src_ip` was explicitly
   zeroed at init and only re-detected later; upstream filters drop it, so the client
   sat in handshake-retry forever. Fixed: detected source address applied at init.
2. **Ethernet header copied verbatim from the first captured frame** — if that frame
   was inbound, the header was `[dst = own NIC][src = gateway]`, so every SYN was
   addressed to the machine itself and never left it. Fixed: deterministic construction
   via `GetBestRoute` + `SendARP` (gateway MAC) and `GetAdaptersAddresses` (own MAC).
3. Fake RNG seeding above (also defeats the randomized heartbeat sizes).

### Build hardening

`-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wformat -Wformat-security
-fno-plt -fvisibility=hidden`, release builds stripped.

## Compatibility

- **All stealth changes are wire-format-compatible with unpatched peers**, except
  heartbeat *size*: unpatched peers accept any heartbeat length, but the randomized
  length means the two ends should both run this fork for symmetric stealth.
- `--fix-gro` changes the wire format (2-byte length prefix) and **must match on both
  ends** (this was already true upstream).
- Crypto/key derivation is unchanged from upstream — a hardened client pairs with an
  unpatched server and vice versa.

## Prebuilt binaries (GitHub Releases)

| File | Built from | Notes |
|---|---|---|
| `udp2raw-linux-x64` | this source, `make all` | static, stripped, hardened flags |
| `udp2raw-win64.exe` (release) | same source, mingw-w64 x86_64 cross-compile | static, needs Npcap |

sha256 sums are attached to the release. Linux binary requires root or `cap_net_raw`
(faketcp mode also uses iptables via `-a`); Windows exe needs **Npcap** with
WinPcap-compatible mode.

## Example: hysteria2 over fake-TCP

Server (Linux VPS, systemd unit recommended):

```
udp2raw -s -l 0.0.0.0:29999 -r 127.0.0.1:39999 -k <KEY> \
  --auth-mode hmac_sha1 --cipher-mode aes128cbc --raw-mode faketcp --fix-gro \
  --mtu-warn 1500 -a
```

Client (Windows, admin not required if Npcap was installed without admin-only):

```
udp2raw_win64.exe -c -l 127.0.0.1:3333 -r <SERVER>:29999 -k <KEY> \
  --auth-mode hmac_sha1 --cipher-mode aes128cbc --raw-mode faketcp --fix-gro \
  --mtu-warn 1500
```

Then point the hysteria2 client at `127.0.0.1:3333` (UDP) as if it were the server.
On a UDP-hostile line this traded ~50% of peak throughput for a working, noticeably
more responsive connection versus a dead UDP path; measure on your own line.

## Loss-recovery emulation (`feature/tcp-loss-emulation`)

Plain upstream fake TCP never retransmits: sequence numbers advance with zero
retransmissions, no duplicate ACKs, and an ACK for every packet. On a lossy path a
real TCP flow is continuously recovering, so its absence is a clean classifier.

That branch adds, per connection:

| Mechanism | Behaviour |
|---|---|
| Retransmit | outgoing data frames buffered (encrypted wire bytes, cap 192); only the head-of-line unACKed segment is resent, with the original seq range and fresh ack/timestamp/window |
| Loss gate | an RTO resend happens only when the peer's cumulative ACK has not moved for a full RTO (2 s, doubling, max 4 tries) and the segment was not resent within that window — a clean path never retransmits |
| Cumulative ACK | ACK stays at the contiguous receive position; a gap holds it there while out-of-order frames are still delivered |
| Dup-ACK | up to 5 ACK-only frames per gap |
| Fast retransmit | 3 dup-ACKs resend the segment at the acked position immediately |
| Re-ACK | a retransmission dropped by the replay window (i.e. our ACK was lost) gets an ACK, at most one per 100 ms — a real TCP sends one dup-ACK per segment, not per duplicate byte |
| Retire | scan-based, not FIFO: new data is sent while old segments await retransmission |

Retransmissions reuse the inner anti-replay seq, so a peer that already processed them
drops the copy — nothing is duplicated into user data. An unpatched peer sees ordinary
data frames, so a patched end degrades to RTO-only recovery instead of breaking.

The outer fake-TCP seq is cosmetic and must never gate delivery: seq_mode 3 rewinds
`send_info.seq` to the peer's ACK when the emulated window fills, so a frame can carry
new payload under an old seq. Frames behind the current ACK are therefore decrypted
and processed like any other; only the inner anti-replay window may drop a duplicate.
(An earlier build dropped them on the outer seq and lost real data under load — live
throughput fell from ~1.5 MB/s to tens of KB/s.)

Verified on loopback at 8% netem loss + 25%/50% reorder: 42/60 probes echoed intact,
zero unresolved sequence holes, and the only retransmissions on the wire were 2
client→server; the rest of the recovery was fast retransmit on dup-ACKs (6 client,
3 server), with `giveup=0`. A 0% control produced no emulation events at all. The
first timer-only build of the emulation fired 39/18 RTO resends on an equivalent
clean-ish path because ACKs only ride the 600 ms heartbeat and the old 800 ms RTO
expired during normal bursts; the ACK-progress gate removed that entirely.

(The 18/60 probe losses above sit on the unprotected plain-UDP echo hop, which the
tunnel cannot retransmit — the sequence-coverage check, not the probe count, is the
tunnel-layer verdict.)

The first build of this branch wired the dup-ACK/re-ACK emitter only into an unused
receive wrapper (`recv_safer_notused`), so that half of the emulation never ran; the
counters added since make this visible. With the emitter on the live path but still
on the old timer-only retransmit, a 5% loss + reorder run recorded 7/11 RTO retx and
one abandoned segment — the behaviour the ACK-progress gate above replaced.

Each connection now logs a summary at log_info, at most every 10 s and only when a
counter changed:

```
[203.0.113.9:29999]tcp-emul retx=2 fast_retx=6 dupack=39 reack=0 gaps=14 giveup=0 ackidle=0ms inflight=0
```

Run the binary with `--log-level 4` (INFO) to see it. ACK-only frames are 54 B on the
wire (AES padding + HMAC) — the same size as small data frames — so capture heuristics
cannot count dup-ACKs; the counters are the reliable measure. The benefit on a real
lossy path is still unproven and needs measurement there; `tests/netem_loopback.sh`
and `tests/analyze_capture.py` are the harness.

## Known limitations

- Loss-recovery emulation exists on `feature/tcp-loss-emulation` only; the default
  branch still does not retransmit.
- Any scanner can complete the fake handshake (no crypto before the handshake);
  the port looks "open but silent" to probes.
- No padding of data packets (only heartbeats are randomized), so payload-length
  distributions of the inner protocol remain visible.

## Credits

All upstream work is [wangyu-](https://github.com/wangyu-/udp2raw) (MIT).
This fork's changes are also MIT.
