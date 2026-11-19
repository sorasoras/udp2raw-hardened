#!/bin/bash
# Loopback test for fake-TCP loss-recovery emulation.
#
# Builds a tunnel over lo, injects loss with netem, and drives an echo server
# through it. Then analyses the capture for retransmissions, dup-ACKs and
# sequence coverage.
#
# Usage: sudo ./netem_loopback.sh /path/to/udp2raw [loss_percent]
#
# Notes:
#  - needs root (raw sockets + tc + tcpdump)
#  - the echo server itself is plain UDP and is NOT retransmitted by the
#    tunnel, so end-to-end delivery counts under heavy loss include loss on
#    that unprotected hop. Use the capture analysis (not the echo count) to
#    judge whether the tunnel layer recovers its own holes.
set +e

BIN=${1:?usage: $0 /path/to/udp2raw [loss_percent]}
LOSS=${2:-8}
KEY=${KEY:-testkey9}
SPORT=45001
CPORT=45002
ECHO=5599
OUT=${OUT:-/tmp/tcpemul-test}

mkdir -p "$OUT"
rm -f "$OUT"/capture.pcap "$OUT"/capture.txt

echo "=== netem ${LOSS}% loss on lo ==="
tc qdisc del dev lo root 2>/dev/null
tc qdisc add dev lo root netem loss "${LOSS}%"

python3 - "$ECHO" <<'PY' >"$OUT"/echo.log 2>&1 &
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', port))
s.settimeout(90)
for _ in range(500):
    try:
        d, a = s.recvfrom(2048)
        s.sendto(b'echo:' + d, a)
    except socket.timeout:
        break
PY
ECHO_PID=$!

"$BIN" -s -l 127.0.0.1:$SPORT -r 127.0.0.1:$ECHO -k "$KEY" \
    --auth-mode hmac_sha1 --cipher-mode aes128cbc --raw-mode faketcp \
    --fix-gro --mtu-warn 1500 --log-level 2 -a >"$OUT"/server.log 2>&1 &
SRV_PID=$!
sleep 2

"$BIN" -c -l 127.0.0.1:$CPORT -r 127.0.0.1:$SPORT -k "$KEY" \
    --auth-mode hmac_sha1 --cipher-mode aes128cbc --raw-mode faketcp \
    --fix-gro --mtu-warn 1500 --log-level 2 -a >"$OUT"/client.log 2>&1 &
CLI_PID=$!
sleep 3

timeout 60 tcpdump -ni lo "tcp port $SPORT" -w "$OUT"/capture.pcap >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

python3 - "$CPORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
s.settimeout(8)
ok = lost = 0
for i in range(60):
    s.sendto(('probe%03d' % i).encode(), ('127.0.0.1', port))
    try:
        d, _ = s.recvfrom(2048)
        assert d.decode().endswith('probe%03d' % i), 'payload corrupted'
        ok += 1
    except socket.timeout:
        lost += 1
    time.sleep(0.2)
print(f'echoed intact: {ok}, lost: {lost} of 60')
PY

sleep 8
kill $TCPDUMP_PID $CLI_PID $SRV_PID $ECHO_PID 2>/dev/null
sleep 1
tc qdisc del dev lo root 2>/dev/null

echo "=== capture analysis ==="
tcpdump -nr "$OUT"/capture.pcap -S 2>/dev/null >"$OUT"/capture.txt
"$(dirname "$0")"/analyze_capture.py "$OUT"/capture.txt $SPORT
