#!/usr/bin/env python3
"""Analyse a fake-TCP capture for loss-recovery behaviour.

Reads tcpdump text output (tcpdump -nr file.pcap -S) and reports, per
direction: retransmissions (same seq+len seen more than once), repeated ACK
values in small frames (dup-ACK evidence), and whether the sequence space is
fully covered at the end (every hole eventually filled).

Usage: tcpdump -nr cap.pcap -S > cap.txt
       ./analyze_capture.py cap.txt SERVER_PORT
"""
import re
import sys
from collections import Counter

PAT = re.compile(
    r'IP (\S+?)\.(\d+) > (\S+?)\.(\d+): Flags \[([^\]]+)\], '
    r'seq (\d+)(?::(\d+))?, ack (\d+), win (\d+)'
    r'(?:, options \[[^\]]*\])?(?:, length (\d+))?')

DATA_MIN = 21  # frames at or below this size are hb/ack carriers in practice


def parse(path):
    rows = []
    for line in open(path, errors='replace'):
        m = PAT.search(line)
        if not m:
            continue
        rows.append(dict(
            src=m.group(1) + ':' + m.group(2),
            dst_port=m.group(4),
            seq=int(m.group(6)),
            length=int(m.group(10) or 0),
            ack=int(m.group(8)),
        ))
    return rows


def report(rows, label):
    data = [r for r in rows if r['length'] >= DATA_MIN]
    small = [r for r in rows if r['length'] < DATA_MIN]
    seen = Counter((r['src'], r['seq'], r['length']) for r in data)
    retx = {k: v for k, v in seen.items() if v > 1}
    total_retx = sum(v - 1 for v in retx.values())
    print(f'{label}: {len(rows)} frames ({len(data)} data, {len(small)} hb/ack)')
    print(f'  retransmissions: {total_retx}')
    for k, v in sorted(retx.items(), key=lambda x: -x[1])[:5]:
        print(f'    seq {k[1]} len {k[2]} x{v} from {k[0]}')
    acks = Counter(r['ack'] for r in small)
    dup = {k: v for k, v in acks.items() if v >= 2}
    print(f'  small-frame ack values seen 2+ times: {len(dup)}')
    for k, v in sorted(dup.items(), key=lambda x: -x[1])[:5]:
        print(f'    ack {k} x{v}')
    return data


def coverage(data, label):
    if not data:
        return
    spans = sorted({(r['seq'], r['seq'] + r['length']) for r in data})
    cur = spans[0][0]
    holes = 0
    for a, b in spans:
        if a > cur:
            holes += 1
            cur = b
        else:
            cur = max(cur, b)
    print(f'{label} seq coverage {spans[0][0]}..{cur}, unresolved holes: {holes}')


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    path, port = sys.argv[1], sys.argv[2]
    rows = parse(path)
    print(f'parsed {len(rows)} packets')
    c2s = [r for r in rows if r['dst_port'] == port]
    s2c = [r for r in rows if r['src'].endswith(':' + port)]
    d1 = report(c2s, 'client->server')
    report(s2c, 'server->client')
    coverage(d1, 'client->server')
    return 0


if __name__ == '__main__':
    sys.exit(main())
