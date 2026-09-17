#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reconstruct per-direction raw TCP byte streams (client<->server) from a pcapng
via tshark's tcp.payload dump, excluding SSH. Writes srv_<clientport>.c2s/.s2c."""
import subprocess, sys, re, os, collections

TSHARK = os.environ.get("TSHARK", r"C:\Program Files\Wireshark\tshark.exe")
CLIENT_IP = os.environ.get("NC_CLIENT_IP", "")

def main(pcap, outdir):
    # fields: frame number, src ip, dst ip, src port, dst port, tcp payload(hex)
    fields = ["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.payload"]
    cmd = [TSHARK, "-r", pcap, "-Y", "tcp.payload && tcp.port != 22",
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.check_output(cmd, text=True, errors="replace")

    # Group by the configured client address, or use a private-network heuristic.
    streams = collections.OrderedDict()  # cport -> {"c2s": [], "s2c": []}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 6:
            continue
        try:
            src, dst = parts[1], parts[2]
            sport, dport = int(parts[3]), int(parts[4])
        except ValueError:
            continue
        payload_hex = parts[5].strip().replace(":", "")
        if not payload_hex:
            continue
        payload = bytes.fromhex(payload_hex)
        # Decide direction from NC_CLIENT_IP, or use a private-network heuristic.
        if (CLIENT_IP and src == CLIENT_IP) or (not CLIENT_IP and src.startswith("192.168.")):
            cport = sport
            streams.setdefault(cport, {"c2s": [], "s2c": []})
            streams[cport]["c2s"].append(payload)
        else:
            cport = dport
            streams.setdefault(cport, {"c2s": [], "s2c": []})
            streams[cport]["s2c"].append(payload)

    written = []
    for cport, data in streams.items():
        for side in ("c2s", "s2c"):
            raw = b"".join(data[side])
            if not raw:
                continue
            path = os.path.join(outdir, "srv_%d.%s" % (cport, side))
            with open(path, "wb") as fh:
                fh.write(raw)
            written.append((path, len(raw)))
    return written

if __name__ == "__main__":
    pcap = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(pcap)
    for path, size in main(pcap, outdir):
        print("%-8d bytes  %s" % (size, path))
