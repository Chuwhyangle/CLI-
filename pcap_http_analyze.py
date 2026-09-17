#!/usr/bin/env python3
# pcap TCP-reassembly HTTP analyzer for NC client traffic on port 18080
import sys, struct, collections

FN = sys.argv[1] if len(sys.argv) > 1 else 'nc2.pcap'

def read_pcap(fn):
    with open(fn, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24: return None
        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'; tzoff = struct.unpack('<i', gh[8:12])[0]
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'; tzoff = struct.unpack('>i', gh[8:12])[0]
        else:
            return None
        linktype = struct.unpack(endian + 'I', gh[20:24])[0]
        pkts = []
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            ts_sec, ts_usec, incl, orig = struct.unpack(endian + 'IIII', hdr)
            data = f.read(incl)
            pkts.append((ts_sec*1e6+ts_usec, data))
        return linktype, pkts

lt, pkts = read_pcap(FN)
if lt is None:
    sys.exit('bad pcap')
if lt != 1:
    sys.exit(f'unexpected linktype {lt}')

# group tcp payloads per connection-direction
D = collections.defaultdict(list)   # key (srcip,sport,dstip,dport) -> [(seq,data)]
meta = collections.defaultdict(list) # first time
def ip2(b): return '.'.join(str(x) for x in b)
def parse(payload):
    if len(payload) < 14: return None
    ethertype = payload[12:14]
    if ethertype == b'\x08\x00':
        ip = payload[14:]
        if len(ip) < 20: return None
        ihl = (ip[0] & 0x0f) * 4
        proto = ip[9]
        if proto != 6: return None
        tcp = ip[ihl:]
        if len(tcp) < 20: return None
        sport, dport = struct.unpack('>HH', tcp[0:4])
        seq = struct.unpack('>I', tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload_data = tcp[doff:]
        src = ip2(ip[12:16]); dst = ip2(ip[16:20])
        return (src, sport, dst, dport), seq, payload_data
    return None

first_ts = {}
for ts, data in pkts:
    r = parse(data)
    if not r: continue
    (src, sport, dst, dport), seq, pl = r
    key = (src, sport, dst, dport)
    if pl:
        D[key].append((seq, pl))
        first_ts.setdefault(key, ts)

def rebuild(chunks):
    chunks.sort()
    out = bytearray(); pos = None; gaps = 0
    for seq, data in chunks:
        if pos is None:
            out = bytearray(data); pos = seq + len(data); continue
        if seq > pos:
            gaps += (seq - pos)
            out += b'\x00' * (seq - pos) + data; pos = seq + len(data)
        elif seq + len(data) > pos:
            # overlap: append only new tail
            newpos = seq + len(data)
            if newpos > pos:
                out += data[pos - seq:]
                pos = newpos
        # else fully duplicate: ignore
    return bytes(out), gaps

def parse_http(stream):
    """yield (kind, headline, headers, body) for HTTP messages"""
    i = 0; n = len(stream)
    while i < n:
        j = stream.find(b'\r\n\r\n', i)
        if j < 0: break
        head = stream[i:j]
        lines = head.split(b'\r\n')
        first = lines[0]
        headers = {}
        for ln in lines[1:]:
            if b':' in ln:
                k, v = ln.split(b':', 1)
                headers[k.strip().lower()] = v.strip()
        body = b''
        nxt = j + 4
        clen = headers.get('content-length')
        if clen is not None and clen.isdigit():
            body = stream[nxt:nxt+int(clen)]
            nxt += int(clen)
        elif first.startswith(b'HTTP') and headers.get('transfer-encoding','').lower() == 'chunked':
            # minimal: read until 0 chunk
            p = nxt
            while True:
                e = stream.find(b'\r\n', p)
                if e < 0: break
                try:
                    sz = int(stream[p:e].split(b';')[0], 16)
                except Exception:
                    break
                if sz == 0: break
                p = e + 2 + sz + 2
            nxt = p
        kind = 'REQ' if first.startswith((b'GET', b'POST', b'HEAD', b'PUT')) else 'RESP'
        yield kind, first, headers, body
        i = nxt
        if nxt <= j: break

MAGIC = bytes.fromhex('7271890b92')
req_paths = collections.Counter()
disp = []     # dispatcher request bodies (first bytes, lengths)
resp_types = collections.Counter()
disp_resp = []
skipped_req = 0

for key, chunks in D.items():
    (src, sport, dst, dport) = key
    stream, gaps = rebuild(chunks)
    if not stream: continue
    is_c2s = (dport == 18080)
    for kind, first, headers, body in parse_http(stream):
        if kind == 'REQ':
            line = first.decode('latin1')
            path = line.split(' ')[1] if len(line.split(' ')) > 1 else line
            req_paths[path.split('?')[0]] += 1
            if 'ServiceDispatcherServlet' in path:
                if len(disp) < 6:
                    disp.append((path, len(body), body[:24].hex()))
        else:
            ct = headers.get('content-type', b'').decode('latin1')
            resp_types[ct] += 1
            # which request did this respond to? approximate: dispatcher responses have serialized-object ct or octet
            if ct.startswith('application/x-java-serialized-object') and len(disp_resp) < 6:
                disp_resp.append((first.decode('latin1'), len(body), body[:24].hex()))

print('=== unique REQUEST paths (count) ===')
for p, c in req_paths.most_common(40):
    print(f'{c:6d}  {p}')
print()
print('=== ServiceDispatcherServlet REQUEST bodies ===')
for path, blen, h16 in disp:
    flag = 'MAGIC!' if h16.startswith(MAGIC.hex()) else ''
    print(f'len={blen:<6} first24={h16} {flag}')
print(f'  (total dispatcher requests captured across all reqs: shown first few; more in counts)')
print()
print('=== response content-types (count) ===')
for ct, c in resp_types.most_common(15):
    print(f'{c:6d}  {ct}')
print()
print('=== dispatcher RESPONSE bodies (serialized-object) ===')
for first, blen, h16 in disp_resp:
    print(f'{first} len={blen} first24={h16}')
print()
print('DONE. connections=%d' % len(D))
