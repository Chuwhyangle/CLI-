#!/usr/bin/env python3
import sys, struct, collections, re

FN = sys.argv[1]
def read_pcap(fn):
    with open(fn,'rb') as f:
        gh=f.read(24); magic=gh[:4]
        endian = '<' if magic==b'\xd4\xc3\xb2\xa1' else ('>' if magic==b'\xa1\xb2\xc3\xd4' else None)
        if not endian: return None
        linktype=struct.unpack(endian+'I',gh[20:24])[0]
        out=[]
        while True:
            h=f.read(16)
            if len(h)<16: break
            ts,_,incl,_=struct.unpack(endian+'IIII',h)
            out.append((ts*1e6, f.read(incl)))
        return linktype,out

lt,pkts=read_pcap(FN)
D=collections.defaultdict(list)
def ipn(b): return '.'.join(str(x) for x in b)
for _,data in pkts:
    if len(data)<14 or data[12:14]!=b'\x08\x00': continue
    ip=data[14:]
    if len(ip)<20 or ip[9]!=6: continue
    tcp=ip[(ip[0]&0xf)*4:]
    if len(tcp)<20: continue
    sport,dport=struct.unpack('>HH',tcp[0:4]); seq=struct.unpack('>I',tcp[4:8])[0]
    pl=tcp[((tcp[12]>>4)&0xf)*4:]
    if pl:
        D[(ipn(ip[12:16]),sport,ipn(ip[16:20]),dport)].append((seq,pl))

def rebuild(chunks):
    chunks.sort(); out=bytearray(); pos=None
    for seq,data in chunks:
        if pos is None: out=bytearray(data); pos=seq+len(data); continue
        if seq>pos: out+=b'\x00'*(seq-pos)+data; pos=seq+len(data)
        elif seq+len(data)>pos:
            out+=data[pos-seq:]; pos=seq+len(data)
    return bytes(out)

MAGIC=bytes.fromhex('7271890b92')
disp_bodies=[]; magic_hits=0; provision=0; plainish=0
for key,chunks in D.items():
    (srcip,sport,dstip,dport)=key
    if dport!=18080: continue
    s=rebuild(chunks)
    magic_hits += s.count(MAGIC)
    # locate dispatcher requests
    idx=0
    while True:
        i=s.find(b'ServiceDispatcherServlet', idx)
        if i<0: break
        idx=i+1
        he=s.find(b'\r\n\r\n', i)
        if he<0: continue
        head=s[i:he]
        m=re.search(rb'Content-Length:\s*(\d+)', head, re.I)
        if not m: continue
        clen=int(m.group(1))
        body=s[he+4:he+4+clen]
        if body:
            disp_bodies.append((clen, body[:20].hex()))
    # provision count
    provision += s.count(b'/provision')
print(f'connections(c2s dirs scanned)=? total dirs={len(D)}')
print(f'global MAGIC(7271890b92) hits in c2s payload = {magic_hits}')
print(f'/provision occurrences = {provision}')
print(f'dispatcher request bodies parsed = {len(disp_bodies)}')
if disp_bodies:
    mstart = sum(1 for l,h in disp_bodies if h.startswith(MAGIC.hex()))
    print(f'  bodies whose first5B == MAGIC : {mstart}/{len(disp_bodies)}')
    print('  first 12 samples (len, first20hex):')
    for l,h in disp_bodies[:12]:
        print(f'    len={l:<6} {h}')
