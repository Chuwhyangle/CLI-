#!/usr/bin/env python3
import sys, struct, collections
FN = sys.argv[1]; OUT = sys.argv[2]
def read_pcap(fn):
    with open(fn,'rb') as f:
        gh=f.read(24); magic=gh[:4]
        endian = '<' if magic==b'\xd4\xc3\xb2\xa1' else ('>' if magic==b'\xa1\xb2\xc3\xd4' else None)
        if not endian: sys.exit('bad')
        pkts=[]
        while True:
            h=f.read(16)
            if len(h)<16: break
            _,_,incl,_=struct.unpack(endian+'IIII',h)
            pkts.append(f.read(incl))
        return pkts
def ipn(b): return '.'.join(str(x) for x in b)
D=collections.defaultdict(list)
for data in read_pcap(FN):
    if len(data)<14 or data[12:14]!=b'\x08\x00': continue
    ip=data[14:]
    if len(ip)<20 or ip[9]!=6: continue
    tcp=ip[(ip[0]&0xf)*4:]
    if len(tcp)<20: continue
    sport,dport=struct.unpack('>HH',tcp[0:4]); seq=struct.unpack('>I',tcp[4:8])[0]
    pl=tcp[((tcp[12]>>4)&0xf)*4:]
    if pl: D[(ipn(ip[12:16]),sport,ipn(ip[16:20]),dport)].append((seq,pl))
def rebuild(chunks):
    chunks.sort(); out=bytearray(); pos=None
    for seq,data in chunks:
        if pos is None: out=bytearray(data); pos=seq+len(data); continue
        if seq>pos: out+=b'\x00'*(seq-pos)+data; pos=seq+len(data)
        elif seq+len(data)>pos: out+=data[pos-seq:]; pos=seq+len(data)
    return bytes(out)
best=None; bestscore=-1
for key,chunks in D.items():
    (sip,sp,dip,dp)=key
    if dp!=18080: continue
    s=rebuild(chunks)
    n=s.count(b'ServiceDispatcherServlet')
    if n>bestscore and n>0:
        bestscore=n; best=s
if best is None:
    sys.exit('no dispatcher c2s stream found')
with open(OUT,'wb') as f: f.write(best)
print('wrote', OUT, 'bytes=', len(best), 'dispatcher_occurrences=', bestscore)
