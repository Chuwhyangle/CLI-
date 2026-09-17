#!/usr/bin/env python3
# Extract raw HTTP messages that hit ServiceDispatcherServlet from a conn .c2s/.s2c file.
import sys, re

fn = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else fn + '.extract.txt'
only_dispatcher = True

with open(fn, 'rb') as f:
    raw = f.read()

messages = []
i = 0
n = len(raw)
while i < n:
    j = raw.find(b'\r\n\r\n', i)
    if j < 0:
        break
    head = raw[i:j]
    rest = j + 4
    m = re.search(rb'Content-Length:\s*(\d+)', head, re.I)
    if m:
        clen = int(m.group(1))
        body = raw[rest:rest + clen]
        rest += clen
    else:
        body = b''
    messages.append((head, body))
    i = rest

disp = [(k, h, b) for k, (h, b) in enumerate(messages)
        if b'ServiceDispatcherServlet' in h or b'application/x-java-serialized-object' in h]

lines = []
lines.append('# source: %s' % fn)
lines.append('# total HTTP messages: %d ; dispatcher-classified: %d' % (len(messages), len(disp)))
for k, head, body in disp:
    first = head.split(b'\r\n', 1)[0].decode('latin1')
    lines.append('')
    lines.append('=' * 70)
    lines.append('MESSAGE index=%d  %s  body_len=%d' % (k, first, len(body)))
    lines.append('-' * 70)
    lines.append('--- HEAD (plaintext) ---')
    lines.append(head.decode('latin1'))
    lines.append('--- BODY (raw bytes, hex) ---')
    for off in range(0, len(body), 16):
        chunk = body[off:off + 16]
        hexs = ' '.join('%02x' % b for b in chunk)
        lines.append('%08x  %s' % (off, hexs))

with open(out, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')
print('wrote', out, '(%d bytes, %d dispatcher messages)' % (len('\n'.join(lines)), len(disp)))
