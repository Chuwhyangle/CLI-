import socket, threading, time, os, sys

LISTEN_IP = os.environ.get('NC_LISTEN_IP', '127.0.0.2')
LISTEN_PORT = int(os.environ.get('NC_LISTEN_PORT', '80'))
TARGET_IP = os.environ.get('NC_TARGET_IP', '127.0.0.1')
TARGET_PORT = int(os.environ.get('NC_TARGET_PORT', '80'))
LOG_DIR = os.path.dirname(os.path.abspath(__file__))

conn_counter = [0]
lock = threading.Lock()

def ts():
    return time.strftime('%Y-%m-%d %H:%M:%S') + ('.%03d' % int((time.time() % 1) * 1000))

def esc(data):
    out = []
    for b in data:
        if b == 13:
            continue  # HTTP CRLF: drop CR for readability
        elif b == 10:
            out.append('\n')
        elif 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append('\\x%02x' % b)
    return ''.join(out)

def pump(src, dst, txt, raw, tag, cid):
    while True:
        try:
            data = src.recv(65536)
        except Exception:
            break
        if not data:
            break
        try:
            dst.sendall(data)
        except Exception:
            break
        with lock:
            txt.write('[%s] %s conn#%d (+%d bytes)\n%s\n' % (ts(), tag, cid, len(data), esc(data)))
            txt.flush()
            raw.write(data)
            raw.flush()
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass

def handle(csock, addr):
    conn_counter[0] += 1
    cid = conn_counter[0]
    print('[%s] conn#%d from %s:%s' % (ts(), cid, addr[0], addr[1]), flush=True)
    f_txt = open(os.path.join(LOG_DIR, 'conn_%03d.txt' % cid), 'w', encoding='utf-8', errors='replace')
    f_c2s = open(os.path.join(LOG_DIR, 'conn_%03d.c2s' % cid), 'wb')
    f_s2c = open(os.path.join(LOG_DIR, 'conn_%03d.s2c' % cid), 'wb')
    f_txt.write('=== conn#%d from %s:%s ===\n' % (cid, addr[0], addr[1]))
    s = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=30)
    f_txt.write('[%s] -> connected %s:%d\n' % (ts(), TARGET_IP, TARGET_PORT)); f_txt.flush()
    t1 = threading.Thread(target=pump, args=(csock, s, f_txt, f_c2s, 'C->S', cid)); t1.start()
    t2 = threading.Thread(target=pump, args=(s, csock, f_txt, f_s2c, 'S->C', cid)); t2.start()
    t1.join(); t2.join()
    f_txt.write('=== conn#%d closed ===\n' % cid)
    for f in (f_txt, f_c2s, f_s2c):
        f.close()
    csock.close(); s.close()
    print('[%s] conn#%d closed' % (ts(), cid), flush=True)

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_IP, LISTEN_PORT))
    srv.listen(64)
    print('[%s] relay listening on %s:%d -> %s:%d  (logs: %s)' % (ts(), LISTEN_IP, LISTEN_PORT, TARGET_IP, TARGET_PORT, LOG_DIR), flush=True)
    while True:
        cs, addr = srv.accept()
        threading.Thread(target=handle, args=(cs, addr), daemon=True).start()

if __name__ == '__main__':
    main()
