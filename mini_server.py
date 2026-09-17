from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

RECV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mini_server_recv.txt")

class H(BaseHTTPRequestHandler):
    def _handle(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n) if n else b''
        lines = ['请求行: ' + self.requestline]
        lines.append('请求头:')
        for k, v in self.headers.items():
            lines.append('  %s: %s' % (k, v))
        lines.append('空行分隔后 Body:')
        lines.append(body.decode('utf-8', 'replace'))
        with open(RECV_PATH, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        data = json.dumps({'status': 200, 'msg': 'ok'}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(data)

    do_POST = _handle
    do_GET = _handle

    def log_message(self, *a):
        pass

HTTPServer(('127.0.0.1', 9800), H).serve_forever()
