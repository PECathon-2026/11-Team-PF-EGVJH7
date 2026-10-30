import http.server
import socketserver
import os

# Tests pass an ephemeral port so they never collide with a manually started server.
PORT = int(os.environ.get("PRIVACYLENS_TESTLAB_PORT", "8000"))
os.chdir(os.path.join(os.path.dirname(__file__), "pages"))

Handler = http.server.SimpleHTTPRequestHandler
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving testlab pages on http://localhost:{PORT}")
    httpd.serve_forever()
