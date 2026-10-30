import http.server
import os

# Tests pass an ephemeral port so they never collide with a manually started server.
PORT = int(os.environ.get("PRIVACYLENS_TESTLAB_PORT", "8000"))
os.chdir(os.path.join(os.path.dirname(__file__), "pages"))

# Threaded: Chrome opens idle "pre-connect" sockets, and a single-threaded
# server blocks on one of them while every other request (pages, iframes,
# the extension's Test Lab tab) waits.
http.server.ThreadingHTTPServer.allow_reuse_address = True
http.server.ThreadingHTTPServer.daemon_threads = True
with http.server.ThreadingHTTPServer(("", PORT), http.server.SimpleHTTPRequestHandler) as httpd:
    print(f"Serving testlab pages on http://localhost:{PORT}")
    httpd.serve_forever()
