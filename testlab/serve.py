import http.server
import socketserver
import os

PORT = 8000
os.chdir(os.path.join(os.path.dirname(__file__), "pages"))

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving testlab pages on http://localhost:{PORT}")
    httpd.serve_forever()
