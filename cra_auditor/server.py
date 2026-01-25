import http.server
import socketserver
import os
import sys

PORT = 8099
# DIRECTORY = "/app/dist"

# Auto-detect the correct frontend build folder
if os.path.exists("/app/dist"):
    DIRECTORY = "/app/dist"
elif os.path.exists("/app/build"):
    DIRECTORY = "/app/build"
else:
    print("CRITICAL ERROR: Neither /app/dist nor /app/build found!", file=sys.stderr)
    print(f"Contents of /app: {os.listdir('/app')}", file=sys.stderr)
    sys.exit(1)

class SpaHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve index.html for SPA routing if file not found
        try:
            path = self.translate_path(self.path)
            if not os.path.exists(path) or os.path.isdir(path):
                # Check if it's a file request or a route request
                if '.' not in os.path.basename(path):
                    self.path = '/index.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        except Exception as e:
            print(f"Error handling request: {e}", file=sys.stderr)
            self.send_error(500, str(e))

# Robust Directory Changing
print(f"Attempting to serve from: {DIRECTORY}")
if not os.path.exists(DIRECTORY):
    print(f"CRITICAL ERROR: Directory {DIRECTORY} does not exist.", file=sys.stderr)
    print(f"Current working directory content: {os.listdir('.')}", file=sys.stderr)
    sys.exit(1)

os.chdir(DIRECTORY)

# Allow address reuse to prevent "Address already in use" errors on restarts
socketserver.TCPServer.allow_reuse_address = True

try:
    with socketserver.TCPServer(("", PORT), SpaHandler) as httpd:
        print(f"Serving HTTP on 0.0.0.0 port {PORT} from {DIRECTORY}...")
        httpd.serve_forever()
except OSError as e:
    print(f"Failed to bind to port {PORT}: {e}", file=sys.stderr)
    sys.exit(1)