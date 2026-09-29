"""Serve the local canvas demo and save the rendered WebM beside this script."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "NetAdaptAI-demo.webm"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/NetAdaptAI-demo.webm" and OUTPUT.exists():
            video = OUTPUT.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "video/webm")
            self.send_header("Content-Length", str(len(video)))
            self.end_headers()
            self.wfile.write(video)
            return
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        page = (ROOT / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        if self.path != "/save" or self.headers.get_content_type() != "video/webm":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 80 * 1024 * 1024:
            self.send_error(413, "Video must be between 1 byte and 80 MB")
            return
        data = self.rfile.read(length)
        if not data.startswith(b"\x1aE\xdf\xa3"):
            self.send_error(400, "The uploaded file is not a valid WebM container")
            return
        OUTPUT.write_bytes(data)
        body = json.dumps({"path": str(OUTPUT)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Open http://127.0.0.1:8765 to render the NetAdaptAI demo video.")
    print(f"The video will be saved to: {OUTPUT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping demo video renderer.")
        server.server_close()
