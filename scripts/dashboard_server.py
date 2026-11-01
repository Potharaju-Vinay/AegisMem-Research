"""
AegisMem Reviewer Demo: Compose Dashboard Service (Part D9)
Lightweight reverse proxy and SPA static file server for React frontend.
Serves frontend/dist and proxies /api/* calls to aegismem-gateway:8000.
Reachable at 127.0.0.1 only.
"""

import argparse
import http.server
import os
import socketserver
import sys
import urllib.error
import urllib.request
from pathlib import Path


class DashboardProxyHandler(http.server.SimpleHTTPRequestHandler):
    gateway_url = "http://aegismem-gateway:8000"
    dist_dir = Path("/app/frontend/dist")

    def __init__(self, *args, **kwargs):
        # Fallback to local path if not in container
        if not self.dist_dir.exists():
            self.dist_dir = Path(__file__).resolve().parent.parent / "frontend" / "dist"
        super().__init__(*args, directory=str(self.dist_dir), **kwargs)

    def end_headers(self):
        if not getattr(self, "path", "").startswith("/api/"):
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/") or self.path in ("/health", "/status"):
            self._proxy()
        else:
            # SPA Fallback: If static file does not exist, serve index.html
            requested_path = self.dist_dir / self.path.lstrip("/").split("?")[0]
            if not requested_path.exists() and not self.path.startswith("/assets/"):
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    def _proxy(self):
        # Rewrite /api/foo -> /foo on gateway
        target_path = self.path
        if target_path.startswith("/api/"):
            target_path = target_path[4:]  # Keep leading slash

        target_url = f"{self.gateway_url}{target_path}"

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        req_headers = {}
        for key, value in self.headers.items():
            if key.lower() not in ("host", "content-length"):
                req_headers[key] = value

        req = urllib.request.Request(
            url=target_url,
            data=body,
            headers=req_headers,
            method=self.command
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in ("transfer-encoding", "content-length"):
                        self.send_header(k, v)
                resp_body = resp.read()
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as exc:
            self.send_response(exc.code)
            for k, v in exc.headers.items():
                if k.lower() not in ("transfer-encoding", "content-length"):
                    self.send_header(k, v)
            err_body = exc.read()
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as exc:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            err_msg = f'{{"error": "Bad Gateway", "detail": "{str(exc)}"}}'.encode("utf-8")
            self.send_header("Content-Length", str(len(err_msg)))
            self.end_headers()
            self.wfile.write(err_msg)


def run_server(port: int = 5173, gateway: str = "http://aegismem-gateway:8000"):
    DashboardProxyHandler.gateway_url = gateway.rstrip("/")
    handler = DashboardProxyHandler

    with socketserver.ThreadingTCPServer(("0.0.0.0", port), handler) as httpd:
        print(f"[AegisMem Dashboard] Serving on http://127.0.0.1:{port} (Gateway proxy: {gateway})")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[AegisMem Dashboard] Stopping server...")
            httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisMem Dashboard Compose Server")
    parser.add_argument("--port", type=int, default=5173, help="Port to listen on")
    parser.add_argument("--gateway", type=str, default="http://aegismem-gateway:8000", help="Gateway URL")
    args = parser.parse_args()

    run_server(port=args.port, gateway=args.gateway)

