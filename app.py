import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from sec_log_labeler_framework import SecLogLabelerFramework


ROOT_DIR = Path(__file__).resolve().parent
INDEX_PATH = ROOT_DIR / "templates" / "index.html"
STYLESHEET_PATH = ROOT_DIR / "static" / "style.css"
FRAMEWORK = SecLogLabelerFramework()


class SecLogHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status_code: int, html: str):
        body = html.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/static/style.css":
            if not STYLESHEET_PATH.exists():
                self.send_error(500, "Missing static/style.css")
                return
            body = STYLESHEET_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/":
            self.send_error(404, "Not Found")
            return

        if not INDEX_PATH.exists():
            self.send_error(500, "Missing templates/index.html")
            return

        self._send_html(200, INDEX_PATH.read_text(encoding="utf-8"))

    def do_POST(self):
        if self.path != "/annotate":
            self.send_error(404, "Not Found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        log_text = payload.get("log", "")
        result = FRAMEWORK.annotate_log(log_text)

        labels = [
            {
                "label": "BINARY_SECURITY_LABEL",
                "value": result["binary_label"],
                "reason": result["binary_reasoning"] if result["binary_label"] == 1 else None,
            }
        ]
        if result["binary_label"] == 1 and result["multilabels"]:
            for key, val in result["multilabels"].items():
                labels.append(
                    {
                        "label": key,
                        "value": val,
                        "reason": result["multilabel_reasoning"] if val == 1 else None,
                    }
                )

        self._send_json(
            200,
            {
                "labels": labels,
                "binary_label": result["binary_label"],
                "multilabels": result["multilabels"],
                "binary_reasoning": result["binary_reasoning"],
                "multilabel_reasoning": result["multilabel_reasoning"],
                "mode": result["mode"],
                "error": result["error"],
            },
        )


def run_server(host: str = "127.0.0.1", port: int = 5000):
    server = HTTPServer((host, port), SecLogHandler)
    print(f"SecLogLabeler running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
