# app.py
import http.server
import json
import os
import time
import urllib.request
import ssl

MOOGSOFT_URL = os.environ["MOOGSOFT_URL"]
MOOGSOFT_API_KEY = os.environ["MOOGSOFT_API_KEY"]
PROXY_URL = os.environ.get("PROXY_URL")  # e.g. http://10.80.198.88:8080

SEVERITY_MAP = {"critical": 1, "warning": 3, "info": 5}  # confirm real scale with Moogsoft

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        for alert in payload.get("alerts", []):
            self.forward_to_moogsoft(alert)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"relayed"}')

    def forward_to_moogsoft(self, alert):
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        event = {
            "id": alert.get("fingerprint", str(int(time.time()))),
            "eventtime": str(int(time.time())),
            "healthRulename": labels.get("alertname", "unknown"),
            "class": labels.get("namespace", "unknown"),
            "description": annotations.get("description", ""),
            "country": "SG",
            "manager": "Yugabyte",
            "severity": SEVERITY_MAP.get(labels.get("severity"), 5),
            "hostname": labels.get("instance", "NA"),
            "applicationName": labels.get("namespace", "unknown"),
            "IP": "",
            "resource": "",
            "summaryMessage": annotations.get("summary", "")
        }

        data = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(
            MOOGSOFT_URL,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "apiKey": MOOGSOFT_API_KEY
            }
        )

        # proxy handling for urllib
        if PROXY_URL:
            req.set_proxy(PROXY_URL.replace("http://", ""), "https")

        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                print(f"Moogsoft response: {resp.status} {resp.read()}")
        except Exception as e:
            print(f"Failed to forward alert to Moogsoft: {e}")

    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args))

if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", 8080), Handler)
    print("Adapter listening on :8080")
    server.serve_forever()