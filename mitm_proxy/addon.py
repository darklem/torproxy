"""
TorProxy-Chain mitmproxy addon.

Loads heuristic rules from /heuristics.yml and dispatches them per hostname.
When a check fires, it optionally calls the TorProxy /rotate endpoint.
All events are also pushed to /mitm/event for the admin dashboard.
"""

import json
import time
import logging
import urllib.request
import urllib.error

import yaml

from checks.rate_limit import RateLimitCheck
from checks.redirect import RedirectCheck
from checks.timeout import TimeoutCheck

log = logging.getLogger(__name__)

CHECKS = {c.name: c for c in [RateLimitCheck(), RedirectCheck(), TimeoutCheck()]}


class TorProxyAddon:
    def load(self, loader):
        with open("/heuristics.yml") as f:
            self.cfg = yaml.safe_load(f)
        self.api = self.cfg["global"]["torproxy_api"]
        self.default_action = self.cfg["global"].get("default_action", "log")
        log.info(f"TorProxyAddon loaded — API: {self.api}")

    def response(self, flow):
        self._dispatch(flow, "check_response")

    def error(self, flow):
        self._dispatch(flow, "check_error")

    def _dispatch(self, flow, method: str):
        host = flow.request.pretty_host
        site_rules = self.cfg.get("sites", {})
        rules = site_rules.get(host, []) + site_rules.get("*", [])
        for rule in rules:
            check = CHECKS.get(rule.get("check"))
            if not check:
                continue
            reason = getattr(check, method)(flow, rule)
            if reason:
                action = rule.get("action", self.default_action)
                self._trigger(host, reason, action, flow.request.url)

    def _trigger(self, host: str, reason: str, action: str, url: str):
        event = {
            "ts": time.time(),
            "host": host,
            "reason": reason,
            "action": action,
            "url": url[:120],
        }
        if action == "rotate":
            try:
                req = urllib.request.Request(f"{self.api}/rotate", data=b"", method="POST")
                urllib.request.urlopen(req, timeout=5)
                log.info(f"Rotated exit proxy (triggered by {host}: {reason})")
            except Exception as e:
                log.warning(f"Could not reach TorProxy API to rotate: {e}")
        try:
            body = json.dumps(event).encode()
            req = urllib.request.Request(
                f"{self.api}/mitm/event",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass


class CertServer:
    """Tiny HTTP server that serves the mitmproxy CA cert on port 8081."""

    def running(self):
        import threading
        import http.server
        import pathlib

        cert_file = pathlib.Path("/root/.mitmproxy/mitmproxy-ca-cert.pem")

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/", "/ca"):
                    if cert_file.exists():
                        body = cert_file.read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-x509-ca-cert")
                        self.send_header("Content-Disposition", 'attachment; filename="mitmproxy-ca.pem"')
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    else:
                        self.send_response(503)
                        self.end_headers()
                        self.wfile.write(b"Cert not ready yet — wait a few seconds and retry")
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        def _serve():
            http.server.HTTPServer(("0.0.0.0", 8081), _Handler).serve_forever()

        threading.Thread(target=_serve, daemon=True).start()
        log.info("CA cert server listening on :8081/ca")


addons = [TorProxyAddon(), CertServer()]
