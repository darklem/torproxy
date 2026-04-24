"""
TorProxy-Chain mitmproxy addon.

Loads heuristic rules from /heuristics.yml and dispatches them per hostname.
When a check fires, it optionally calls the TorProxy /rotate endpoint.
All events are also pushed to /mitm/event for the admin dashboard.
"""

import time
import logging

import requests
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
                requests.post(f"{self.api}/rotate", timeout=5)
                log.info(f"Rotated exit proxy (triggered by {host}: {reason})")
            except Exception as e:
                log.warning(f"Could not reach TorProxy API to rotate: {e}")
        try:
            requests.post(f"{self.api}/mitm/event", json=event, timeout=2)
        except Exception:
            pass


addons = [TorProxyAddon()]
