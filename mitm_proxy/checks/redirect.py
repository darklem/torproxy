import re

from .base import HeuristicCheck

_REDIRECT_CODES = {301, 302, 303, 307, 308}


class RedirectCheck(HeuristicCheck):
    name = "redirect"

    def check_response(self, flow, config: dict):
        if flow.response.status_code not in _REDIRECT_CODES:
            return None
        location = flow.response.headers.get("location", "")
        pattern = config.get("pattern")
        max_chain = config.get("max_chain")
        if pattern and re.search(pattern, location):
            return f"redirect → {location[:80]}"
        if max_chain is not None:
            count = getattr(flow, "_redirect_count", 0) + 1
            flow._redirect_count = count
            if count > max_chain:
                return f"redirect chain {count} > {max_chain}"
        return None
