from .base import HeuristicCheck


class RateLimitCheck(HeuristicCheck):
    name = "rate_limit"

    def check_response(self, flow, config: dict):
        code = flow.response.status_code
        if code in config.get("status_codes", [429]):
            keywords = config.get("body_keywords", [])
            if not keywords or any(
                kw.encode() in (flow.response.content or b"") for kw in keywords
            ):
                return f"HTTP {code}"
        return None
