from .base import HeuristicCheck


class TimeoutCheck(HeuristicCheck):
    name = "timeout"

    def check_response(self, flow, config: dict):
        threshold = config.get("threshold_ms", 30000)
        if flow.response and flow.request.timestamp_start:
            elapsed = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
            if elapsed > threshold:
                return f"slow {elapsed:.0f}ms > {threshold}ms"
        return None
