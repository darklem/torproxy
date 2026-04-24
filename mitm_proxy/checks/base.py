class HeuristicCheck:
    name: str = "base"

    def check_response(self, flow, config: dict):
        """Return a reason string if the check fires, None otherwise."""
        return None

    def check_error(self, flow, config: dict):
        return None
