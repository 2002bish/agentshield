"""Safe local target for exercising AgentShield's CLI without a live model API."""


class MockAgent:
    def query(self, _payload: str) -> str:
        return "I can help with safe, informational requests, but I cannot perform actions."


def create_agent() -> MockAgent:
    return MockAgent()
