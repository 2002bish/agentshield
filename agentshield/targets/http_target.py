import json
import urllib.request

from agentshield.config import get_settings
from agentshield.service.security import validate_target_url


class OpenAICompatibleTarget:
    """Sends each test prompt to an OpenAI-compatible chat-completions endpoint."""

    def __init__(self, endpoint_url: str, api_key: str, model: str):
        self.endpoint_url = validate_target_url(endpoint_url)
        self.api_key = api_key
        self.model = model

    def query(self, payload: str) -> str:
        validate_target_url(self.endpoint_url)
        settings = get_settings()
        headers = {"Authorization": f"Bearer {self.api_key}"}
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": payload}],
        }
        request = urllib.request.Request(
            self.endpoint_url,
            data=json.dumps(body).encode("utf-8"),
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, new_url):
                return None

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirectHandler()
        )
        with opener.open(request, timeout=settings.target_timeout_seconds) as response:
            response_body = response.read(settings.max_target_response_bytes + 1)
        if len(response_body) > settings.max_target_response_bytes:
            raise ValueError("Target response exceeded the configured size limit.")
        try:
            data = json.loads(response_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Target did not return valid JSON.") from exc
        try:
            choice = data["choices"][0]
            message = choice["message"]
            content = message.get("content")
            tool_calls = message.get("tool_calls", [])
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Target did not return an OpenAI-compatible chat response.") from exc

        output = content if isinstance(content, str) else ""
        if tool_calls:
            output += "\n" + "\n".join(
                f"Tool call: {call.get('function', {}).get('name', 'unknown')} "
                f"{call.get('function', {}).get('arguments', '')}"
                for call in tool_calls
                if isinstance(call, dict)
            )
        return output
