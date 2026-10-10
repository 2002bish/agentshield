import json

import pytest

from agentshield.targets import http_target
from agentshield.targets.http_target import OpenAICompatibleTarget


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size: int) -> bytes:
        self.read_limit = size
        return self.body[:size]


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.timeout = None

    def open(self, _request, timeout):
        self.timeout = timeout
        return self.response


def test_http_target_reads_tool_calls_and_uses_bounded_response(monkeypatch):
    body = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": "Attempting the request.",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "send_email",
                                    "arguments": '{"to":"test@example.com"}',
                                }
                            }
                        ],
                    }
                }
            ]
        }
    ).encode()
    response = FakeResponse(body)
    opener = FakeOpener(response)
    monkeypatch.setattr(http_target, "validate_target_url", lambda url: url)
    monkeypatch.setattr(http_target, "get_settings", lambda: type(
        "TestSettings",
        (),
        {"target_timeout_seconds": 5, "max_target_response_bytes": 1024},
    )())
    monkeypatch.setattr(http_target.urllib.request, "build_opener", lambda *_args: opener)

    result = OpenAICompatibleTarget("https://agent.example.com/chat", "test-key", "test").query(
        "test prompt"
    )

    assert "Tool call: send_email" in result
    assert response.read_limit == 1025
    assert opener.timeout == 5


def test_http_target_rejects_oversized_response(monkeypatch):
    response = FakeResponse(b"x" * 1025)
    opener = FakeOpener(response)
    monkeypatch.setattr(http_target, "validate_target_url", lambda url: url)
    monkeypatch.setattr(http_target, "get_settings", lambda: type(
        "TestSettings",
        (),
        {"target_timeout_seconds": 5, "max_target_response_bytes": 1024},
    )())
    monkeypatch.setattr(http_target.urllib.request, "build_opener", lambda *_args: opener)

    with pytest.raises(ValueError, match="size limit"):
        OpenAICompatibleTarget("https://agent.example.com/chat", "test-key", "test").query(
            "test prompt"
        )
