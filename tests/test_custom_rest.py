"""Declarative custom-REST adapter (plan LSCAN-018): data-described request/response mapping with no template code
execution and no response-driven fetching; unknown contracts are unsupported."""
import json

import pytest

from hfsentinel.targets.custom_rest import CustomRestTarget, RestContract, select
from hfsentinel.targets.transport import Response

CONTRACT = RestContract(url="https://api.example.com/v1/run", text_path="data.output.0.text",
                        body_template={"q": "{prompt}", "cfg": {"max": "{max_tokens}"}},
                        auth_header="x-api-key", usage_path="data.usage")


class FakeTransport:
    def __init__(self, payload):
        self.body, self.seen = json.dumps(payload).encode(), {}

    def request(self, method, url, *, headers, body=None, timeout=60.0, limit=0):
        self.seen = {"method": method, "url": url, "headers": headers, "body": json.loads(body)}
        return Response(200, {}, self.body)


def test_select_follows_dotted_paths_safely():
    data = {"data": {"output": [{"text": "hello"}], "usage": {"t": 1}}}
    assert select(data, "data.output.0.text") == "hello" and select(data, "data.usage") == {"t": 1}
    assert select(data, "data.missing.0") is None            # missing step -> None, never raises


def test_request_fills_only_allowlisted_placeholders_and_binds_auth():
    ft = FakeTransport({"data": {"output": [{"text": "answer"}], "usage": {"t": 2}}})
    t = CustomRestTarget("custom-x", CONTRACT, api_key="K", transport=ft)
    r = t.chat([{"role": "user", "content": "hi there"}], max_tokens=64)
    assert r.text == "answer" and r.usage == {"t": 2}
    assert ft.seen["body"] == {"q": "hi there", "cfg": {"max": "64"}}   # named substitution only
    assert ft.seen["headers"]["x-api-key"] == "K"                        # per-target credential bound to origin


def test_contract_with_non_allowlisted_placeholder_is_unsupported():
    with pytest.raises(ValueError, match="unsupported custom-REST contract"):
        CustomRestTarget("x", RestContract(url="u", text_path="t", body_template={"q": "{os.environ}"}))
    bad = RestContract(url="", text_path="", body_template={})
    assert bad.supported()[0] is False                                   # missing url/selector -> unsupported


def test_url_in_the_response_is_never_followed():
    # the adapter returns the text verbatim; a URL inside it is data, never fetched
    ft = FakeTransport({"data": {"output": [{"text": "see https://evil.example/exfil?x=1"}]}})
    t = CustomRestTarget("x", RestContract(url="u", text_path="data.output.0.text", body_template={"q": "{prompt}"}),
                         transport=ft)
    assert "https://evil.example" in t.chat([{"role": "user", "content": "x"}]).text  # returned as data, not fetched
