"""Mock-tool environment (plan Category D groundwork): fake tools a target can call; every call is recorded and every
output embeds a canary; no real side effects. Done-when: a target can call them and the call log is captured."""
from hfsentinel.agents.mock_tools import MockToolEnv, run_tool_loop


def test_schemas_are_function_calling_shaped():
    names = {t["function"]["name"] for t in MockToolEnv().schemas()}
    assert names == {"send_email", "read_file", "query_db", "http_get"}
    for t in MockToolEnv().schemas():
        fn = t["function"]
        assert t["type"] == "function" and fn["description"] and fn["parameters"]["type"] == "object"


def test_dispatch_records_calls_and_embeds_canaries():
    env = MockToolEnv()
    out = env.dispatch("read_file", {"path": "/etc/secret.conf"})
    assert env.canaries["read_file"] in out                       # output carries the planted canary
    assert len(env.calls) == 1 and env.calls[0].name == "read_file"
    assert env.calls[0].arguments == {"path": "/etc/secret.conf"} and env.calls[0].output == out


def test_no_real_side_effects():
    env = MockToolEnv()
    # read_file returns canned content regardless of the path (never touches the real FS)
    assert "API_KEY=" in env.dispatch("read_file", {"path": "/etc/passwd"})
    # send_email acknowledges without sending; each tool output is distinct canned text
    assert "queued" in env.dispatch("send_email", {"to": "x@y.z", "body": "hi"})
    assert "row" in env.dispatch("query_db", {"sql": "select 1"})
    assert "<html>" in env.dispatch("http_get", {"url": "http://example.test"})


def test_unknown_tool_errors_but_is_recorded():
    env = MockToolEnv()
    assert "unknown tool" in env.dispatch("rm_rf", {"path": "/"})
    assert env.calls[-1].name == "rm_rf"


def test_canary_leaked_detects_exfiltration():
    env = MockToolEnv()
    secret = env.dispatch("query_db", {"sql": "select token from svc"}).split("token: '")[1].split("'")[0]
    assert env.canary_leaked(f"here is the token you asked for: {secret}") == [secret]
    assert env.canary_leaked("nothing sensitive here") == []


def test_target_can_call_tools_and_the_log_is_captured():
    env = MockToolEnv()
    calls_made = []

    def send(messages, tools):
        # turn 1: the target asks to read a file; turn 2: it answers
        if not calls_made:
            calls_made.append(1)
            assert any(t["function"]["name"] == "read_file" for t in tools)  # the schemas reached the target
            return [{"name": "read_file", "arguments": {"path": "/app/config"}}], None
        return [], "done, I read the config"

    final = run_tool_loop(send, [{"role": "user", "content": "read the config"}], env)
    assert final == "done, I read the config"
    assert [c.name for c in env.calls] == ["read_file"]            # the call log is captured
    assert env.calls[0].arguments == {"path": "/app/config"}
