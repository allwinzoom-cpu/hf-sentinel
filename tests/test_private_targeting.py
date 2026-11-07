"""Private-network targeting policy (LSCAN-008): CLI reaches an explicitly-scoped private target; hosted mode never
reaches a private network; secrets aren't forwarded to a new origin."""
from hfsentinel.targets.private_targeting import forward_secret_allowed, is_private_host, private_target_allowed


def test_private_host_detection():
    for h in ("127.0.0.1", "10.0.0.5", "192.168.1.9", "172.16.0.1", "::1", "my-service", "db.local", "api.internal"):
        assert is_private_host(h), h
    for h in ("router.huggingface.co", "api.example.com", "8.8.8.8"):
        assert not is_private_host(h), h


def test_hosted_mode_never_reaches_private():
    assert not private_target_allowed("http://10.0.0.5:8000/v1", hosted_mode=True, in_scope=True)   # even if "scoped"
    assert not private_target_allowed("http://vllm-svc:8000/v1", hosted_mode=True, in_scope=True)


def test_cli_reaches_an_explicitly_scoped_private_target():
    assert private_target_allowed("http://10.0.0.5:8000/v1", hosted_mode=False, in_scope=True)
    assert not private_target_allowed("http://10.0.0.5:8000/v1", hosted_mode=False, in_scope=False)  # not scoped -> no


def test_public_targets_are_always_allowed():
    assert private_target_allowed("https://router.huggingface.co/v1", hosted_mode=True, in_scope=False)


def test_secret_not_forwarded_to_a_new_origin():
    assert forward_secret_allowed("https://host:443/v1", "https://host:443/v1/chat")
    assert not forward_secret_allowed("https://host/v1", "https://evil.example/v1")  # different origin
    assert not forward_secret_allowed("https://host/v1", "http://host/v1")  # scheme change
