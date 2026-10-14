from capshield import RedactionPolicy, redact


def test_redacts_keys_and_exact_paths_without_mutating_input() -> None:
    value = {
        "Authorization": "secret",
        "customer": {"email": "private@example.com", "name": "Ada"},
        "items": [{"token": "nested-secret"}],
    }
    safe = redact(value, paths={("customer", "email")})
    assert safe["Authorization"] == "[REDACTED]"
    assert safe["customer"]["email"] == "[REDACTED]"
    assert safe["items"][0]["token"] == "[REDACTED]"
    assert value["items"][0]["token"] == "nested-secret"


def test_policy_is_reusable_and_handles_bytes() -> None:
    policy = RedactionPolicy(keys=frozenset({"authorization"}), max_depth=2)
    value = {"Authorization": "x", "body": b"1234"}
    assert policy.apply(value) == {"Authorization": "[REDACTED]", "body": "<bytes:4>"}


def test_depth_limit_is_explicit() -> None:
    assert redact({"a": {"b": {"c": 1}}}, max_depth=1) == {"a": {"b": "[DEPTH_LIMIT]"}}


def test_cycles_are_replaced_without_recursion_errors() -> None:
    value: dict[str, object] = {}
    value["self"] = value
    assert redact(value) == {"self": "[CYCLE]"}
