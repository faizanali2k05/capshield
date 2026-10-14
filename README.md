# capshield

Redact sensitive mapping keys and exact paths before data reaches logs, errors, or telemetry.

```bash
python -m pip install capshield
```

```python
from capshield import RedactionPolicy

policy = RedactionPolicy(
    keys=frozenset({"password", "authorization"}),
    paths=frozenset({("customer", "email")}),
)

safe = policy.apply({
    "password": "never-log-me",
    "customer": {"email": "private@example.com", "name": "Ada"},
})
```

Redaction is recursive, returns a copy, handles mappings and sequences, limits depth, detects cycles, and summarizes byte strings. Common credential and HTTP-secret keys are included by default; pass your own `keys` iterable to replace that set. Exact paths use tuples such as `("request", "headers", "authorization")`; key matching is case-insensitive.

Capshield is a data-safety primitive, not a guarantee that an application contains no secrets. Review custom objects, formatted strings, and logs that bypass the policy.
