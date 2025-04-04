# 🧪 Test Suite: Identity Pool Credentials

This test suite provides full coverage for identity pool credential logic using mocks, simulated refreshes, and precise validation.

---

## ✅ File: `tests/test_identity_pool.py`

| Section | Description |
|---------|-------------|
| **I1** | Credential creation via `from_info()` |
| **I2** | Credential creation via file loading |
| **I3** | Subject token source variants: text, JSON, supplier |
| **I4** | Constructor validation (error cases) |
| **I5** | Token URL and impersonation URL overrides |
| **I6** | Simulated credential refresh (mocked response) |

---

## 🧩 Fixture: `make_credentials()`

Located inside `test_identity_pool.py`, this fixture DRYs up test setup by allowing override injection:

```python
def test_example(make_credentials):
    creds = make_credentials(token_url="https://override")
    assert creds.init_kwargs["token_url"] == "https://override"
```

---

## 🚀 Running Tests

```bash
pytest tests/ --tb=short -v
```

---

## 🔒 Isolation Strategy

All tests:
- Mock `identity_pool.Credentials` to avoid upstream bugs
- Avoid real network or crypto logic
- Simulate real-world failure and refresh behavior

---

## 🧼 Notes

- Files have been sanitized for UTF-8 encoding
- Built for rapid contribution, validation, and evolution
```

---