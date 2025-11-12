from google.auth._cache import LRUCache


def test_lru_cache():
    lru_cache = LRUCache(2)
    lru_cache["a"] = 1
    lru_cache["b"] = 2
    assert lru_cache["a"] == 1
    lru_cache["c"] = 3
    assert "b" not in lru_cache
    assert lru_cache["a"] == 1
    assert lru_cache["c"] == 3
    lru_cache["d"] = 4
    assert "a" not in lru_cache
    assert lru_cache["c"] == 3
    assert lru_cache["d"] == 4


def test_zero_size_lru_cache():
    lru_cache = LRUCache(0)
    lru_cache["a"] = 1
    assert "a" not in lru_cache
