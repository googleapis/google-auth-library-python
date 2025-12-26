from google.auth._cache import LRUCache


def test_lru_cache():
    """Test the LRUCache for generally expected functionality and ordering."""
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
    """Confirm the LRUCache handles zero-size correctly."""
    lru_cache = LRUCache(0)
    lru_cache["a"] = 1
    assert "a" not in lru_cache


def test_lru_cache_get_updates_lru():
    """Confirm the LRUCache handles get calls correctly."""
    lru_cache = LRUCache(2)
    lru_cache["a"] = 1
    lru_cache["b"] = 2

    # Access "a" via get(), making it MRU.
    assert lru_cache.get("a") == 1

    # Add "c", which should evict "b" (LRU), not "a".
    lru_cache["c"] = 3

    assert "a" in lru_cache
    assert "b" not in lru_cache
    assert "c" in lru_cache


def test_lru_cache_get_missing():
    """Confirm the LRUCache handles missing keys correctly."""
    lru_cache = LRUCache(2)
    assert lru_cache.get("missing") is None
    assert lru_cache.get("missing", "default") == "default"
