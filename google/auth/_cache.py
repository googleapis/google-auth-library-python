from collections import OrderedDict


class LRUCache(dict):
    def __init__(self, maxsize):
        super().__init__()
        self._order = OrderedDict()
        self.maxsize = maxsize

    def clear(self):
        super().clear()
        self._order.clear()

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self._update(key)
        return value

    def __setitem__(self, key, value):
        maxsize = self.maxsize
        if maxsize <= 0:
            return
        if key not in self:
            while len(self) >= maxsize:
                self.popitem()
        super().__setitem__(key, value)
        self._update(key)

    def __delitem__(self, key):
        super().__delitem__(key)
        del self._order[key]

    def popitem(self):
        """Remove and return the least recently used key-value pair."""
        key, _ = self._order.popitem(last=False)
        return key, super().pop(key)

    def _update(self, key):
        try:
            self._order.move_to_end(key)
        except KeyError:
            self._order[key] = None
