from __future__ import annotations

from collections import OrderedDict
from typing import Callable, Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class LRUDict(OrderedDict, Generic[K, V]):
    """Dict with a hard size cap; the least recently used entry is evicted.

    Every per-flow / per-host table uses this so a hostile capture with
    millions of fake addresses cannot exhaust memory."""

    def __init__(self, maxlen: int):
        super().__init__()
        self.maxlen = maxlen
        self.evicted = 0

    def get_or_create(self, key: K, factory: Callable[[], V]) -> V:
        try:
            value = self[key]
            self.move_to_end(key)
            return value
        except KeyError:
            value = factory()
            self[key] = value
            if len(self) > self.maxlen:
                self.popitem(last=False)
                self.evicted += 1
            return value

    def put(self, key: K, value: V) -> None:
        self[key] = value
        self.move_to_end(key)
        if len(self) > self.maxlen:
            self.popitem(last=False)
            self.evicted += 1


def add_capped(items: list, value, cap: int) -> None:
    if len(items) < cap:
        items.append(value)
