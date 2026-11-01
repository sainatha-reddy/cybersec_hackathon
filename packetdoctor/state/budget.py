from collections import Counter, defaultdict


class StateLimitReached(Exception):
    pass


class StateBudget:
    def __init__(self, limit, max_entries=100_000):
        self.limit = limit
        self.max_entries = max_entries
        self.used = 0

    def reserve(self):
        if self.used >= self.limit:
            raise StateLimitReached("State item budget reached; analysis covers the processed portion only.")
        self.used += 1

    def wrap(self, value):
        if hasattr(value, "get_or_create") and hasattr(value, "maxlen"):
            value.budget = self
            return value
        if isinstance(value, (BudgetDict, BudgetList, BudgetSet, BudgetCounter)):
            return value
        if isinstance(value, Counter):
            return BudgetCounter(self, value)
        if isinstance(value, dict) and not hasattr(value, "get_or_create"):
            return BudgetDict(self, value, value.default_factory if isinstance(value, defaultdict) else None)
        if isinstance(value, list):
            return BudgetList(self, value)
        if isinstance(value, set):
            return BudgetSet(self, value)
        return value

    def bind(self, owner):
        for name, value in vars(owner).items():
            setattr(owner, name, self.wrap(value))


class BudgetDict(dict):
    def __init__(self, budget, initial=(), factory=None):
        self.budget = budget
        self.factory = factory
        super().__init__()
        self.update(initial)

    def __missing__(self, key):
        if self.factory is None:
            raise KeyError(key)
        self[key] = self.factory()
        return self[key]

    def __setitem__(self, key, value):
        if key not in self:
            if len(self) >= self.budget.max_entries:
                raise StateLimitReached("Collection entry limit reached; analysis covers the processed portion only.")
            self.budget.reserve()
        super().__setitem__(key, self.budget.wrap(value))

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def update(self, other=(), **kwargs):
        for key, value in dict(other, **kwargs).items():
            self[key] = value


class BudgetList(list):
    def __init__(self, budget, initial=()):
        self.budget = budget
        super().__init__()
        self.extend(initial)

    def append(self, value):
        if len(self) >= self.budget.max_entries:
            raise StateLimitReached("Collection entry limit reached; analysis covers the processed portion only.")
        self.budget.reserve()
        super().append(self.budget.wrap(value))

    def extend(self, values):
        for value in values:
            self.append(value)

    def __iadd__(self, values):
        self.extend(values)
        return self


class BudgetSet(set):
    def __init__(self, budget, initial=()):
        self.budget = budget
        super().__init__()
        self.update(initial)

    def add(self, value):
        if value not in self:
            if len(self) >= self.budget.max_entries:
                raise StateLimitReached("Collection entry limit reached; analysis covers the processed portion only.")
            self.budget.reserve()
        super().add(value)

    def update(self, *groups):
        for group in groups:
            for value in group:
                self.add(value)

    def __ior__(self, values):
        self.update(values)
        return self


class BudgetCounter(Counter):
    def __init__(self, budget, initial=()):
        self.budget = budget
        super().__init__(initial)

    def __setitem__(self, key, value):
        if key not in self:
            if len(self) >= self.budget.max_entries:
                raise StateLimitReached("Collection entry limit reached; analysis covers the processed portion only.")
            self.budget.reserve()
        super().__setitem__(key, value)
