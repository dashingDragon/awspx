from __future__ import annotations

from lib.graph.base import Edge


class Associative(Edge):
    """Associative edge."""

    def __init__(self, properties={}, source=None, target=None):
        super().__init__(properties, source, target)


class Transitive(Edge):
    """Transitive edge."""

    def __init__(self, properties={}, source=None, target=None):
        super().__init__(properties, source, target)


class Action(Edge):
    """Action edge."""

    def __init__(self, properties={}, source=None, target=None):
        for key in [
            "Name",
            "Description",
            "Effect",
            "Access",
            "Reference",
            "Condition",
        ]:
            if key not in properties:
                raise ValueError("Edge properties must include '%s'" % key)

        super().__init__(properties, source, target)


class Trusts(Action):
    """Trusts edge."""

    def __init__(self, properties={}, source=None, target=None):
        super().__init__(properties, source, target)
