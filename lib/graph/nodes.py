from __future__ import annotations

from lib.graph.base import Node


class Generic(Node):
    """Generic node."""

    def __init__(self, properties={}, labels=[]):
        label = self.__class__.__name__

        super().__init__(
            properties,
            labels + [label] if label not in labels else labels,
            "Arn",
        )


class Resource(Node):
    """Resource node."""

    def __init__(self, properties={}, labels=[], key="Arn"):
        label = self.__class__.__name__

        super().__init__(
            properties,
            labels + [label] if label not in labels else labels,
            key,
        )

    def account(self):
        """Return the account associated to the resource node."""
        if (
            "Arn" not in self.properties()
            or len(self.properties()["Arn"].split(":")) < 5
        ):
            return None

        return str(self.properties()["Arn"].split(":")[4])


class External(Node):
    """External node."""

    def __init__(self, properties={}, labels=[], key="Name"):
        label = self.__class__.__name__

        super().__init__(
            properties,
            labels + [label] if label not in labels else labels,
            key,
        )
