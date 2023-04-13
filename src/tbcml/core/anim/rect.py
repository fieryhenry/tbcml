from typing import Any, Optional
from tbcml.core import io


class Rect:
    def __init__(self, x: int, y: int, width: int, height: int, name: str = ""):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.name = name

    @staticmethod
    def from_list(l: list["io.data.Data"]) -> Optional["Rect"]:
        if len(l) < 4:
            return None
        if len(l) > 4:
            name = l[4].to_str()
        else:
            name = ""
        return Rect(l[0].to_int(), l[1].to_int(), l[2].to_int(), l[3].to_int(), name)

    def to_list(self) -> list["io.data.Data"]:
        return [
            io.data.Data(self.x),
            io.data.Data(self.y),
            io.data.Data(self.width),
            io.data.Data(self.height),
            io.data.Data(self.name),
        ]

    def __str__(self):
        return f"Rect({self.x}, {self.y}, {self.width}, {self.height}, {self.name})"

    def __repr__(self):
        return f"Rect({self.x}, {self.y}, {self.width}, {self.height}, {self.name})"

    def serialize(self) -> dict[str, Any]:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "name": self.name,
        }

    @staticmethod
    def deserialize(d: dict[str, Any]) -> "Rect":
        return Rect(d["x"], d["y"], d["width"], d["height"], d["name"])

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Rect):
            return False
        return (
            self.x == other.x
            and self.y == other.y
            and self.width == other.width
            and self.height == other.height
            and self.name == other.name
        )

    def copy(self) -> "Rect":
        return Rect(self.x, self.y, self.width, self.height, self.name)

    @staticmethod
    def create_empty() -> "Rect":
        return Rect(0, 0, 0, 0)
