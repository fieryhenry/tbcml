from typing import Any, Optional


class Rect:
    def __init__(self, x: int, y: int, width: int, height: int, name: str = ""):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.name = name

    @staticmethod
    def from_list(l: list[str]) -> Optional["Rect"]:
        if len(l) < 4:
            return None
        if len(l) > 4:
            name = l[4]
        else:
            name = ""
        return Rect(
            int(l[0]),
            int(l[1]),
            int(l[2]),
            int(l[3]),
            name,
        )

    def to_list(self) -> list[str]:
        return [
            str(self.x),
            str(self.y),
            str(self.width),
            str(self.height),
            str(self.name),
        ]

    def copy(self) -> "Rect":
        return Rect(self.x, self.y, self.width, self.height, self.name)

    @staticmethod
    def create_empty() -> "Rect":
        return Rect(0, 0, 0, 0)

    def apply_dict(self, dict_data: dict[str, Any]):
        x = dict_data.get("x")
        if x is not None:
            self.x = x
        y = dict_data.get("y")
        if y is not None:
            self.y = y
        width = dict_data.get("width")
        if width is not None:
            self.width = width
        height = dict_data.get("height")
        if height is not None:
            self.height = height
        name = dict_data.get("name")
        if name is not None:
            self.name = name

    def to_dict(self) -> dict[str, Any]:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "name": self.name,
        }

    @staticmethod
    def from_dict(dict_data: dict[str, Any]) -> "Rect":
        return Rect(
            dict_data.get("x", 0),
            dict_data.get("y", 0),
            dict_data.get("width", 0),
            dict_data.get("height", 0),
            dict_data.get("name", ""),
        )
