from dataclasses import field
from typing import Any, Generic, Optional, TypeVar

from marshmallow_dataclass import dataclass

from tbcml import core


F = TypeVar("F")


@dataclass
class CSVField(Generic[F]):
    value: Optional[Any] = None  # marshmallow_dataclass can't do generics atm

    def __post_init__(self):
        self.col_index: int = 0
        self.always_write: bool = False

    def get(self, csv: "core.CSV") -> F:
        ...

    def set(self, csv: "core.CSV"):
        if self.value is None and not self.always_write:
            return
        csv.set_str(self.value, self.col_index)

    def set_value(self, value: F):
        self.value = value

    def set_col_index(self, col_index: int):
        self.col_index = col_index

    def set_always_write(self, always_write: bool):
        self.always_write = always_write

    @staticmethod
    def to_field(type: Any, *args: Any, **kwargs: Any):
        return field(default_factory=lambda: type(*args, **kwargs))


class IntCSVField(CSVField[int]):
    value: Optional[int] = None

    def __init__(self, col_index: int, always_write: bool = False):
        super().__init__()
        self.set_col_index(col_index)
        self.set_always_write(always_write)

    def get(self, csv: "core.CSV") -> int:
        return csv.get_int(self.col_index)


class BoolCSVField(CSVField[bool]):
    value: Optional[bool] = None

    def __init__(self, col_index: int, always_write: bool = False):
        super().__init__()
        self.set_col_index(col_index)
        self.set_always_write(always_write)

    def get(self, csv: "core.CSV") -> bool:
        return csv.get_bool(self.col_index)


class StringCSVField(CSVField[str]):
    value: Optional[str] = None

    def __init__(self, col_index: int, always_write: bool = False):
        super().__init__()
        self.set_col_index(col_index)
        self.set_always_write(always_write)

    def get(self, csv: "core.CSV") -> str:
        return csv.get_str(self.col_index)


class StrListCSVField(CSVField[list[str]]):
    value: Optional[list[str]] = None

    def __init__(
        self,
        col_index: int,
        always_write: bool = False,
        length: Optional[int] = None,
    ):
        super().__init__()
        self.set_col_index(col_index)
        self.set_always_write(always_write)
        self.length = length

    def get(self, csv: "core.CSV") -> list[str]:
        return csv.get_str_list(self.col_index, self.length)

    def set(self, csv: "core.CSV"):
        if self.value is None and not self.always_write:
            return
        if self.length is None:
            length = len(csv.get_current_line() or [])
        else:
            length = self.length
        if self.value is None:
            self.value = [""] * length
        csv.set_list(self.value, self.col_index)
