from dataclasses import field
from typing import Any, Generic, Optional, TypeVar

from marshmallow_dataclass import dataclass

import tbcml


F = TypeVar("F")
T = TypeVar("T")


@dataclass
class CSVField(Generic[F]):
    value: Optional[Any] = None  # marshmallow_dataclass can't do generics in fields atm

    def __post_init__(self):
        self.original_index: Optional[int] = None

    def read_from_csv(self, csv: "tbcml.CSV", default: Any = None) -> None:
        raise NotImplementedError

    def initialize_csv(self, csv: "tbcml.CSV", writing: bool) -> bool:
        if self.value is None and not self.always_write and writing:
            self.original_index = None
            return False
        self.original_index = csv.index
        if self.row_index is not None:
            csv.index = self.row_index
        csv.index += self.row_offset
        return True

    def uninitialize_csv(self, csv: "tbcml.CSV"):
        if self.original_index is None:
            return
        csv.index = self.original_index

    def write_to_csv(self, csv: "tbcml.CSV"):
        if not self.initialize_csv(csv, writing=True):
            return
        csv.set_str(self.value, self.col_index)
        self.uninitialize_csv(csv)

    def set(self, value: F):
        self.value = value

    def set_ignore_none(self, value: Optional[F]):
        if value is None:
            return
        self.value = value

    @property
    def value_(self) -> F:
        return self.get()

    @value_.setter
    def value_(self, value: F):
        self.set(value)

    def get(self) -> F:
        raise NotImplementedError

    def set_col_index(self, col_index: int):
        self.col_index = col_index

    def set_always_write(self, always_write: bool):
        self.always_write = always_write

    def set_row_index(self, row_index: Optional[int] = None):
        self.row_index = row_index

    def set_row_offset(self, row_offset: int = 0):
        self.row_offset = row_offset

    @staticmethod
    def to_field(type: type[T], *args: Any, **kwargs: Any) -> T:
        f = field(default_factory=lambda: type(None, *args, **kwargs))
        return f


@dataclass
class IntCSVField(CSVField[int]):
    value: Optional[int] = None
    col_index: int = 0
    always_write: bool = False
    row_index: Optional[int] = None
    row_offset: int = 0

    def read_from_csv(self, csv: "tbcml.CSV", default: int = 0):
        if not self.initialize_csv(csv, writing=False):
            return
        self.value = csv.get_int(self.col_index, default=default)
        self.uninitialize_csv(csv)

    def get(self) -> int:
        return self.value or 0


@dataclass
class BoolCSVField(CSVField[bool]):
    value: Optional[bool] = None
    col_index: int = 0
    always_write: bool = False
    row_index: Optional[int] = None
    row_offset: int = 0

    def read_from_csv(self, csv: "tbcml.CSV", default: bool = False):
        if not self.initialize_csv(csv, writing=False):
            return
        self.value = csv.get_bool(self.col_index, default=default)
        self.uninitialize_csv(csv)

    def get(self) -> bool:
        return self.value or False


@dataclass
class StringCSVField(CSVField[str]):
    value: Optional[str] = None
    col_index: int = 0
    always_write: bool = False
    row_index: Optional[int] = None
    row_offset: int = 0

    def read_from_csv(self, csv: "tbcml.CSV", default: str = ""):
        if not self.initialize_csv(csv, writing=False):
            return
        self.value = csv.get_str(self.col_index, default=default)
        self.uninitialize_csv(csv)

    def get(self) -> str:
        return self.value or ""


@dataclass
class StrListCSVField(CSVField[list[str]]):
    value: Optional[list[str]] = None
    col_index: int = 0
    always_write: bool = False
    length: Optional[int] = None
    row_index: Optional[int] = None
    row_offset: int = 0
    blank: str = ""

    def read_from_csv(self, csv: "tbcml.CSV", default: str = ""):
        if not self.initialize_csv(csv, writing=False):
            return
        self.value = csv.get_str_list(self.col_index, self.length, default=default)
        self.uninitialize_csv(csv)

    def write_to_csv(self, csv: "tbcml.CSV"):
        if not self.initialize_csv(csv, writing=True):
            return

        if self.length is None:
            length = len(csv.get_current_line() or [])
        else:
            length = self.length
        if self.value is None:
            self.value = [self.blank] * length
        remaining = length - len(self.value)
        if remaining > 0:
            self.value.extend([self.blank] * remaining)
        elif remaining < 0:
            self.value = self.value[:length]
        csv.set_list(self.value, self.col_index)

        self.uninitialize_csv(csv)

    def get(self) -> list[str]:
        if self.value is None:
            return [self.blank] * (self.length or 0)
        if self.length is None:
            return self.value
        required_length = self.length - len(self.value)
        if required_length < 0:
            return self.value[: self.length]

        value = self.value.copy()
        value.extend([self.blank] * required_length)
        return value

    def set_element(self, value: str, index: int):
        ls = self.get()
        ls[index] = value
        self.value = ls


@dataclass
class IntListCSVField(CSVField[list[int]]):
    value: Optional[list[int]] = None
    col_index: int = 0
    always_write: bool = False
    length: Optional[int] = None
    row_index: Optional[int] = None
    row_offset: int = 0
    blank: int = 0

    def read_from_csv(self, csv: "tbcml.CSV", default: int = 0):
        if not self.initialize_csv(csv, writing=False):
            return
        self.value = csv.get_int_list(self.col_index, self.length, default=default)
        self.uninitialize_csv(csv)

    def write_to_csv(self, csv: "tbcml.CSV"):
        if not self.initialize_csv(csv, writing=True):
            return

        if self.length is None:
            length = len(csv.get_current_line() or [])
        else:
            length = self.length
        if self.value is None:
            self.value = [self.blank] * length

        remaining = length - len(self.value)
        if remaining > 0:
            self.value.extend([self.blank] * remaining)
        elif remaining < 0:
            self.value = self.value[:length]
        csv.set_list(self.value, self.col_index)

        self.uninitialize_csv(csv)

    def get(self) -> list[int]:
        if self.value is None:
            return [self.blank] * (self.length or 0)
        if self.length is None:
            return self.value
        required_length = self.length - len(self.value)
        if required_length < 0:
            return self.value[: self.length]

        value = self.value.copy()
        value.extend([self.blank] * required_length)
        return value

    def set_element(self, value: int, index: int):
        ls = self.get()
        ls[index] = value
        self.value = ls
