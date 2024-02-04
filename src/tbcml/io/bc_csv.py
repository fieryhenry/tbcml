import enum
from typing import Any, Optional, Union

import tbcml


def to_str(item: Optional[Union[str, int, bool]], is_int: bool = True) -> str:
    if isinstance(item, (int, str)):
        return str(item)
    if item is None:
        if is_int:
            return "0"
        return ""
    return str(int(item))


class DelimeterType(enum.Enum):
    COMMA = ","
    TAB = "\t"
    PIPE = "|"


class Delimeter:
    def __init__(self, de: Union[DelimeterType, str]):
        if isinstance(de, str):
            self.delimeter = DelimeterType(de)
        else:
            self.delimeter = de

    @staticmethod
    def from_country_code_res(cc: "tbcml.CountryCode") -> "Delimeter":
        if cc == tbcml.CountryCode.JP:
            return Delimeter(DelimeterType.COMMA)
        else:
            return Delimeter(DelimeterType.PIPE)

    def __str__(self) -> str:
        return self.delimeter.value


class CSV:
    def __init__(
        self,
        file_data: Optional["tbcml.Data"] = None,
        delimeter: Union[Delimeter, str] = Delimeter(DelimeterType.COMMA),
        remove_padding: bool = True,
        remove_comments: bool = True,
        remove_empty: bool = True,
        lines: Optional[list[list[str]]] = None,
    ):
        if file_data is None:
            file_data = tbcml.Data()
        file_data = file_data
        if remove_padding:
            try:
                file_data = file_data.unpad_pkcs7()
            except ValueError:
                pass
        self.remove_padding = remove_padding
        self.delimeter = str(delimeter)
        self.remove_comments = remove_comments
        self.remove_empty = remove_empty
        self.index = 0
        self.line_length = 0
        self.is_int = True
        self.ignore_none = True
        if lines is not None:
            self.lines = lines
        else:
            self.parse(file_data)

    def parse(self, file_data: "tbcml.Data"):
        lines: list[list[str]] = []
        for line in file_data.to_str().splitlines():
            if self.remove_comments:
                line = line.split("//")[0]
            line = line.strip()
            line = line.split(self.delimeter)
            if self.remove_empty:
                line = [x for x in line if x]
                if not line:
                    continue
            lines.append(line)
        self.lines = lines

    @staticmethod
    def from_file(
        path: "tbcml.Path", delimeter: Delimeter = Delimeter(DelimeterType.COMMA)
    ) -> "CSV":
        return CSV(path.read(), delimeter)

    def reset_index(self):
        self.index = 0

    def __iter__(self):
        self.reset_index()
        return self

    def __next__(self) -> list[str]:
        line = self.read_line()
        if line is None:
            raise StopIteration
        return line

    def read_line(self) -> Optional[list[str]]:
        if self.index >= len(self.lines):
            return None
        line = self.lines[self.index]
        self.index += 1
        return line

    def get_current_line(self) -> Optional[list[str]]:
        if self.index >= len(self.lines):
            return None
        line = self.lines[self.index]
        return line

    def to_data(self) -> "tbcml.Data":
        return tbcml.Data(
            "\n".join(
                [
                    self.delimeter.join(line)
                    for line in self.lines
                    if line or self.remove_empty
                ]
            )
        )

    def extend(
        self,
        length: int,
        sub_length: int = 0,
        item: str = "",
    ):
        for _ in range(length):
            if sub_length == 0:
                self.lines.append([])
            else:
                self.lines.append([item] * sub_length)

    def extend_to(self, length: int, sub_length: int = 0, item: str = ""):
        if length > len(self.lines):
            self.extend(length - len(self.lines) + 1, sub_length, item)

    def set_line(self, line: list[str], index: int):
        if index >= len(self.lines):
            self.extend(index - len(self.lines) + 1)
        self.lines[index] = line

    def get_line(self, index: int):
        if index >= len(self.lines):
            self.extend(index - len(self.lines) + 1)
        return self.lines[index]

    def set_str(
        self,
        item: Optional[Union[str, int, bool]],
        index: int,
        length: Optional[int] = None,
    ):
        if item is None and self.ignore_none:
            return
        if self.index >= len(self.lines):
            self.extend_to(
                self.index + 1,
            )
        line = self.lines[self.index]

        if index < len(line):
            line[index] = to_str(item, self.is_int)
        else:
            if length is None:
                length = index + 1
            if isinstance(item, int):
                line.extend(["0"] * (length - len(line)))
            else:
                line.extend([""] * (length - len(line)))
            line[index] = to_str(item, self.is_int)

    def get_str(self, index: int, default: str = "") -> str:
        try:
            return self.lines[self.index][index]
        except (ValueError, IndexError):
            return default

    def get_int(self, index: int, default: int = 0) -> int:
        try:
            return int(self.lines[self.index][index])
        except (ValueError, IndexError):
            return default

    def get_bool(self, index: int, default: bool = False):
        return bool(self.get_int(index, int(default)))

    def get_str_list(
        self,
        index: int,
        length: Optional[int] = None,
        default: str = "",
    ) -> list[str]:
        if self.index >= len(self.lines):
            return []
        line = self.lines[self.index]
        if index >= len(line):
            return []
        if length is None:
            item = line[index:]
        else:
            item = line[index:]
            if len(item) > length:
                item = item[:length]
            else:
                item.extend([default] * (length - len(item)))
        return item

    def get_int_list(
        self,
        index: int,
        length: Optional[int] = None,
        default: int = 0,
    ) -> list[int]:
        str_list = self.get_str_list(index, length)
        int_list: list[int] = []
        for item in str_list:
            try:
                int_list.append(int(item))
            except ValueError:
                int_list.append(default)
        return int_list

    def set_list(self, item: Optional[list[Any]], index: int):
        if item is None:
            return
        for i, string in enumerate(item):
            self.set_str(string, index + i)

    def copy(self) -> "tbcml.CSV":
        return tbcml.CSV(
            delimeter=self.delimeter,
            remove_padding=self.remove_padding,
            remove_comments=self.remove_comments,
            remove_empty=self.remove_empty,
            lines=self.lines,
        )
