import enum
from typing import Optional, Union
from tbcml import core


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
    def from_country_code_res(cc: "core.CountryCode") -> "Delimeter":
        if cc == core.CountryCode.JP:
            return Delimeter(DelimeterType.COMMA)
        else:
            return Delimeter(DelimeterType.PIPE)

    def __str__(self) -> str:
        return self.delimeter.value


class CSV:
    def __init__(
        self,
        file_data: Optional["core.Data"] = None,
        delimeter: Union[Delimeter, str] = Delimeter(DelimeterType.COMMA),
        remove_padding: bool = True,
        remove_comments: bool = True,
        remove_empty: bool = True,
    ):
        if file_data is None:
            file_data = core.Data()
        self.file_data = file_data
        if remove_padding:
            try:
                self.file_data = self.file_data.unpad_pkcs7()
            except ValueError:
                pass
        self.delimeter = str(delimeter)
        self.remove_comments = remove_comments
        self.remove_empty = remove_empty
        self.index = 0
        self.parse()

    def parse(self):
        lines: list[list[str]] = []
        for line in self.file_data.to_str().splitlines():
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
        path: "core.Path", delimeter: Delimeter = Delimeter(DelimeterType.COMMA)
    ) -> "CSV":
        return CSV(path.read(), delimeter)

    def reset_index(self):
        self.index = 0

    def __iter__(self):
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

    def to_data(self) -> "core.Data":
        return core.Data(
            "\n".join([self.delimeter.join(line) for line in self.lines if line])
        )

    def extend(self, length: int, sub_length: int = 0):
        for _ in range(length):
            if sub_length == 0:
                self.lines.append([])
            else:
                self.lines.append([""] * sub_length)
