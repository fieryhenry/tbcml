import base64
import enum
from io import BytesIO
import lzma
import struct
import typing
from typing import Any, Literal, Optional, Union
from tbcml import core


class PaddingType(enum.Enum):
    PKCS7 = enum.auto()
    ZERO = enum.auto()
    NONE = enum.auto()


class Data:
    def __init__(self, data: Union[bytes, str, None, int, bool, "Data"] = None):
        if isinstance(data, str):
            self.data = data.encode("utf-8")
        elif isinstance(data, bytes):
            self.data = data
        elif isinstance(data, bool):
            value = 1 if data else 0
            self.data = str(value).encode("utf-8")
        elif isinstance(data, int):
            self.data = str(data).encode("utf-8")
        elif isinstance(data, Data):
            self.data = data.data
        elif data is None:
            self.data = b""
        else:
            raise TypeError(
                f"data must be bytes, str, int, bool, Data, or None, not {type(data)}"
            )
        self.pos = 0

    def decompress_xz(self) -> "Data":
        return Data(lzma.decompress(self.data))

    @staticmethod
    def from_hex(hex: str):
        return Data(bytes.fromhex(hex))

    def is_empty(self) -> bool:
        return len(self.data) == 0

    def to_file(self, path: "core.Path"):
        with open(path.path, "wb") as f:
            f.write(self.data)

    def write(self, data: "Data"):
        pos = self.pos
        self.data = self.data[:pos] + data.data + self.data[pos + len(data) :]
        self.pos += len(data)

    def copy(self) -> "Data":
        return Data(self.data)

    @staticmethod
    def from_file(path: "core.Path") -> "Data":
        with open(path.path, "rb") as f:
            return Data(f.read())

    def set_pos(self, pos: int):
        self.pos = pos

    def get_pos(self) -> int:
        return self.pos

    def to_hex(self) -> str:
        return self.data.hex()

    def __len__(self) -> int:
        return len(self.data)

    def __add__(self, other: "Data") -> "Data":
        return Data(self.data + other.data)

    @typing.overload
    def __getitem__(self, key: int) -> int:
        pass

    @typing.overload
    def __getitem__(self, key: slice) -> "Data":
        pass

    def __getitem__(self, key: Union[int, slice]) -> Union[int, "Data"]:
        if isinstance(key, int):
            return self.data[key]
        elif isinstance(key, slice):  # type: ignore
            return Data(self.data[key])
        else:
            raise TypeError("key must be int or slice")

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Data):
            return self.data == other.data
        else:
            return False

    def get_bytes(self) -> bytes:
        return self.data

    def read_bytes(self, length: int) -> bytes:
        result = self.data[self.pos : self.pos + length]
        self.pos += length
        return result

    def read_int(self) -> int:
        result = struct.unpack("<i", self.read_bytes(4))[0]
        return result

    def read_int_list(self, length: int) -> list[int]:
        result: list[int] = []
        for _ in range(length):
            result.append(self.read_int())
        return result

    def pad_pkcs7(self, block_size: int = 16) -> "Data":
        pad = block_size - (len(self.data) % block_size)
        return Data(self.data + bytes([pad] * pad))

    def unpad_pkcs7(self) -> "Data":
        try:
            pad = self.data[-1]
        except IndexError as exc:
            raise ValueError("Cannot unpad empty data") from exc
        if pad > len(self.data):
            raise ValueError("Invalid padding")
        if self.data[-pad:] != bytes([pad] * pad):
            raise ValueError("Invalid padding")
        return Data(self.data[:-pad])

    def pad_zeroes(self, block_size: int = 16) -> "Data":
        pad = block_size - (len(self.data) % block_size)
        return Data(self.data + bytes([0] * pad))

    def unpad_zeroes(self) -> "Data":
        try:
            pad = self.data[-1]
        except IndexError as exc:
            raise ValueError("Cannot unpad empty data") from exc
        if pad > len(self.data):
            raise ValueError("Invalid padding")
        if self.data[-pad:] != bytes([0] * pad):
            raise ValueError("Invalid padding")
        return Data(self.data[:-pad])

    def pad(self, padding_type: "PaddingType", block_size: int = 16) -> "Data":
        if padding_type == PaddingType.PKCS7:
            return self.pad_pkcs7(block_size)
        elif padding_type == PaddingType.ZERO:
            return self.pad_zeroes(block_size)
        else:
            raise TypeError("Invalid padding type")

    def split(self, separator: bytes) -> list["Data"]:
        data_list: list[Data] = []
        for line in self.data.split(separator):
            data_list.append(Data(line))
        return data_list

    def to_int(self) -> int:
        return int(self.data.decode())

    def to_int_little(self) -> int:
        return int.from_bytes(self.data, "little")

    def to_str(self) -> str:
        return self.data.decode(encoding="utf-8-sig")

    def to_bool(self) -> bool:
        return bool(self.to_int())

    @staticmethod
    def int_list_data_list(int_list: list[int]) -> list["Data"]:
        data_list: list[Data] = []
        for integer in int_list:
            data_list.append(Data(str(integer)))
        return data_list

    @staticmethod
    def string_list_data_list(string_list: list[Any]) -> list["Data"]:
        data_list: list[Data] = []
        for string in string_list:
            data_list.append(Data(str(string)))
        return data_list

    @staticmethod
    def data_list_int_list(data_list: list["Data"]) -> list[int]:
        int_list: list[int] = []
        for data in data_list:
            int_list.append(data.to_int())
        return int_list

    @staticmethod
    def data_list_string_list(data_list: list["Data"]) -> list[str]:
        string_list: list[str] = []
        for data in data_list:
            string_list.append(data.to_str())
        return string_list

    def to_bytes(self) -> bytes:
        return self.data

    @staticmethod
    def from_many(others: list["Data"], joiner: Optional["Data"] = None) -> "Data":
        data_lst: list[bytes] = []
        for other in others:
            data_lst.append(other.data)
        if joiner is None:
            return Data(b"".join(data_lst))
        else:
            return Data(joiner.data.join(data_lst))

    @staticmethod
    def from_int_list(
        int_list: list[int], endianess: Literal["little", "big"]
    ) -> "Data":
        bytes_data = b""
        for integer in int_list:
            bytes_data += integer.to_bytes(4, endianess)
        return Data(bytes_data)

    def strip(self) -> "Data":
        return Data(self.data.strip())

    def replace(self, old_data: "Data", new_data: "Data") -> "Data":
        return Data(self.data.replace(old_data.data, new_data.data))

    def set(self, value: Union[bytes, str, None, int, bool]) -> None:
        self.data = Data(value).data

    def to_bytes_io(self) -> BytesIO:
        return BytesIO(self.data)

    def __repr__(self) -> str:
        return f"Data({self.data!r})"

    def __str__(self) -> str:
        return self.to_str()

    def to_base_64(self) -> str:
        return base64.b64encode(self.data).decode()

    @staticmethod
    def from_base_64(string: str) -> "Data":
        return Data(base64.b64decode(string))

    def to_csv(self, *args: Any, **kwargs: Any) -> "core.CSV":
        return core.CSV(self, *args, **kwargs)

    def search(self, search_data: "Data", start: int = 0) -> int:
        return self.data.find(search_data.data, start)


class PaddedInt:
    def __init__(self, value: int, size: int):
        self.value = value
        self.size = size

    def __int__(self):
        return self.value

    def __str__(self):
        return str(self.value).zfill(self.size)

    def __repr__(self):
        return f"PaddedInt({self.value}, {self.size})"

    def to_str(self):
        return str(self)
