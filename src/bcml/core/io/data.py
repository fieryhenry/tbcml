import base64
import enum
from io import BytesIO
import struct
import typing
from typing import Any, Optional, Union
from bcml.core.io import bc_csv, path


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
            raise TypeError(f"data must be bytes, str, int, bool, Data, or None, not {type(data)}")
        self.pos = 0
    
    def is_empty(self) -> bool:
        return len(self.data) == 0
    
    def to_file(self, path: "path.Path"):
        with open(path.path, "wb") as f:
            f.write(self.data)
        
    def copy(self) -> "Data":
        return Data(self.data)
    
    @staticmethod
    def from_file(path: "path.Path") -> "Data":
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
    
    def read_uint(self) -> int:
        result = struct.unpack("<I", self.read_bytes(4))[0]
        return result
    
    def read_short(self) -> int:
        result = struct.unpack("<h", self.read_bytes(2))[0]
        return result
    
    def read_ushort(self) -> int:
        result = struct.unpack("<H", self.read_bytes(2))[0]
        return result
    
    def read_byte(self) -> int:
        result = struct.unpack("<b", self.read_bytes(1))[0]
        return result
    
    def read_ubyte(self) -> int:
        result = struct.unpack("<B", self.read_bytes(1))[0]
        return result
    
    def read_float(self) -> float:
        result = struct.unpack("<f", self.read_bytes(4))[0]
        return result
    
    def read_double(self) -> float:
        result = struct.unpack("<d", self.read_bytes(8))[0]
        return result
    
    def read_string(self, length: Optional[int] = None) -> str:
        if length is None:
            length = self.read_int()
        result = self.read_bytes(length).decode("utf-8")
        return result
    
    def write_bytes(self, data: bytes):
        self.data += data
        self.pos += len(data)
    
    def write_int(self, value: int):
        self.write_bytes(struct.pack("<i", value))
    
    def write_uint(self, value: int):
        self.write_bytes(struct.pack("<I", value))
    
    def write_short(self, value: int):
        self.write_bytes(struct.pack("<h", value))
    
    def write_ushort(self, value: int):
        self.write_bytes(struct.pack("<H", value))
    
    def write_byte(self, value: int):
        self.write_bytes(struct.pack("<b", value))
    
    def write_ubyte(self, value: int):
        self.write_bytes(struct.pack("<B", value))
    
    def write_float(self, value: float):
        self.write_bytes(struct.pack("<f", value))
    
    def write_double(self, value: float):
        self.write_bytes(struct.pack("<d", value))
    
    def write_string(self, value: str, length: Optional[int] = None):
        if length is None:
            self.write_int(len(value))
        else:
            self.write_int(length)
        self.write_bytes(value.encode("utf-8"))
    
    def read_bool(self) -> bool:
        return self.read_byte() != 0
    
    def write_bool(self, value: bool):
        self.write_byte(int(value))

    def read(self, type: "DataType") -> Any:
        if type == DataType.INT:
            return self.read_int()
        elif type == DataType.UINT:
            return self.read_uint()
        elif type == DataType.SHORT:
            return self.read_short()
        elif type == DataType.USHORT:
            return self.read_ushort()
        elif type == DataType.BYTE:
            return self.read_byte()
        elif type == DataType.UBYTE:
            return self.read_ubyte()
        elif type == DataType.FLOAT:
            return self.read_float()
        elif type == DataType.DOUBLE:
            return self.read_double()
        elif type == DataType.STRING:
            return self.read_string()
        elif type == DataType.BOOL:
            return self.read_bool()
        else:
            raise TypeError("Invalid type")
        
    def write(self, type: "DataType", value: Any):
        if type == DataType.INT:
            self.write_int(value)
        elif type == DataType.UINT:
            self.write_uint(value)
        elif type == DataType.SHORT:
            self.write_short(value)
        elif type == DataType.USHORT:
            self.write_ushort(value)
        elif type == DataType.BYTE:
            self.write_byte(value)
        elif type == DataType.UBYTE:
            self.write_ubyte(value)
        elif type == DataType.FLOAT:
            self.write_float(value)
        elif type == DataType.DOUBLE:
            self.write_double(value)
        elif type == DataType.STRING:
            self.write_string(value)
        elif type == DataType.BOOL:
            self.write_bool(value)
        else:
            raise TypeError("Invalid type")
        
    def pad_pkcs7(self, block_size: int = 16) -> "Data":
        pad = block_size - (len(self.data) % block_size)
        return Data(self.data + bytes([pad] * pad))
    
    def unpad_pkcs7(self) -> "Data":
        try:
            pad = self.data[-1]
        except IndexError:
            raise ValueError("Cannot unpad empty data")
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
        except IndexError:
            raise ValueError("Cannot unpad empty data")
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
    
    #def remove_comments(self) -> "Data":
    #    comments = ["//"]
    #    data_list = self.split("\n")
    #    for comment in comments:
    #        data_list = [data.split(comment)[0] for data in data_list]
    #    return Data.from_many(data_list, Data("\n"))
    
    def to_int(self) -> int:
        return int(self.data.decode())
    
    def to_int_little(self) -> int:
        return int.from_bytes(self.data, "little")
    
    def to_str(self) -> str:
        return self.data.decode()
    
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
    
    def to_csv(self, *args: Any, **kwargs: Any) -> "bc_csv.CSV":
        return bc_csv.CSV(self, *args, **kwargs)

class DataType(enum.Enum):
    INT = 0
    UINT = 1
    SHORT = 2
    USHORT = 3
    BYTE = 4
    UBYTE = 5
    FLOAT = 6
    DOUBLE = 7
    STRING = 8
    BOOL = 9

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