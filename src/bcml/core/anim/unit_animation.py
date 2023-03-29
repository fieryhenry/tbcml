from typing import Any, Optional
from bcml.core import io, game_data
import enum


class AnimType(enum.Enum):
    WALK = 0
    IDLE = 1
    ATTACK = 2
    KNOCK_BACK = 3

    @staticmethod
    def from_bcu_str(string: str) -> Optional["AnimType"]:
        string = string.split("_")[1]
        string = string.split(".")[0]
        if string == "walk":
            return AnimType.WALK
        elif string == "idle":
            return AnimType.IDLE
        elif string == "attack":
            return AnimType.ATTACK
        elif string == "kb":
            return AnimType.KNOCK_BACK
        else:
            return None


class ModificationType(enum.Enum):
    PARENT = 0
    ID = 1
    SPRITE = 2
    Z_ORDER = 3
    POS_X = 4
    POS_Y = 5
    PIVOT_X = 6
    PIVOT_Y = 7
    SCALE = 8
    SCALE_X = 9
    SCALE_Y = 10
    ANGLE = 11
    OPACITY = 12
    H_FLIP = 13
    V_FLIP = 14


class Move:
    def __init__(
        self,
        frame: int,
        change_in_value: int,
        ease_mode: int,
        ease_power: int,
    ):
        self.frame = frame
        self.change_in_value = change_in_value
        self.ease_mode = ease_mode
        self.ease_power = ease_power

    @staticmethod
    def from_data(data: list["io.data.Data"]):
        frame = data[0].to_int()
        change_in_value = data[1].to_int()
        ease = data[2].to_int()
        ease_power = data[3].to_int()
        return Move(frame, change_in_value, ease, ease_power)

    def serialize(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "change_in_value": self.change_in_value,
            "ease_mode": self.ease_mode,
            "ease_power": self.ease_power,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return Move(
            data["frame"],
            data["change_in_value"],
            data["ease_mode"],
            data["ease_power"],
        )

    def copy(self):
        return Move(self.frame, self.change_in_value, self.ease_mode, self.ease_power)

    def to_data(self) -> list["io.data.Data"]:
        ls: list[int] = [
            self.frame,
            self.change_in_value,
            self.ease_mode,
            self.ease_power,
        ]
        return io.data.Data.int_list_data_list(ls)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Move):
            return False
        return (
            self.frame == other.frame
            and self.change_in_value == other.change_in_value
            and self.ease_mode == other.ease_mode
            and self.ease_power == other.ease_power
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return (
            f"Move(frame={self.frame}, change_in_value={self.change_in_value}, "
            f"ease_mode={self.ease_mode}, ease_power={self.ease_power})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def create_empty() -> "Move":
        return Move(0, 0, 0, 0)


class PartAnim:
    def __init__(
        self,
        part_id: int,
        modification_type: ModificationType,
        loop: int,
        min_value: int,
        max_value: int,
        name: str,
        moves: list[Move],
    ):
        self.part_id = part_id
        self.modification_type = modification_type
        self.loop = loop
        self.min_value = min_value
        self.max_value = max_value
        self.name = name
        self.moves = moves

    @staticmethod
    def from_data(data: list[list["io.data.Data"]]) -> tuple[int, "PartAnim"]:
        model_id = data[0][0].to_int()
        modification_type = ModificationType(data[0][1].to_int())
        loop = data[0][2].to_int()
        min_value = data[0][3].to_int()
        max_value = data[0][4].to_int()
        try:
            name = data[0][5].to_str()
        except IndexError:
            name = ""

        total_moves = data[1][0].to_int()
        end_index = 2
        moves: list[Move] = []
        for _ in range(total_moves):
            moves.append(Move.from_data(data[end_index]))
            end_index += 1

        return (
            end_index,
            PartAnim(
                model_id,
                modification_type,
                loop,
                min_value,
                max_value,
                name,
                moves,
            ),
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "part_id": self.part_id,
            "modification_type": self.modification_type,
            "loop": self.loop,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "name": self.name,
            "moves": [move.serialize() for move in self.moves],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return PartAnim(
            data["part_id"],
            data["modification_type"],
            data["loop"],
            data["min_value"],
            data["max_value"],
            data["name"],
            [Move.deserialize(move) for move in data["moves"]],
        )

    def copy(self):
        return PartAnim(
            self.part_id,
            self.modification_type,
            self.loop,
            self.min_value,
            self.max_value,
            self.name,
            [move.copy() for move in self.moves],
        )

    def to_data(self) -> list[list["io.data.Data"]]:
        ls: list[list[Any]] = [
            [
                self.part_id,
                self.modification_type.value,
                self.loop,
                self.min_value,
                self.max_value,
            ],
            [len(self.moves)],
        ]
        if self.name:
            ls[0].append(self.name)
        new_ls: list[list["io.data.Data"]] = []
        for item in ls:
            new_ls.append(io.data.Data.string_list_data_list(item))
        for move in self.moves:
            new_ls.append(move.to_data())
        return new_ls

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PartAnim):
            return False
        return (
            self.part_id == other.part_id
            and self.modification_type == other.modification_type
            and self.loop == other.loop
            and self.min_value == other.min_value
            and self.max_value == other.max_value
            and self.name == other.name
            and self.moves == other.moves
        )

    def __str__(self) -> str:
        return (
            f"PartAnim(part_id={self.part_id}, modification_type={self.modification_type}, "
            f"loop={self.loop}, min_value={self.min_value}, max_value={self.max_value}, "
            f"name={self.name}, moves={self.moves})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def create_empty() -> "PartAnim":
        return PartAnim(0, ModificationType.PARENT, 0, 0, 0, "", [])


class UnitAnimMetaData:
    def __init__(self, head_name: str, version_code: int, total_parts: int):
        self.head_name = head_name
        self.version_code = version_code
        self.total_parts = total_parts

    @staticmethod
    def from_csv(csv: "io.bc_csv.CSV") -> "UnitAnimMetaData":
        head_line = csv.read_line()
        if head_line is None:
            raise ValueError("CSV file is empty")
        head_name = head_line[0].to_str()

        version_line = csv.read_line()
        if version_line is None:
            raise ValueError("CSV file is empty")
        version_code = version_line[0].to_int()

        total_parts_line = csv.read_line()
        if total_parts_line is None:
            raise ValueError("CSV file is empty")
        total_parts = total_parts_line[0].to_int()

        return UnitAnimMetaData(head_name, version_code, total_parts)

    def to_csv(self, total_parts: int) -> "io.bc_csv.CSV":
        self.set_total_parts(total_parts)
        csv = io.bc_csv.CSV()
        csv.add_line([self.head_name])
        csv.add_line([self.version_code])
        csv.add_line([self.total_parts])
        return csv

    def set_total_parts(self, total_parts: int):
        self.total_parts = total_parts

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnitAnimMetaData):
            return False
        return (
            self.head_name == other.head_name
            and self.version_code == other.version_code
            and self.total_parts == other.total_parts
        )

    def __str__(self) -> str:
        return (
            f"UnitAnimMetaData(head_name={self.head_name}, version_code={self.version_code}, "
            f"total_parts={self.total_parts})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    def copy(self):
        return UnitAnimMetaData(self.head_name, self.version_code, self.total_parts)

    def serialize(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "total_parts": self.total_parts,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return UnitAnimMetaData(
            data["head_name"], data["version_code"], data["total_parts"]
        )

    @staticmethod
    def create_empty() -> "UnitAnimMetaData":
        return UnitAnimMetaData("", 0, 0)


class UnitAnimLoaderInfo:
    def __init__(self, name: str, game_packs: "game_data.pack.GamePacks"):
        self.name = name
        self.game_packs = game_packs

    def load(self) -> Optional["UnitAnim"]:
        return UnitAnim.load(self.name, self.game_packs)


class UnitAnim:
    def __init__(self, parts: list[PartAnim], meta_data: UnitAnimMetaData, name: str):
        self.parts = parts
        self.meta_data = meta_data
        self.name = name

    @staticmethod
    def load(name: str, game_packs: "game_data.pack.GamePacks") -> Optional["UnitAnim"]:
        file = game_packs.find_file(name)
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        meta_data = UnitAnimMetaData.from_csv(csv)

        parts: list[PartAnim] = []
        total_parts = meta_data.total_parts
        start_index = 3
        for _ in range(total_parts):
            lines = csv.lines[start_index:]
            end_index, part = PartAnim.from_data(lines)
            parts.append(part)
            start_index += end_index

        return UnitAnim(parts, meta_data, name)

    def save(self, game_packs: "game_data.pack.GamePacks"):
        file = game_packs.find_file(self.name)
        if file is None:
            raise FileNotFoundError(f"Could not find file {self.name}")
        csv = self.meta_data.to_csv(self.get_total_parts())
        for part in self.parts:
            for line in part.to_data():
                csv.add_line(line)
        game_packs.set_file(self.name, csv.to_data())

    def get_total_parts(self) -> int:
        return len(self.parts)

    def copy(self):
        return UnitAnim(
            [part.copy() for part in self.parts],
            self.meta_data.copy(),
            self.name,
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "parts": [part.serialize() for part in self.parts],
            "meta_data": self.meta_data.serialize(),
            "name": self.name,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return UnitAnim(
            [PartAnim.deserialize(part) for part in data["parts"]],
            UnitAnimMetaData.deserialize(data["meta_data"]),
            data["name"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnitAnim):
            return False
        return (
            self.parts == other.parts
            and self.meta_data == other.meta_data
            and self.name == other.name
        )

    def __str__(self) -> str:
        return f"UnitAnim(parts={self.parts}, meta_data={self.meta_data}, name={self.name})"

    def __repr__(self) -> str:
        return self.__str__()

    def get_part(self, part_id: int) -> PartAnim:
        if part_id < 0 or part_id >= len(self.parts):
            raise IndexError(f"Part id {part_id} is out of range")
        return self.parts[part_id]

    def is_empty(self) -> bool:
        return len(self.parts) == 0

    @staticmethod
    def create_empty() -> "UnitAnim":
        return UnitAnim([], UnitAnimMetaData.create_empty(), "")
