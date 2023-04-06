import math
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
    SCALE_UNIT = 8
    SCALE_X = 9
    SCALE_Y = 10
    ANGLE = 11
    OPACITY = 12
    H_FLIP = 13
    V_FLIP = 14


class KeyFrame:
    def __init__(
        self,
        frame: int,
        change_in_value: int,
        ease_mode: int,
        ease_power: int,
    ):
        self.frame = frame
        self.change = change_in_value
        self.ease_mode = ease_mode
        self.ease_power = ease_power

    @staticmethod
    def from_data(data: list["io.data.Data"]):
        frame = data[0].to_int()
        change_in_value = data[1].to_int()
        ease = data[2].to_int()
        ease_power = data[3].to_int()
        return KeyFrame(frame, change_in_value, ease, ease_power)

    def serialize(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "change_in_value": self.change,
            "ease_mode": self.ease_mode,
            "ease_power": self.ease_power,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return KeyFrame(
            data["frame"],
            data["change_in_value"],
            data["ease_mode"],
            data["ease_power"],
        )

    def copy(self):
        return KeyFrame(self.frame, self.change, self.ease_mode, self.ease_power)

    def to_data(self) -> list["io.data.Data"]:
        ls: list[int] = [
            self.frame,
            self.change,
            self.ease_mode,
            self.ease_power,
        ]
        return io.data.Data.int_list_data_list(ls)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyFrame):
            return False
        return (
            self.frame == other.frame
            and self.change == other.change
            and self.ease_mode == other.ease_mode
            and self.ease_power == other.ease_power
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return (
            f"KeyFrame(frame={self.frame}, change_in_value={self.change}, "
            f"ease_mode={self.ease_mode}, ease_power={self.ease_power})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def create_empty() -> "KeyFrame":
        return KeyFrame(0, 0, 0, 0)

    def ease_linear(
        self,
        next_keyframe: "KeyFrame",
        local_frame: float,
        current_keyframe_start_frame: int,
        next_keyframe_start_frame: int,
    ) -> float:
        ti = (local_frame - current_keyframe_start_frame) / (
            next_keyframe_start_frame - current_keyframe_start_frame
        )
        change_in_value = (ti * (next_keyframe.change - self.change)) + self.change
        return change_in_value

    def ease_instant(self) -> float:
        return self.change

    def ease_exponential(
        self,
        next_keyframe: "KeyFrame",
        local_frame: float,
        current_keyframe_start_frame: int,
        next_keyframe_start_frame: int,
    ) -> float:
        if self.ease_power >= 0:
            change_in_value = (
                (
                    1
                    - math.sqrt(
                        1
                        - math.pow(
                            (((local_frame - current_keyframe_start_frame)))
                            / (
                                (
                                    next_keyframe_start_frame
                                    - current_keyframe_start_frame
                                )
                            ),
                            self.ease_power,
                        )
                    )
                )
                * (next_keyframe.change - self.change)
            ) + self.change
        else:
            change_in_value = (
                math.sqrt(
                    1
                    - math.pow(
                        1
                        - (
                            (((local_frame - current_keyframe_start_frame)))
                            / (
                                (
                                    next_keyframe_start_frame
                                    - current_keyframe_start_frame
                                )
                            )
                        ),
                        -self.ease_power,
                    )
                )
                * (next_keyframe.change - self.change)
            ) + self.change
        return change_in_value

    def ease_sine(
        self,
        next_keyframe: "KeyFrame",
        local_frame: float,
        current_keyframe_start_frame: int,
        next_keyframe_start_frame: int,
    ) -> float:
        ti = (local_frame - current_keyframe_start_frame) / (
            next_keyframe_start_frame - current_keyframe_start_frame
        )
        change_in_value = (
            ((next_keyframe.change - self.change) * (1 - math.cos(ti * math.pi / 2)))
            / 2
        ) + self.change
        return change_in_value


class KeyFrames:
    def __init__(
        self,
        part_id: int,
        modification_type: ModificationType,
        loop: int,
        min_value: int,
        max_value: int,
        name: str,
        keyframes: list[KeyFrame],
    ):
        self.part_id = part_id
        self.modification_type = modification_type
        self.loop = loop
        self.min_value = min_value
        self.max_value = max_value
        self.name = name
        self.keyframes = keyframes

    @staticmethod
    def from_data(data: list[list["io.data.Data"]]) -> tuple[int, "KeyFrames"]:
        model_id = data[0][0].to_int()
        modification_type = ModificationType(data[0][1].to_int())
        loop = data[0][2].to_int()
        min_value = data[0][3].to_int()
        max_value = data[0][4].to_int()
        try:
            name = data[0][5].to_str()
        except IndexError:
            name = ""

        total_keyframes = data[1][0].to_int()
        end_index = 2
        keyframes: list[KeyFrame] = []
        for _ in range(total_keyframes):
            keyframes.append(KeyFrame.from_data(data[end_index]))
            end_index += 1

        return (
            end_index,
            KeyFrames(
                model_id,
                modification_type,
                loop,
                min_value,
                max_value,
                name,
                keyframes,
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
            "keyframes": [keyframe.serialize() for keyframe in self.keyframes],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return KeyFrames(
            data["part_id"],
            data["modification_type"],
            data["loop"],
            data["min_value"],
            data["max_value"],
            data["name"],
            [KeyFrame.deserialize(keyframe) for keyframe in data["keyframes"]],
        )

    def copy(self):
        return KeyFrames(
            self.part_id,
            self.modification_type,
            self.loop,
            self.min_value,
            self.max_value,
            self.name,
            [keyframe.copy() for keyframe in self.keyframes],
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
            [len(self.keyframes)],
        ]
        if self.name:
            ls[0].append(self.name)
        new_ls: list[list["io.data.Data"]] = []
        for item in ls:
            new_ls.append(io.data.Data.string_list_data_list(item))
        for keyframe in self.keyframes:
            new_ls.append(keyframe.to_data())
        return new_ls

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyFrames):
            return False
        return (
            self.part_id == other.part_id
            and self.modification_type == other.modification_type
            and self.loop == other.loop
            and self.min_value == other.min_value
            and self.max_value == other.max_value
            and self.name == other.name
            and self.keyframes == other.keyframes
        )

    def __str__(self) -> str:
        return (
            f"PartAnim(part_id={self.part_id}, modification_type={self.modification_type}, "
            f"loop={self.loop}, min_value={self.min_value}, max_value={self.max_value}, "
            f"name={self.name}, keyframes={self.keyframes})"
        )

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def create_empty() -> "KeyFrames":
        return KeyFrames(0, ModificationType.PARENT, 0, 0, 0, "", [])

    def get_end_frame(self) -> int:
        if not self.keyframes:
            return 1
        loop = self.loop if self.loop > 0 else 1
        val = self.keyframes[-1].frame * loop
        if val == 0:
            return 1
        return val

    def ease_polynomial(
        self,
        keyframe_index: int,
        local_frame: float,
    ) -> float:
        high = keyframe_index
        low = keyframe_index
        for j in range(keyframe_index - 1, -1, -1):
            if self.keyframes[j].ease_mode == 3:
                low = j
            else:
                break
        for j in range(keyframe_index + 1, len(self.keyframes)):
            high = j
            if self.keyframes[j].ease_mode != 3:
                break
        total = 0
        for j in range(low, high + 1):
            val = self.keyframes[j].change * 4096
            for k in range(low, high + 1):
                if k != j:
                    val = (
                        val
                        * ((local_frame - self.keyframes[k].frame))
                        / ((self.keyframes[j].frame - self.keyframes[k].frame))
                    )
            total += val
        change_in_value = total / 4096
        return change_in_value

    def set_action(self, frame_counter: int):
        local_frame = 0
        change_in_value = 0

        start_frame = self.keyframes[0].frame
        end_frame = self.keyframes[-1].frame
        if frame_counter >= start_frame:
            if frame_counter < end_frame or start_frame == end_frame:
                local_frame = frame_counter
            elif self.loop == -1:
                local_frame = (
                    (frame_counter - start_frame) % (end_frame - start_frame)
                ) + start_frame
            elif self.loop >= 1:
                condition = (frame_counter - start_frame) / (
                    end_frame - start_frame
                ) < self.loop
                if condition:
                    local_frame = (
                        (frame_counter - start_frame) % (end_frame - start_frame)
                    ) + start_frame
                else:
                    local_frame = end_frame
            else:
                local_frame = end_frame
            if start_frame == end_frame:
                change_in_value = self.keyframes[0].change
            elif local_frame == end_frame:
                change_in_value = self.keyframes[-1].change
            else:
                for keyframe_index in range(len(self.keyframes) - 1):
                    current_keyframe = self.keyframes[keyframe_index]
                    next_keyframe = self.keyframes[keyframe_index + 1]
                    current_keyframe_start_frame = current_keyframe.frame
                    next_keyframe_start_frame = next_keyframe.frame
                    if (
                        local_frame < current_keyframe_start_frame
                        or local_frame >= next_keyframe_start_frame
                    ):
                        continue
                    else:
                        change_in_value = self.ease(keyframe_index, local_frame)
                        break

            change_in_value = int(change_in_value)
        return change_in_value

    def ease(self, keyframe_index: int, local_frame: float) -> float:
        current_keyframe = self.keyframes[keyframe_index]
        next_keyframe = self.keyframes[keyframe_index + 1]
        current_keyframe_start_frame = current_keyframe.frame
        next_keyframe_start_frame = next_keyframe.frame
        if current_keyframe.ease_mode == 0:
            return current_keyframe.ease_linear(
                next_keyframe,
                local_frame,
                current_keyframe_start_frame,
                next_keyframe_start_frame,
            )
        elif current_keyframe.ease_mode == 1:
            return current_keyframe.ease_instant()
        elif current_keyframe.ease_mode == 2:
            return current_keyframe.ease_exponential(
                next_keyframe,
                local_frame,
                current_keyframe_start_frame,
                next_keyframe_start_frame,
            )
        elif current_keyframe.ease_mode == 3:
            return self.ease_polynomial(keyframe_index, local_frame)
        elif current_keyframe.ease_mode == 4:
            return current_keyframe.ease_sine(
                next_keyframe,
                local_frame,
                current_keyframe_start_frame,
                next_keyframe_start_frame,
            )
        else:
            raise Exception("Unknown ease mode")


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
    def __init__(self, parts: list[KeyFrames], meta_data: UnitAnimMetaData, name: str):
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

        parts: list[KeyFrames] = []
        total_parts = meta_data.total_parts
        start_index = 3
        for _ in range(total_parts):
            lines = csv.lines[start_index:]
            end_index, part = KeyFrames.from_data(lines)
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
            [KeyFrames.deserialize(part) for part in data["parts"]],
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

    def get_parts(self, part_id: int) -> list[KeyFrames]:
        return [part for part in self.parts if part.part_id == part_id]

    def is_empty(self) -> bool:
        return len(self.parts) == 0

    @staticmethod
    def create_empty() -> "UnitAnim":
        return UnitAnim([], UnitAnimMetaData.create_empty(), "")
