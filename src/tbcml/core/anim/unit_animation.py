import math
from typing import Any, Optional
from tbcml import core
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


class AnimModificationType(enum.Enum):
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
    def from_data(data: list[str]):
        frame = int(data[0])
        change_in_value = int(data[1])
        ease = int(data[2])
        ease_power = int(data[3])
        return KeyFrame(frame, change_in_value, ease, ease_power)

    def copy(self):
        return KeyFrame(self.frame, self.change, self.ease_mode, self.ease_power)

    def to_data(self) -> list[str]:
        ls: list[str] = [
            str(self.frame),
            str(self.change),
            str(self.ease_mode),
            str(self.ease_power),
        ]
        return ls

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

    def apply_dict(self, dict_data: dict[str, Any]):
        frame = dict_data.get("frame")
        change = dict_data.get("change")
        ease_mode = dict_data.get("ease_mode")
        ease_power = dict_data.get("ease_power")
        if frame is not None:
            self.frame = frame
        if change is not None:
            self.change = change
        if ease_mode is not None:
            self.ease_mode = ease_mode
        if ease_power is not None:
            self.ease_power = ease_power

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "change": self.change,
            "ease_mode": self.ease_mode,
            "ease_power": self.ease_power,
        }


class KeyFrames:
    def __init__(
        self,
        part_id: int,
        modification_type: AnimModificationType,
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
    def from_data(data: list[list[str]]) -> tuple[int, "KeyFrames"]:
        model_id = int(data[0][0])
        modification_type = AnimModificationType(int(data[0][1]))
        loop = int(data[0][2])
        min_value = int(data[0][3])
        max_value = int(data[0][4])
        try:
            name = data[0][5]
        except IndexError:
            name = ""

        total_keyframes = int(data[1][0])
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

    def to_data(self) -> list[list[str]]:
        ls: list[list[str]] = [
            [
                str(self.part_id),
                str(self.modification_type.value),
                str(self.loop),
                str(self.min_value),
                str(self.max_value),
            ],
            [str(len(self.keyframes))],
        ]
        if self.name:
            ls[0].append(self.name)
        new_ls: list[list[str]] = []
        for item in ls:
            new_ls.append(item)
        for keyframe in self.keyframes:
            new_ls.append(keyframe.to_data())
        return new_ls

    @staticmethod
    def create_empty() -> "KeyFrames":
        return KeyFrames(0, AnimModificationType.PARENT, 0, 0, 0, "", [])

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

        if not self.keyframes:
            return None

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
            raise ValueError("Invalid ease mode")

    def add_keyframe(self, keyframe: "KeyFrame"):
        self.keyframes.append(keyframe)
        self.sort_keyframes()

    def remove_keyframe(self, keyframe: "KeyFrame"):
        if keyframe in self.keyframes:
            self.keyframes.remove(keyframe)
            self.sort_keyframes()

    def sort_keyframes(self):
        self.keyframes.sort(key=lambda x: x.frame)

    def apply_dict(self, dict_data: dict[str, Any]):
        loop = dict_data.get("loop")
        if loop is not None:
            self.loop = loop

        part_id = dict_data.get("part_id")
        if part_id is not None:
            self.part_id = part_id

        modification_type = dict_data.get("modification_type")
        if modification_type is not None:
            self.modification_type = AnimModificationType(modification_type)

        min_value = dict_data.get("min_value")
        if min_value is not None:
            self.min_value = min_value

        max_value = dict_data.get("max_value")
        if max_value is not None:
            self.max_value = max_value

        name = dict_data.get("name")
        if name is not None:
            self.name = name

        keyframes = dict_data.get("keyframes")
        if keyframes is not None:
            for i, data_keyframe in enumerate(keyframes):
                if i < len(self.keyframes):
                    current_keyframe = self.keyframes[i]
                    current_keyframe.apply_dict(data_keyframe)
                else:
                    new_keyframe = KeyFrame.create_empty()
                    new_keyframe.apply_dict(data_keyframe)
                    self.add_keyframe(new_keyframe)

    def to_dict(self) -> dict[str, Any]:
        return {
            "loop": self.loop,
            "part_id": self.part_id,
            "modification_type": self.modification_type.value,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "name": self.name,
            "keyframes": [keyframe.to_dict() for keyframe in self.keyframes],
        }

    def flip_x(self):
        if self.modification_type == AnimModificationType.ANGLE:
            for keyframe in self.keyframes:
                keyframe.change = -keyframe.change

    def flip_y(self):
        if self.modification_type == AnimModificationType.ANGLE:
            for keyframe in self.keyframes:
                keyframe.change = -keyframe.change


class UnitAnimMetaData:
    def __init__(self, head_name: str, version_code: int, total_parts: int):
        self.head_name = head_name
        self.version_code = version_code
        self.total_parts = total_parts

    @staticmethod
    def from_csv(csv: "core.CSV") -> "UnitAnimMetaData":
        head_line = csv.read_line()
        if head_line is None:
            raise ValueError("CSV file is empty")
        head_name = head_line[0]

        version_line = csv.read_line()
        if version_line is None:
            raise ValueError("CSV file is empty")
        version_code = int(version_line[0])

        total_parts_line = csv.read_line()
        if total_parts_line is None:
            raise ValueError("CSV file is empty")
        total_parts = int(total_parts_line[0])

        return UnitAnimMetaData(head_name, version_code, total_parts)

    def to_csv(self, total_parts: int) -> "core.CSV":
        self.set_total_parts(total_parts)
        csv = core.CSV()
        csv.lines.append([self.head_name])
        csv.lines.append([str(self.version_code)])
        csv.lines.append([str(self.total_parts)])
        return csv

    def set_total_parts(self, total_parts: int):
        self.total_parts = total_parts

    def copy(self):
        return UnitAnimMetaData(self.head_name, self.version_code, self.total_parts)

    @staticmethod
    def create_empty() -> "UnitAnimMetaData":
        return UnitAnimMetaData("", 0, 0)

    def apply_dict(self, dict_data: dict[str, Any]):
        head_name = dict_data.get("head_name")
        if head_name is not None:
            self.head_name = head_name

        version_code = dict_data.get("version_code")
        if version_code is not None:
            self.version_code = version_code

        total_parts = dict_data.get("total_parts")
        if total_parts is not None:
            self.total_parts = total_parts

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "total_parts": self.total_parts,
        }


class UnitAnimLoaderInfo:
    def __init__(self, name: str, game_packs: "core.GamePacks"):
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
    def load(name: str, game_packs: "core.GamePacks") -> Optional["UnitAnim"]:
        file = game_packs.find_file(name)
        if file is None:
            return None

        return UnitAnim.from_data(name, file.dec_data)

    @staticmethod
    def from_data(name: str, data: "core.Data") -> "UnitAnim":
        csv = core.CSV(data)
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

    def save(self, game_packs: "core.GamePacks"):
        data = self.to_data()

        game_packs.set_file(self.name, data)

    def to_data(self) -> "core.Data":
        csv = self.meta_data.to_csv(self.get_total_parts())
        for part in self.parts:
            for line in part.to_data():
                csv.lines.append(line)
        return csv.to_data()

    def get_total_parts(self) -> int:
        return len(self.parts)

    def copy(self):
        return UnitAnim(
            [part.copy() for part in self.parts],
            self.meta_data.copy(),
            self.name,
        )

    def get_parts(self, part_id: int) -> list[KeyFrames]:
        return [part for part in self.parts if part.part_id == part_id]

    def is_empty(self) -> bool:
        return len(self.parts) == 0

    @staticmethod
    def create_empty() -> "UnitAnim":
        return UnitAnim([], UnitAnimMetaData.create_empty(), "")

    def apply_dict(self, dict_data: dict[str, Any]):
        parts = dict_data.get("parts")
        if parts is not None:
            for i, data_part in enumerate(parts):
                if i < len(self.parts):
                    current_part = self.parts[i]
                    current_part.apply_dict(data_part)
                else:
                    new_part = KeyFrames.create_empty()
                    new_part.apply_dict(data_part)
                    self.parts.append(new_part)

        meta_data = dict_data.get("meta_data")
        if meta_data is not None:
            self.meta_data.apply_dict(meta_data)

        name = dict_data.get("name")
        if name is not None:
            self.name = name

    def to_dict(self) -> dict[str, Any]:
        return {
            "parts": [part.to_dict() for part in self.parts],
            "meta_data": self.meta_data.to_dict(),
            "name": self.name,
        }

    def set_unit_id(self, unit_id: int):
        parts = self.name.split("_")
        parts[0] = core.PaddedInt(unit_id, 3).to_str()
        self.name = "_".join(parts)

    def set_unit_form(self, form: str):
        name = self.name
        parts = name.split("_")
        cat_id = parts[0]
        anim_id = parts[1][1:3]
        self.name = f"{cat_id}_{form}{anim_id}.maanim"

    def flip_x(self):
        for part in self.parts:
            part.flip_x()

    def flip_y(self):
        for part in self.parts:
            part.flip_y()
