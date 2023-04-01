import math
from typing import Any, Optional, Union
from bcml.core.anim import texture, rect, anim_transformer, unit_animation
from bcml.core import io, game_data
from PyQt5 import QtGui, QtCore


class ModelPart:
    def __init__(
        self,
        index: int,
        parent_id: int,
        unit_id: int,
        rect_id: int,
        z_depth: int,
        x: int,
        y: int,
        pivot_x: int,
        pivot_y: int,
        scale_x: int,
        scale_y: int,
        rotation: int,
        alpha: int,
        glow: int,
        name: str,
    ):
        self.index = index
        self.parent_id = parent_id
        self.unit_id = unit_id
        self.rect_id = rect_id
        self.z_depth = z_depth
        self.x = x
        self.y = y
        self.pivot_x = pivot_x
        self.pivot_y = pivot_y
        self.scale_x = scale_x
        self.scale_y = scale_y
        self.rotation = rotation
        self.alpha = alpha
        self.glow = glow
        self.name = name

        self.pos_x_orig = x
        self.pos_y_orig = y
        self.pivot_x_orig = pivot_x
        self.pivot_y_orig = pivot_y
        self.scale_x_orig = scale_x
        self.scale_y_orig = scale_y
        self.rotation_orig = rotation
        self.alpha_orig = alpha

        self.parent: Optional[ModelPart] = None
        self.children: list[ModelPart] = []
        self.part_anims: list[unit_animation.PartAnim] = []
        self.model: Model
        self.scale_unit: int
        self.angle_unit: int
        self.alpha_unit: int

        self.__recursive_scale: Optional[tuple[float, float]] = None
        self.__recursive_alpha: Optional[float] = None

    def load_texs(self):
        rct = self.model.tex.get_rect(self.rect_id)
        if rct is None:
            self.rect = rect.Rect.create_empty()
        else:
            self.rect = rct

        img = self.model.tex.get_image(self.rect_id)
        if img is None:
            self.image = io.bc_image.BCImage.create_empty()
        else:
            self.image = img

    def set_rect(self, rect_id: int):
        self.rect_id = rect_id
        self.load_texs()

    def get_end_frame(self) -> int:
        if len(self.part_anims) == 0:
            return 0
        return max([part_anim.get_end_frame() for part_anim in self.part_anims])

    def set_action(self, frame_counter: int, part_anim: unit_animation.PartAnim):
        local_frame = 0
        change_in_value = 0

        start_frame = part_anim.moves[0].frame
        end_frame = part_anim.moves[-1].frame
        if frame_counter >= start_frame:
            if frame_counter < end_frame or start_frame == end_frame:
                local_frame = frame_counter
            elif part_anim.loop == -1:
                local_frame = (
                    (frame_counter - start_frame) % (end_frame - start_frame)
                ) + start_frame
            elif part_anim.loop >= 1:
                condition = (frame_counter - start_frame) / (
                    end_frame - start_frame
                ) < part_anim.loop
                if condition:
                    local_frame = (
                        (frame_counter - start_frame) % (end_frame - start_frame)
                    ) + start_frame
                else:
                    local_frame = end_frame
            else:
                local_frame = end_frame
            if start_frame == end_frame:
                change_in_value = part_anim.moves[0].change
            elif local_frame == end_frame:
                change_in_value = part_anim.moves[-1].change
            else:
                for move_index in range(len(part_anim.moves) - 1):
                    current_move = part_anim.moves[move_index]
                    next_move = part_anim.moves[move_index + 1]
                    current_move_start_frame = current_move.frame
                    next_move_start_frame = next_move.frame
                    ti = (local_frame - current_move_start_frame) / (
                        next_move_start_frame - current_move_start_frame
                    )
                    if (
                        local_frame < current_move_start_frame
                        or local_frame >= next_move_start_frame
                    ):
                        continue
                    elif current_move.ease_mode == 0:  # Linear
                        change_in_value = (
                            ti * (next_move.change - current_move.change)
                        ) + current_move.change

                    elif current_move.ease_mode == 1:  # Instant
                        change_in_value = current_move.change
                    elif current_move.ease_mode == 2:  # Exponential
                        if current_move.ease_power >= 0:
                            change_in_value = (
                                (
                                    1
                                    - math.sqrt(
                                        1
                                        - math.pow(
                                            (((local_frame - current_move_start_frame)))
                                            / (
                                                (
                                                    next_move_start_frame
                                                    - current_move_start_frame
                                                )
                                            ),
                                            current_move.ease_power,
                                        )
                                    )
                                )
                                * (next_move.change - current_move.change)
                            ) + current_move.change
                        else:
                            change_in_value = (
                                math.sqrt(
                                    1
                                    - math.pow(
                                        1
                                        - (
                                            (((local_frame - current_move_start_frame)))
                                            / (
                                                (
                                                    next_move_start_frame
                                                    - current_move_start_frame
                                                )
                                            )
                                        ),
                                        -current_move.ease_power,
                                    )
                                )
                                * (next_move.change - current_move.change)
                            ) + current_move.change
                    elif current_move.ease_mode == 3:  # Polynomial
                        high = move_index
                        low = move_index
                        for j in range(move_index - 1, -1, -1):
                            if part_anim.moves[j].ease_mode == 3:
                                low = j
                            else:
                                break
                        for j in range(move_index + 1, len(part_anim.moves)):
                            high = j
                            if part_anim.moves[j].ease_mode != 3:
                                break
                        total = 0
                        for j in range(low, high + 1):
                            val = part_anim.moves[j].change * 4096
                            for k in range(low, high + 1):
                                if k != j:
                                    val = (
                                        val
                                        * ((local_frame - part_anim.moves[k].frame))
                                        / (
                                            (
                                                part_anim.moves[j].frame
                                                - part_anim.moves[k].frame
                                            )
                                        )
                                    )
                            total += val
                        change_in_value = total / 4096

                    elif current_move.ease_mode == 4:  # Sine
                        change_in_value = (
                            (
                                (next_move.change - current_move.change)
                                * (1 - math.cos(ti * math.pi / 2))
                            )
                            / 2
                        ) + current_move.change

            change_in_value = int(change_in_value)

            mod = part_anim.modification_type
            if mod == unit_animation.ModificationType.PARENT:
                self.parent_id = change_in_value
                self.set_parent_by_id(self.parent_id)
            elif mod == unit_animation.ModificationType.ID:
                self.unit_id = change_in_value
            elif mod == unit_animation.ModificationType.SPRITE:
                self.rect_id = change_in_value
                self.set_rect(self.rect_id)
            elif mod == unit_animation.ModificationType.Z_ORDER:
                self.z_depth = (
                    change_in_value * len(self.model.mamodel.parts) + self.index
                )
            elif mod == unit_animation.ModificationType.POS_X:
                self.x = change_in_value + self.pos_x_orig
            elif mod == unit_animation.ModificationType.POS_Y:
                self.y = change_in_value + self.pos_y_orig
            elif mod == unit_animation.ModificationType.PIVOT_X:
                self.pivot_x = change_in_value + self.pivot_x_orig
            elif mod == unit_animation.ModificationType.PIVOT_Y:
                self.pivot_y = change_in_value + self.pivot_y_orig
            elif mod == unit_animation.ModificationType.SCALE_UNIT:
                self.gsca = change_in_value
                self.set_scale(self.scale_x, self.scale_y)
            elif mod == unit_animation.ModificationType.SCALE_X:
                self.scale_x = int(
                    change_in_value * self.scale_x_orig / self.scale_unit
                )
                self.set_scale(self.scale_x, self.scale_y)
            elif mod == unit_animation.ModificationType.SCALE_Y:
                self.scale_y = int(
                    change_in_value * self.scale_y_orig / self.scale_unit
                )

                self.set_scale(self.scale_x, self.scale_y)
            elif mod == unit_animation.ModificationType.ANGLE:
                self.rotation = change_in_value + self.rotation_orig
                self.set_rotation(self.rotation)
            elif mod == unit_animation.ModificationType.OPACITY:
                self.alpha = int(change_in_value * self.alpha_orig / self.alpha_unit)
                self.set_alpha(self.alpha)
            elif mod == unit_animation.ModificationType.H_FLIP:
                self.h_flip = change_in_value
            elif mod == unit_animation.ModificationType.V_FLIP:
                self.v_flip = change_in_value

    def reset_scale(self):
        self.__recursive_scale = None
        for child in self.children:
            child.reset_scale()

    def reset_alpha(self):
        self.__recursive_alpha = None
        for child in self.children:
            child.reset_alpha()

    def set_scale(self, scale_x: int, scale_y: int):
        self.scale_x = scale_x
        self.scale_y = scale_y
        scl_x = scale_x / self.scale_unit
        scl_y = scale_y / self.scale_unit
        gcsa = self.gsca / self.scale_unit
        self.real_scale_x = scl_x * gcsa
        self.real_scale_y = scl_y * gcsa
        self.reset_scale()

    def set_alpha(self, alpha: int):
        self.alpha = alpha
        alp = alpha / self.alpha_unit
        self.real_alpha = alp
        self.reset_alpha()

    def set_rotation(self, rotation: int):
        self.rotation = rotation
        self.real_rotation = rotation / self.angle_unit

    @staticmethod
    def from_data(data: list["io.data.Data"], index: int):
        parent_id = data[0].to_int()
        unit_id = data[1].to_int()
        cut_id = data[2].to_int()
        z_depth = data[3].to_int()
        x = data[4].to_int()
        y = data[5].to_int()
        pivot_x = data[6].to_int()
        pivot_y = data[7].to_int()
        scale_x = data[8].to_int()
        scale_y = data[9].to_int()
        rotation = data[10].to_int()
        alpha = data[11].to_int()
        glow = data[12].to_int()
        try:
            name = data[13].to_str()
        except IndexError:
            name = ""

        return ModelPart(
            index,
            parent_id,
            unit_id,
            cut_id,
            z_depth,
            x,
            y,
            pivot_x,
            pivot_y,
            scale_x,
            scale_y,
            rotation,
            alpha,
            glow,
            name,
        )

    def to_data(self) -> list[Any]:
        data: list[Any] = [
            self.parent_id,
            self.unit_id,
            self.rect_id,
            self.z_depth,
            self.x,
            self.y,
            self.pivot_x,
            self.pivot_y,
            self.scale_x,
            self.scale_y,
            self.rotation,
            self.alpha,
            self.glow,
        ]
        if self.name:
            data.append(self.name)
        return data

    def draw_part(
        self,
        painter: "QtGui.QPainter",
        base_x: float,
        base_y: float,
    ):
        img = self.image
        rct = self.rect
        current_transform = painter.transform()
        transformer = anim_transformer.AnimTransformer()
        scale_x, scale_y = self.get_recursive_scale()
        self.transform(transformer, base_x, base_y)

        flip_x, flip_y = self.get_flip(scale_x, scale_y)
        t_piv_x = self.pivot_x * scale_x * flip_x * base_x
        t_piv_y = self.pivot_y * scale_y * flip_y * base_y
        transformer.scale(flip_x, flip_y)
        sc_w = rct.width * scale_x * base_x
        sc_h = rct.height * scale_y * base_y
        self.draw_img(
            transformer,
            img,
            (t_piv_x, t_piv_y),
            (sc_w, sc_h),
            self.get_recursive_alpha(),
            self.glow,
            painter,
        )
        painter.setTransform(current_transform)
        painter.setOpacity(1)
        painter.setCompositionMode(
            QtGui.QPainter.CompositionMode.CompositionMode_SourceOver
        )

    def draw_img(
        self,
        transformer: anim_transformer.AnimTransformer,
        img: "io.bc_image.BCImage",
        pivot: tuple[float, float],
        size: tuple[float, float],
        alpha: float,
        glow: int,
        painter: "QtGui.QPainter",
    ):
        painter.setTransform(transformer.to_q_transform(), True)
        painter.setOpacity(alpha)

        glow_support = (glow >= 1 and glow <= 3) or glow == -1
        if glow_support:
            painter.setCompositionMode(
                QtGui.QPainter.CompositionMode.CompositionMode_Plus
            )

        q_img = img.fix_libpng_warning().to_qimage()
        painter.drawImage(
            QtCore.QRectF(
                -pivot[0],
                -pivot[1],
                abs(size[0]),
                abs(size[1]),
            ),
            q_img,
        )

    def get_flip(self, scale_x: float, scale_y: float) -> tuple[int, int]:
        flip_x = scale_x < 0
        flip_y = scale_y < 0
        return (
            -1 if flip_x else 1,
            -1 if flip_y else 1,
        )

    def transform(
        self,
        transformer: anim_transformer.AnimTransformer,
        sizer_x: float,
        sizer_y: float,
    ):
        siz_x, siz_y = sizer_x, sizer_y
        if self.parent is not None:
            self.parent.transform(transformer, sizer_x, sizer_y)
            scale_x, scale_y = self.parent.get_recursive_scale()
            siz_x = scale_x * sizer_x
            siz_y = scale_y * sizer_y

        t_pos_x = self.x * siz_x
        t_pos_y = self.y * siz_y
        if self.index != 0:
            transformer.translate(t_pos_x, t_pos_y)
        else:
            p3_x = 0
            p3_y = 0
            if self.ints:
                data = self.ints[0]
                p0_x, p0_y = self.get_base_size(False)
                shi_x = data[2] * p0_x
                shi_y = data[3] * p0_y
                p3_x = shi_x * sizer_x
                p3_y = shi_y * sizer_y

            p0_x, p0_y = self.get_recursive_scale()
            px = self.pivot_x * p0_x * sizer_x
            py = self.pivot_y * p0_y * sizer_y
            transformer.translate(px - p3_x, py - p3_y)

        if self.rotation != 0:
            transformer.rotate(fraction=self.real_rotation)

    def get_base_size(self, parent: bool) -> tuple[float, float]:
        signum_x = 1 if self.scale_x >= 0 else -1
        signum_y = 1 if self.scale_y >= 0 else -1
        if parent:
            if self.parent is not None:
                size_x, size_y = self.parent.get_base_size(True)
                return size_x * signum_x, size_y * signum_y
            else:
                return signum_x, signum_y
        else:
            part_id = self.ints[0][0]
            if part_id == -1:
                return self.real_scale_x, self.real_scale_y
            else:
                if part_id == self.index:
                    return self.real_scale_x, self.real_scale_y
                else:
                    part = self.model.get_part(part_id)
                    size_x, size_y = part.get_base_size(True)
                    size_x *= self.real_scale_x
                    size_y *= self.real_scale_y
                    return size_x * signum_x, size_y * signum_y

    def get_recursive_scale(self) -> tuple[float, float]:
        if self.__recursive_scale is not None:
            return self.__recursive_scale
        current_scale_x = self.real_scale_x
        current_scale_y = self.real_scale_y
        if self.parent is not None:
            parent_scale_x, parent_scale_y = self.parent.get_recursive_scale()
            current_scale_x *= parent_scale_x
            current_scale_y *= parent_scale_y
        self.__recursive_scale = (current_scale_x, current_scale_y)
        return current_scale_x, current_scale_y

    def get_recursive_alpha(self) -> float:
        if self.__recursive_alpha is not None:
            return self.__recursive_alpha
        current_alpha = self.real_alpha
        if self.parent is not None:
            current_alpha *= self.parent.get_recursive_alpha()
        self.__recursive_alpha = current_alpha
        return current_alpha

    def serialize(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "parent_id": self.parent_id,
            "unit_id": self.unit_id,
            "cut_id": self.rect_id,
            "z_depth": self.z_depth,
            "x": self.x,
            "y": self.y,
            "pivot_x": self.pivot_x,
            "pivot_y": self.pivot_y,
            "scale_x": self.scale_x,
            "scale_y": self.scale_y,
            "rotation": self.rotation,
            "alpha": self.alpha,
            "glow": self.glow,
            "name": self.name,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ModelPart":
        return ModelPart(
            data["index"],
            data["parent_id"],
            data["unit_id"],
            data["cut_id"],
            data["z_depth"],
            data["x"],
            data["y"],
            data["pivot_x"],
            data["pivot_y"],
            data["scale_x"],
            data["scale_y"],
            data["rotation"],
            data["alpha"],
            data["glow"],
            data["name"],
        )

    def copy(self) -> "ModelPart":
        return ModelPart(
            self.index,
            self.parent_id,
            self.unit_id,
            self.rect_id,
            self.z_depth,
            self.x,
            self.y,
            self.pivot_x,
            self.pivot_y,
            self.scale_x,
            self.scale_y,
            self.rotation,
            self.alpha,
            self.glow,
            self.name,
        )

    def __repr__(self) -> str:
        return f"ModelPart({self.index}, {self.parent_id}, {self.unit_id}, {self.rect_id}, {self.z_depth}, {self.x}, {self.y}, {self.pivot_x}, {self.pivot_y}, {self.scale_x}, {self.scale_y}, {self.rotation}, {self.alpha}, {self.glow}, {self.name})"

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ModelPart):
            return False
        return (
            self.index == other.index
            and self.parent_id == other.parent_id
            and self.unit_id == other.unit_id
            and self.rect_id == other.rect_id
            and self.z_depth == other.z_depth
            and self.x == other.x
            and self.y == other.y
            and self.pivot_x == other.pivot_x
            and self.pivot_y == other.pivot_y
            and self.scale_x == other.scale_x
            and self.scale_y == other.scale_y
            and self.rotation == other.rotation
            and self.alpha == other.alpha
            and self.glow == other.glow
            and self.name == other.name
        )

    def set_model(self, model: "Model"):
        self.model = model

    def set_parent(self, parent: "ModelPart"):
        self.parent = parent

    def set_parent_by_id(self, parent_id: int):
        self.parent = self.model.get_part(parent_id)

    def set_children(self, all_parts: list["ModelPart"]):
        for part in all_parts:
            if part.parent_id == self.index:
                self.children.append(part)

    def set_units(self, scale_unit: int, angle_unit: int, alpha_unit: int):
        self.scale_unit = scale_unit
        self.gsca = scale_unit
        self.angle_unit = angle_unit
        self.alpha_unit = alpha_unit

        self.real_scale_x = self.scale_x / scale_unit
        self.real_scale_y = self.scale_y / scale_unit
        self.real_rotation = self.rotation / angle_unit
        self.real_alpha = self.alpha / alpha_unit

    def set_part_anims(self, part_anims: list["unit_animation.PartAnim"]):
        self.part_anims = part_anims

    def set_ints(self, ints: list[list[int]]):
        self.ints = ints

    def set_unit_id(self, unit_id: int):
        self.unit_id = unit_id

    @staticmethod
    def create_empty(index: int) -> "ModelPart":
        return ModelPart(index, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, "")


class ModelMetaData:
    def __init__(self, head_name: str, version_code: int, total_parts: int):
        self.head_name = head_name
        self.version_code = version_code
        self.total_parts = total_parts

    @staticmethod
    def from_csv(csv: "io.bc_csv.CSV") -> "ModelMetaData":
        head_line = csv.read_line()
        if head_line is None:
            raise RuntimeError("Invalid model file")
        head_name = head_line[0].to_str()

        version_line = csv.read_line()
        if version_line is None:
            raise RuntimeError("Invalid model file")
        version_code = version_line[0].to_int()

        total_parts_line = csv.read_line()
        if total_parts_line is None:
            raise RuntimeError("Invalid model file")
        total_parts = total_parts_line[0].to_int()

        return ModelMetaData(head_name, version_code, total_parts)

    def to_csv(self, total_parts: int) -> "io.bc_csv.CSV":
        self.set_total_parts(total_parts)

        csv = io.bc_csv.CSV()
        csv.add_line(self.head_name)
        csv.add_line(self.version_code)
        csv.add_line(self.total_parts)

        return csv

    def set_total_parts(self, total_parts: int):
        self.total_parts = total_parts

    def __repr__(self) -> str:
        return (
            f"ModelMetaData({self.head_name}, {self.version_code}, {self.total_parts})"
        )

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ModelMetaData):
            return False
        return (
            self.head_name == other.head_name
            and self.version_code == other.version_code
            and self.total_parts == other.total_parts
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "total_parts": self.total_parts,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ModelMetaData":
        return ModelMetaData(
            data["head_name"], data["version_code"], data["total_parts"]
        )

    def copy(self) -> "ModelMetaData":
        return ModelMetaData(
            self.head_name,
            self.version_code,
            self.total_parts,
        )

    @staticmethod
    def create_empty() -> "ModelMetaData":
        return ModelMetaData("", 0, 0)


class MamodelLoaderInfo:
    def __init__(self, mamodel_name: str, game_packs: "game_data.pack.GamePacks"):
        self.mamodel_name = mamodel_name
        self.game_packs = game_packs

    def load(self) -> "Mamodel":
        mamodel = Mamodel.load(self.mamodel_name, self.game_packs)
        if mamodel is None:
            return Mamodel.create_empty()
        return mamodel


class Mamodel:
    def __init__(
        self,
        meta_data: ModelMetaData,
        scale_unit: int,
        angle_unit: int,
        alpha_unit: int,
        ints: list[list[int]],
        parts: list[ModelPart],
        comments: list[str],
    ):
        self.meta_data = meta_data
        self.scale_unit = scale_unit
        self.angle_unit = angle_unit
        self.alpha_unit = alpha_unit
        self.ints = ints
        self.parts = parts
        self.comments = comments

    def serialize(self) -> dict[str, Any]:
        return {
            "meta_data": self.meta_data.serialize(),
            "scale_unit": self.scale_unit,
            "angle_unit": self.angle_unit,
            "alpha_unit": self.alpha_unit,
            "ints": self.ints,
            "parts": [part.serialize() for part in self.parts],
            "comments": self.comments,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Mamodel":
        return Mamodel(
            ModelMetaData.deserialize(data["meta_data"]),
            data["scale_unit"],
            data["angle_unit"],
            data["alpha_unit"],
            data["ints"],
            [ModelPart.deserialize(part) for part in data["parts"]],
            data["comments"],
        )

    def copy(self) -> "Mamodel":
        return Mamodel(
            self.meta_data.copy(),
            self.scale_unit,
            self.angle_unit,
            self.alpha_unit,
            self.ints,
            [part.copy() for part in self.parts],
            self.comments.copy(),
        )

    def __repr__(self) -> str:
        return f"Mamodel({self.meta_data}, {self.scale_unit}, {self.angle_unit}, {self.alpha_unit}, {self.ints}, {self.parts}, {self.comments})"

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Mamodel):
            return False
        return (
            self.meta_data == other.meta_data
            and self.scale_unit == other.scale_unit
            and self.angle_unit == other.angle_unit
            and self.alpha_unit == other.alpha_unit
            and self.ints == other.ints
            and self.parts == other.parts
            and self.comments == other.comments
        )

    @staticmethod
    def create_empty() -> "Mamodel":
        return Mamodel(ModelMetaData.create_empty(), 0, 0, 0, [], [], [])

    @staticmethod
    def load(
        mamodel_name: str, game_packs: "game_data.pack.GamePacks"
    ) -> Optional["Mamodel"]:
        mamodel_file = game_packs.find_file(mamodel_name)
        if mamodel_file is None:
            return None

        csv = mamodel_file.dec_data.to_csv()
        meta_data = ModelMetaData.from_csv(csv)
        total_parts = meta_data.total_parts

        parts: list[ModelPart] = []
        for i in range(total_parts):
            line_data = csv.read_line()
            if line_data is None:
                continue
            part = ModelPart.from_data(line_data, i)
            parts.append(part)

        units_line = csv.read_line()
        if units_line is None:
            return None

        scale_unit = units_line[0].to_int()
        angle_unit = units_line[1].to_int()
        alpha_unit = units_line[2].to_int()

        ints: list[list[int]] = []
        total_ints_line = csv.read_line()
        if total_ints_line is None:
            return None
        total_ints = total_ints_line[0].to_int()
        comments: list[str] = []

        for _ in range(total_ints):
            line_data = csv.read_line()
            if line_data is None:
                continue
            comment = ""
            if len(line_data) == 7:
                comment = line_data[6].to_str()
            ints.append(io.data.Data.data_list_int_list(line_data[:6]))
            comments.append(comment)

        mamodel = Mamodel(
            meta_data, scale_unit, angle_unit, alpha_unit, ints, parts, comments
        )
        return mamodel


class Model:
    def __init__(
        self,
        tex: Union[texture.TexLoaderInfo, texture.Texture],
        anims: list[Union[unit_animation.UnitAnim, unit_animation.UnitAnimLoaderInfo]],
        mamodel: Union[Mamodel, MamodelLoaderInfo],
        name: str,
    ):
        self.__tex = tex
        self.__anims = anims
        self.__mamodel = mamodel
        self.name = name

    def get_part(self, index: int) -> ModelPart:
        if index < 0 or index >= len(self.mamodel.parts):
            raise RuntimeError("Invalid model part index")
        return self.mamodel.parts[index]

    def get_sorted_parts(self) -> list[ModelPart]:
        return sorted(self.mamodel.parts, key=lambda part: part.z_depth)

    def set_models(self):
        for part in self.mamodel.parts:
            part.set_model(self)

    def set_parents(self):
        for part in self.mamodel.parts:
            if part.parent_id != -1:
                part.set_parent(self.get_part(part.parent_id))

    def set_children(self):
        for part in self.mamodel.parts:
            part.set_children(self.mamodel.parts)

    def set_units(self):
        for part in self.mamodel.parts:
            part.set_units(
                self.mamodel.scale_unit,
                self.mamodel.angle_unit,
                self.mamodel.alpha_unit,
            )

    def set_ints(self):
        for part in self.mamodel.parts:
            part.set_ints(self.mamodel.ints)

    def set_required(self):
        self.set_models()
        self.set_parents()
        self.set_children()
        self.set_units()
        self.set_ints()
        self.tex.split_cuts()
        self.load_texs()

    def load_texs(self):
        for part in self.mamodel.parts:
            part.load_texs()

    def set_part_anims(self, anim_index: int):
        for part in self.mamodel.parts:
            anim_parts = self.anims[anim_index].get_parts(part.index)
            part.set_part_anims(anim_parts)

    def serialize(self) -> dict[str, Any]:
        return {
            "tex": self.tex.serialize(),
            "anims": [anim.serialize() for anim in self.anims],
            "mamodel": self.mamodel.serialize(),
            "name": self.name,
        }

    @property
    def tex(self) -> texture.Texture:
        if isinstance(self.__tex, texture.TexLoaderInfo):
            self.__tex = self.__tex.load()
        return self.__tex

    @property
    def anims(self) -> list[unit_animation.UnitAnim]:
        for i, anim in enumerate(self.__anims):
            if isinstance(anim, unit_animation.UnitAnimLoaderInfo):
                anim = anim.load()
                if anim is None:
                    self.__anims[i] = unit_animation.UnitAnim.create_empty()
                else:
                    self.__anims[i] = anim
        return self.__anims  # type: ignore

    @property
    def mamodel(self) -> Mamodel:
        if isinstance(self.__mamodel, MamodelLoaderInfo):
            self.__mamodel = self.__mamodel.load()
        return self.__mamodel

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Model":
        return Model(
            texture.Texture.deserialize(data["tex"]),
            [
                unit_animation.UnitAnim.deserialize(anim_data)
                for anim_data in data["anims"]
            ],
            Mamodel.deserialize(data["mamodel"]),
            data["name"],
        )

    def copy(self) -> "Model":
        return Model(
            self.tex,
            [anim.copy() for anim in self.anims],
            self.mamodel.copy(),
            self.name,
        )

    def __repr__(self) -> str:
        return f"Model({self.tex}, {self.anims}, {self.mamodel}, {self.name})"

    def __str__(self) -> str:
        return repr(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Model):
            return False
        return (
            self.tex == other.tex
            and self.anims == other.anims
            and self.mamodel == other.mamodel
            and self.name == other.name
        )

    @staticmethod
    def load(
        mamodel_name: str,
        imgcut_name: str,
        img_name: str,
        maanim_names: list[str],
        game_packs: "game_data.pack.GamePacks",
    ):
        tex_loader = texture.TexLoaderInfo(img_name, imgcut_name, game_packs)
        anim_loaders: list[unit_animation.UnitAnimLoaderInfo] = []
        for maanim_name in maanim_names:
            anim = unit_animation.UnitAnimLoaderInfo(maanim_name, game_packs)
            anim_loaders.append(anim)

        mamodel_loader = MamodelLoaderInfo(mamodel_name, game_packs)

        model = Model(
            tex_loader,
            anim_loaders,  # type: ignore
            mamodel_loader,
            mamodel_name,
        )
        return model

    def save(
        self,
        game_packs: "game_data.pack.GamePacks",
    ):
        self.tex.save(game_packs)
        for anim in self.anims:
            anim.save(game_packs)
        mamodel_file = game_packs.find_file(self.name)
        if mamodel_file is None:
            return
        csv = self.mamodel.meta_data.to_csv(self.get_total_parts())
        for part in self.mamodel.parts:
            csv.add_line(part.to_data())

        csv.add_line(
            [self.mamodel.scale_unit, self.mamodel.angle_unit, self.mamodel.alpha_unit]
        )
        csv.add_line([len(self.mamodel.ints)])
        for i, ints in enumerate(self.mamodel.ints):
            csv.add_line(ints)
            if self.mamodel.comments[i]:
                csv.lines[-1].append(io.data.Data(self.mamodel.comments[i]))

        game_packs.set_file(self.name, csv.to_data())

    def get_total_parts(self) -> int:
        return len(self.mamodel.parts)

    def set_unit_id(self, unit_id: int):
        self.tex.set_unit_id(unit_id)
        for part in self.mamodel.parts:
            part.set_unit_id(unit_id)

    def set_unit_form(self, unit_form: str):
        self.tex.set_unit_form(unit_form)

    def is_empty(self) -> bool:
        return self.tex.is_empty()

    @staticmethod
    def create_empty() -> "Model":
        return Model(
            texture.Texture.create_empty(),
            [],
            Mamodel.create_empty(),
            "",
        )

    def set_action(self, frame_counter: int):
        for part in self.mamodel.parts:
            for part_anim in part.part_anims:
                part.set_action(frame_counter, part_anim)

    def get_end_frame(self) -> int:
        end_frame = 0
        for part in self.mamodel.parts:
            end_frame = max(end_frame, part.get_end_frame())
        return end_frame
