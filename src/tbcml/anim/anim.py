from __future__ import annotations

import enum
import math
import tbcml

try:
    from PyQt5 import QtGui, QtCore
except ImportError:
    pass


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


class Anim:
    def __init__(self, model: tbcml.Model, anim: int):
        self.model = model
        self.anim: tbcml.UnitAnim
        self.set_anim(anim)

        self.frame = 0

    def set_frame(self, frame: int):
        self.frame = frame

    def set_anim(self, anim: int):
        if anim < 0 or anim >= len(self.model.anims):
            raise ValueError("Anim is not in range!")
        self.anim = self.model.anims[anim]

    def get_change_in_value(self, keyframes_obj: tbcml.KeyFrames) -> int | None:
        keyframes = keyframes_obj.keyframes
        if not keyframes:
            return None

        frame_counter = self.frame

        start_kf = keyframes[0]
        end_kf = keyframes[-1]

        start_change = start_kf.change_in_value
        end_change = end_kf.change_in_value

        start_frame = start_kf.frame
        end_frame = end_kf.frame
        if (
            start_frame is None
            or end_frame is None
            or start_change is None
            or end_change is None
        ):

            return None

        if frame_counter < start_frame:
            return None

        loop = keyframes_obj.loop or 0

        frame_progress = frame_counter - start_frame
        total_frames = end_frame - start_frame

        if frame_counter < end_frame or start_frame == end_frame:
            local_frame = frame_counter
        elif loop == -1:
            local_frame = (frame_progress % total_frames) + start_frame
        elif loop >= 1:
            if frame_progress / total_frames < loop:
                local_frame = (frame_progress % total_frames) + start_frame
            else:
                local_frame = end_frame
        else:
            local_frame = end_frame

        if start_frame == end_frame:
            return start_change
        if local_frame == end_frame:
            return end_change

        for i in range(len(keyframes) - 1):
            current_kf = keyframes[i]
            next_kf = keyframes[i + 1]

            c_frame = current_kf.frame
            n_frame = next_kf.frame

            c_ease_mode = current_kf.ease_mode
            c_ease_power = current_kf.ease_power or 0

            c_change = current_kf.change_in_value
            n_change = next_kf.change_in_value

            if (
                c_frame is None
                or n_frame is None
                or c_ease_mode is None
                or c_change is None
                or n_change is None
            ):
                continue

            if local_frame < c_frame or local_frame >= n_frame:
                continue

            ease_val = self.ease(
                c_ease_mode,
                c_ease_power,
                c_frame,
                n_frame,
                n_change,
                c_change,
                local_frame,
                i,
                keyframes,
            )
            return int(ease_val)

        return None

    def ease(
        self,
        c_ease_mode: int,
        c_ease_power: int,
        c_frame: int,
        n_frame: int,
        n_change: int,
        c_change: int,
        local_frame: int,
        c_index: int,
        keyframes: list[tbcml.KeyFrame],
    ) -> float:
        lerp = (local_frame - c_frame) / (n_frame - c_frame)
        if c_ease_mode == 0:  # Linear
            return (lerp * (n_change - c_change)) + c_change
        if c_ease_mode == 1:  # Instant
            return c_change
        if c_ease_mode == 2:  # Exponential
            if c_ease_power >= 0:
                return (
                    (1 - math.sqrt(1 - math.pow(lerp, c_ease_power)))
                    * (n_change - c_change)
                ) + c_change
            return (
                math.sqrt(1 - math.pow(1 - lerp, -c_ease_power)) * (n_change - c_change)
            ) + c_change
        if c_ease_mode == 3:  # Polynomial
            high = c_index
            low = c_index

            # Find continous run of keyframes with polynomial easing
            for i in range(c_index - 1, -1, -1):
                if keyframes[i].ease_mode == 3:
                    low = i
                else:
                    break

            for i in range(c_index + 1, len(keyframes)):
                high = i
                if keyframes[i].ease_mode != 3:
                    break

            # Calculate weighted sum
            total = 0
            for i in range(low, high + 1):
                val = (keyframes[i].change_in_value or 0) * 4096

                # Calculated weight factor
                for j in range(low, high + 1):
                    if i != j:
                        i_frame = keyframes[i].frame or 0
                        j_frame = keyframes[j].frame or 0

                        val *= (local_frame - j_frame) / (i_frame - j_frame)
                total += val

            return total / 4096

        raise ValueError("Unsupported ease mode")

    def apply_change(
        self,
        change: int,
        part: tbcml.ModelPart,
        mod_type: int,
    ):
        mod = AnimModificationType(mod_type)

        if part.anim is None:
            return

        if mod == AnimModificationType.PARENT:
            part.anim.parent_id = change
            part.anim.parent = self.model.mamodel.parts[change]
        elif mod == AnimModificationType.ID:
            part.anim.unit_id = change
        elif mod == AnimModificationType.SPRITE:
            part.anim.cut_id = change
            part.anim.rect = self.model.texture.get_rect(part.anim.cut_id)
            part.anim.img = self.model.texture.get_cut(part.anim.cut_id)
        elif mod == AnimModificationType.Z_ORDER:
            part.anim.z_depth = change * self.total_parts + part.anim.part_id
            self.sorted_parts.sort(
                key=lambda x: x.anim.z_depth or 0 if x.anim is not None else 0
            )
        elif mod == AnimModificationType.POS_X:
            part.anim.x = (part.x or 0) + change
        elif mod == AnimModificationType.POS_Y:
            part.anim.y = (part.y or 0) + change
        elif mod == AnimModificationType.PIVOT_X:
            part.anim.pivot_x = (part.pivot_x or 0) + change
        elif mod == AnimModificationType.PIVOT_Y:
            part.anim.pivot_y = (part.pivot_y or 0) + change
        elif mod == AnimModificationType.SCALE_UNIT:
            change_scaled = change / self.scale_unit
            part.anim.scale_x = int((part.scale_x or 0) * change_scaled)
            part.anim.scale_y = int((part.scale_y or 0) * change_scaled)

            part.anim.real_scale_x = part.anim.scale_x / self.scale_unit
            part.anim.real_scale_y = part.anim.scale_y / self.scale_unit

        elif mod == AnimModificationType.SCALE_X:
            change_scaled = change / self.scale_unit
            part.anim.scale_x = int(change_scaled * (part.scale_x or 0))
            part.anim.real_scale_x = part.anim.scale_x / self.scale_unit

        elif mod == AnimModificationType.SCALE_Y:
            change_scaled = change / self.scale_unit
            part.anim.scale_y = int(change_scaled * (part.scale_y or 0))
            part.anim.real_scale_y = part.anim.scale_y / self.scale_unit

        elif mod == AnimModificationType.ANGLE:
            part.anim.rotation = (part.rotation or 0) + change
        elif mod == AnimModificationType.OPACITY:
            change_scaled = change / self.alpha_unit
            part.anim.alpha = int(change_scaled * (part.alpha or 0))
        elif mod == AnimModificationType.H_FLIP:
            part.anim.h_flip = bool(change)
        elif mod == AnimModificationType.V_FLIP:
            part.anim.v_flip = bool(change)

    def set_part_vals(self):
        scale_unit = self.model.mamodel.units.scale_unit
        if scale_unit is None:
            return
        for part in self.model.mamodel.parts:
            anim = part.anim
            if anim is None:
                anim = part.init_anim()
            if anim.parent_id >= 0:
                anim.parent = self.model.mamodel.parts[anim.parent_id]

            if anim.cut_id >= 0:
                anim.rect = self.model.texture.get_rect(anim.cut_id)
                anim.img = self.model.texture.get_cut(anim.cut_id)

            if anim.scale_x != 0:
                anim.real_scale_x = anim.scale_x / scale_unit
            else:
                anim.real_scale_x = 0

            if anim.scale_y != 0:
                anim.real_scale_y = anim.scale_y / scale_unit
            else:
                anim.real_scale_y = 0

        self.total_frames = self.anim.get_end_frame() + 1
        self.total_parts = len(self.model.mamodel.parts)

        scale_unit = self.model.mamodel.units.scale_unit
        alpha_unit = self.model.mamodel.units.alpha_unit
        rotation_unit = self.model.mamodel.units.angle_unit

        if scale_unit is not None:
            self.scale_unit = scale_unit
        if alpha_unit is not None:
            self.alpha_unit = alpha_unit
        if rotation_unit is not None:
            self.rotation_unit = rotation_unit

        self.create_change_cache()
        self.create_keyframe_map()

        self.sorted_parts = self.model.mamodel.parts.copy()
        self.sorted_parts.sort(
            key=lambda x: x.anim.z_depth or 0 if x.anim is not None else 0
        )

    def create_change_cache(self):
        c_frame = self.frame
        self.change_cache: list[list[int | None]] = []
        for frame in range(self.total_frames):
            self.set_frame(frame)
            changes: list[int | None] = []
            for keyframes in self.anim.parts:
                changes.append(self.get_change_in_value(keyframes))
            self.change_cache.append(changes)

        self.set_frame(c_frame)

    def create_keyframe_map(self):
        self.keyframes_map: dict[int, list[tuple[tbcml.KeyFrames, int]]] = {}
        for part in self.model.mamodel.parts:
            for i, keyframes in enumerate(self.anim.parts):
                if part.part_id not in self.keyframes_map:
                    self.keyframes_map[part.part_id] = []
                if part.part_id != keyframes.model_id:
                    continue
                self.keyframes_map[part.part_id].append((keyframes, i))

    def draw_frame(self, painter: QtGui.QPainter, base_x: float, base_y: float):
        changes: list[int | None] = []

        local_frame = self.frame % self.total_frames

        changes = self.change_cache[local_frame]

        for part in self.model.mamodel.parts:
            keyframes_ls = self.keyframes_map[part.part_id]
            for keyframe, i in keyframes_ls:
                change = changes[i]
                if keyframe.modification_type is None or change is None:
                    continue
                self.apply_change(
                    change,
                    part,
                    keyframe.modification_type,
                )

        for part in self.sorted_parts:
            self.draw_part(
                part,
                painter,
                base_x,
                base_y,
            )

    def draw_part(
        self,
        part: tbcml.ModelPart,
        painter: QtGui.QPainter,
        base_x: float,
        base_y: float,
    ):
        if QtGui is None:
            return
        anim = part.anim
        if anim is None:
            return
        if anim.rect is None or anim.img is None:
            return
        if anim.parent_id < 0 or anim.unit_id < 0:
            return

        current_transform = painter.transform()

        matrix, scale_x, scale_y = self.transform(
            part,
            [0.1, 0.0, 0.0, 0.0, 0.1, 0.0],
            base_x,
            base_y,
            self.scale_unit,
            self.rotation_unit,
        )

        scx_bx = scale_x * base_x
        scy_by = scale_y * base_y

        flip_x = -1 if scale_x < 0 else 1
        flip_y = -1 if scale_y < 0 else 1

        t_piv_x = anim.pivot_x * scx_bx * flip_x
        t_piv_y = anim.pivot_y * scy_by * flip_y

        m0 = matrix[0] * flip_x
        m3 = matrix[3] * flip_x
        m1 = matrix[1] * flip_y
        m4 = matrix[4] * flip_y

        sc_w = (anim.rect.w or 0) * scx_bx
        sc_h = (anim.rect.h or 0) * scy_by

        painter.setTransform(
            QtGui.QTransform(m0, m3, m1, m4, matrix[2], matrix[5]), True
        )
        alpha = self.get_recursive_alpha(part, 1, self.alpha_unit)

        self.draw_img(
            anim.img, (t_piv_x, t_piv_y), (sc_w, sc_h), alpha, painter, anim.glow
        )
        if (anim.glow >= 1 and anim.glow <= 3) or anim.glow == -1:
            painter.setCompositionMode(
                QtGui.QPainter.CompositionMode.CompositionMode_SourceOver
            )
        if alpha != 1:
            painter.setOpacity(1)

        painter.setTransform(current_transform)

    def draw_img(
        self,
        img: tbcml.BCImage,
        pivot: tuple[float, float],
        size: tuple[float, float],
        alpha: float,
        painter: QtGui.QPainter,
        glow: int,
    ):
        painter.setOpacity(alpha)
        if (glow >= 1 and glow <= 3) or glow == -1:
            painter.setCompositionMode(
                QtGui.QPainter.CompositionMode.CompositionMode_Plus
            )

        data = img.fix_libpng_warning().to_data()
        q_img = QtGui.QImage()
        q_img.loadFromData(data.to_bytes())
        painter.drawImage(
            QtCore.QRectF(-pivot[0], -pivot[1], abs(size[0]), abs(size[1])), q_img
        )

    def transform(
        self,
        part: tbcml.ModelPart,
        matrix: list[float],
        sizer_x: float,
        sizer_y: float,
        scale_unit: int,
        angle_unit: int,
    ) -> tuple[list[float], float, float]:  # TODO: optimize
        siz_x, siz_y = sizer_x, sizer_y
        if part.anim is None:
            return matrix, siz_x, siz_y

        part_scale_x, part_scale_y = self.get_recursive_scale(part, (1, 1))
        if part.anim.parent is not None:
            matrix, _, _ = self.transform(
                part.anim.parent, matrix, sizer_x, sizer_y, scale_unit, angle_unit
            )
            if part.anim.real_scale_x == 0:
                scale_x = 0
            else:
                scale_x = part_scale_x / part.anim.real_scale_x
            if part.anim.real_scale_y == 0:
                scale_y = 0
            else:
                scale_y = part_scale_y / part.anim.real_scale_y
            siz_x = scale_x * sizer_x
            siz_y = scale_y * sizer_y

        m0, m1, m2, m3, m4, m5 = matrix

        if part.anim.part_id != 0:
            t_pos_x = part.anim.x * siz_x
            t_pos_y = part.anim.y * siz_y
            m2 += (m0 * t_pos_x) + (m1 * t_pos_y)
            m5 += (m3 * t_pos_x) + (m4 * t_pos_y)
        else:
            ints = self.model.mamodel.ints.ints[0]
            if (
                ints.part_id is None
                or ints.base_x_size is None
                or ints.base_y_size is None
            ):
                return matrix, siz_x, siz_y
            p0_x, p0_y = self.get_base_size(part, False, ints.part_id, scale_unit)
            shi_x = ints.base_x_size * p0_x
            shi_y = ints.base_y_size * p0_y
            p3_x = shi_x * sizer_x
            p3_y = shi_y * sizer_y

            px = part.anim.pivot_x * part_scale_x * sizer_x
            py = part.anim.pivot_y * part_scale_y * sizer_y
            x = px - p3_x
            y = py - p3_y
            m2 += (m0 * x) + (m1 * y)
            m5 += (m3 * x) + (m4 * y)

        if part.anim.rotation != 0:
            degrees = (part.anim.rotation / angle_unit) * 360
            radians = math.radians(degrees)
            sin = math.sin(radians)
            cos = math.cos(radians)
            f = (m0 * cos) + (m1 * sin)
            f2 = (m0 * -sin) + (m1 * cos)
            f3 = (m3 * cos) + (m4 * sin)
            f4 = (m3 * -sin) + (m4 * cos)
            m0 = f
            m1 = f2
            m3 = f3
            m4 = f4

        return [m0, m1, m2, m3, m4, m5], part_scale_x, part_scale_y

    def get_base_size(
        self, part: tbcml.ModelPart, parent: bool, int_part_id: int, scale_unit: int
    ) -> tuple[float, float]:
        if part.anim is None:
            raise ValueError("Anim cannot be None")
        signum_x = 1 if part.anim.scale_x >= 0 else -1
        signum_y = 1 if part.anim.scale_y >= 0 else -1
        if parent:
            if part.anim.parent is not None:
                size_x, size_y = self.get_base_size(
                    part.anim.parent, True, int_part_id, scale_unit
                )
                return size_x * signum_x, size_y * signum_y
            return signum_x, signum_y

        if int_part_id == -1 or int_part_id == part.anim.part_id:
            return part.anim.x / scale_unit, part.anim.y / scale_unit

        part2 = self.model.mamodel.parts[int_part_id]
        size_x, size_y = self.get_base_size(part2, True, int_part_id, scale_unit)
        size_x *= part.anim.x / scale_unit
        size_y *= part.anim.y / scale_unit
        return size_x * signum_x, size_y * signum_y

    def get_recursive_scale(
        self,
        part: tbcml.ModelPart,
        current_scale: tuple[float, float],
    ) -> tuple[float, float]:
        if part.anim is None:
            return current_scale

        scale_x = current_scale[0] * (part.anim.real_scale_x)
        scale_y = current_scale[1] * (part.anim.real_scale_y)

        if part.anim.parent is not None:
            return self.get_recursive_scale(part.anim.parent, (scale_x, scale_y))

        return (scale_x, scale_y)

    def get_recursive_alpha(
        self,
        part: tbcml.ModelPart,
        current_alpha: float,
        alpha_unit: int,
    ) -> float:
        if part.anim is None:
            return current_alpha

        alpha = current_alpha * (part.anim.alpha / alpha_unit)

        if part.anim.parent is not None:
            return self.get_recursive_alpha(part.anim.parent, alpha, alpha_unit)

        return alpha
