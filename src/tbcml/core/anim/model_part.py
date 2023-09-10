"""Module for representing a part of a model"""
import math
from typing import Any, Optional

from PyQt5 import QtCore, QtGui

from tbcml import core


class ModelPart:
    """Represents a part of a model"""

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
        """Initializes a ModelPart object

        Args:
            index (int): Part index of the model
            parent_id (int): Parent part index of the model
            unit_id (int): Unit ID that the model is attached to (doesn't really do anything)
            rect_id (int): What cutout of the texture to use
            z_depth (int): Z depth of the part
            x (int): X position of the part
            y (int): Y position of the part
            pivot_x (int): X pivot of the part. This is the point that the part rotates and scales around.
            pivot_y (int): Y pivot of the part. This is the point that the part rotates and scales around.
            scale_x (int): X scale of the part
            scale_y (int): Y scale of the part
            rotation (int): Rotation of the part
            alpha (int): Alpha of the part
            glow (int): Glow of the part. When drawing the part, if the value is between 1 and 3 or -1, the part will be draw additively.
            name (str): Name of the part
        """
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
        self.glow_support = (glow >= 1 and glow <= 3) or glow == -1
        self.name = name

        self.pos_x_orig = x
        self.pos_y_orig = y
        self.pivot_x_orig = pivot_x
        self.pivot_y_orig = pivot_y
        self.scale_x_orig = scale_x
        self.scale_y_orig = scale_y
        self.rotation_orig = rotation
        self.alpha_orig = alpha
        self.parent_id_orig = parent_id
        self.rect_id_orig = rect_id
        self.unit_id_orig = unit_id
        self.z_depth_orig = z_depth

        self.parent: Optional[ModelPart] = None
        self.children: list[ModelPart] = []
        self.keyframes_sets: list[core.KeyFrames] = []
        self.model: Optional[core.Model] = None

        self.scale_unit = 1
        self.gsca = 1
        self.angle_unit = 1
        self.alpha_unit = 1

        self.h_flip = False
        self.v_flip = False

        self.real_scale_x = 0
        self.real_scale_y = 0
        self.real_alpha = 0
        self.real_rotation = 0

        self.__scale_x = None
        self.__scale_y = None
        self.__sv_x = None
        self.__sv_y = None

        self.ints: list[list[int]] = []

        self.units_set = False
        self.rect = core.Rect.create_empty()
        self.image = core.BCImage.create_empty()

    def load_texs(self):
        """Loads the texture and rect for the part."""
        if self.model is None:
            return
        rct = self.model.tex.get_rect(self.rect_id)
        if rct is not None:
            self.rect = rct

        img = self.model.tex.get_image(self.rect_id)
        if img is not None:
            self.image = img

    def set_rect(self, rect_id: int):
        """Sets the rect ID of the part and loads the rect and texture.

        Args:
            rect_id (int): The rect ID to set the part to.
        """
        self.rect_id = rect_id
        if self.model is not None:
            self.load_texs()

    def get_end_frame(self) -> int:
        """Gets the end frame of the part. Note that this doesn't really work for infinite looping animations.

        Returns:
            int: The end frame of the part.
        """
        if len(self.keyframes_sets) == 0:
            return 0
        return max([keyframes.get_end_frame() for keyframes in self.keyframes_sets])

    def set_action(self, frame_counter: int, keyframes: "core.KeyFrames"):
        """Sets the action of the part. This is used for animations.

        Args:
            frame_counter (int): The current frame of the animation.
            keyframes (core.KeyFrames): The collection of keyframes to use for the animation.
        """
        change_in_value = keyframes.set_action(frame_counter)
        if change_in_value is None:
            return
        try:
            start_frame = keyframes.keyframes[0].frame
        except IndexError:
            return
        if frame_counter < start_frame:
            return
        mod = keyframes.modification_type
        if mod == core.AnimModificationType.PARENT:
            self.parent_id = change_in_value
            self.set_parent_by_id(self.parent_id)
        elif mod == core.AnimModificationType.ID:
            self.unit_id = change_in_value
        elif mod == core.AnimModificationType.SPRITE:
            self.rect_id = change_in_value
            self.set_rect(self.rect_id)
        elif mod == core.AnimModificationType.Z_ORDER and self.model is not None:
            self.z_depth = change_in_value * len(self.model.mamodel.parts) + self.index
        elif mod == core.AnimModificationType.POS_X:
            self.x = change_in_value + self.pos_x_orig
        elif mod == core.AnimModificationType.POS_Y:
            self.y = change_in_value + self.pos_y_orig
        elif mod == core.AnimModificationType.PIVOT_X:
            self.pivot_x = change_in_value + self.pivot_x_orig
        elif mod == core.AnimModificationType.PIVOT_Y:
            self.pivot_y = change_in_value + self.pivot_y_orig
        elif mod == core.AnimModificationType.SCALE_UNIT:
            self.gsca = change_in_value
            self.calc_scale()
        elif mod == core.AnimModificationType.SCALE_X:
            self.scale_x = int(change_in_value * self.scale_x_orig / self.scale_unit)
            self.calc_scale()
        elif mod == core.AnimModificationType.SCALE_Y:
            self.scale_y = int(change_in_value * self.scale_y_orig / self.scale_unit)
            self.calc_scale()
        elif mod == core.AnimModificationType.ANGLE:
            self.rotation = change_in_value + self.rotation_orig
            self.set_rotation(self.rotation)
        elif mod == core.AnimModificationType.OPACITY:
            self.alpha = int(change_in_value * self.alpha_orig / self.alpha_unit)
            self.set_alpha(self.alpha)
        elif mod == core.AnimModificationType.H_FLIP:
            self.h_flip = change_in_value
        elif mod == core.AnimModificationType.V_FLIP:
            self.v_flip = change_in_value

    def calc_scale(self):
        """Calculates the real scale of the part."""
        gsca = self.gsca / self.scale_unit
        self.real_scale_x = (self.scale_x / self.scale_unit) * gsca
        self.real_scale_y = (self.scale_y / self.scale_unit) * gsca
        self.__scale_x = None
        self.__scale_y = None

    def set_alpha(self, alpha: int):
        """Sets the alpha of the part.

        Args:
            alpha (int): The alpha to set the part to. Should not have been divided by the alpha unit.
        """
        self.alpha = alpha
        alp = alpha / self.alpha_unit
        self.real_alpha = alp

    def set_rotation(self, rotation: int):
        """Sets the rotation of the part.

        Args:
            rotation (int): The rotation to set the part to. Should be in degrees without dividing by the angle unit.
        """
        self.rotation = rotation
        self.real_rotation = rotation / self.angle_unit

    @staticmethod
    def from_data(data: list[str], index: int) -> "ModelPart":
        """Creates a ModelPart from a list of data.

        Args:
            data (list[core.Data]): The data to use to create the ModelPart.
            index (int): The index of the part.

        Returns:
            ModelPart: The created ModelPart.
        """
        parent_id = int(data[0])
        unit_id = int(data[1])
        cut_id = int(data[2])
        z_depth = int(data[3])
        x = int(data[4])
        y = int(data[5])
        pivot_x = int(data[6])
        pivot_y = int(data[7])
        scale_x = int(data[8])
        scale_y = int(data[9])
        rotation = int(data[10])
        alpha = int(data[11])
        glow = int(data[12])
        try:
            name = data[13]
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

    def to_data(self) -> list[str]:
        """Converts the ModelPart to a list of data.

        Returns:
            list[str]: The list of data.
        """
        data: list[str] = [
            str(self.parent_id),
            str(self.unit_id),
            str(self.rect_id),
            str(self.z_depth),
            str(self.x),
            str(self.y),
            str(self.pivot_x),
            str(self.pivot_y),
            str(self.scale_x),
            str(self.scale_y),
            str(self.rotation),
            str(self.alpha),
            str(self.glow),
        ]
        if self.name:
            data.append(self.name)
        return data

    def draw_part(
        self,
        painter: "QtGui.QPainter",
        base_x: float,
        base_y: float,
        draw_overlay: bool = False,
        just_overlay: bool = False,
    ):
        """Draws the part.

        Args:
            painter (QtGui.QPainter): The painter to use to draw the part on.
            base_x (float): A base scale on the x axis. Used for zooming.
            base_y (float): A base scale on the y axis. Used for zooming.
            draw_overlay (bool, optional): Whether to draw the overlay. Defaults to False.
            just_overlay (bool, optional): Whether to only draw the overlay. Defaults to False.
        """
        self.__scale_x = None
        self.__scale_y = None
        in_valid = self.parent_id < 0 or self.unit_id < 0
        if in_valid and not draw_overlay:
            return
        rct = self.rect

        current_transform = painter.transform()
        scale_x, scale_y = self.get_recursive_scale()
        matrix = self.transform([0.1, 0.0, 0.0, 0.0, 0.1, 0.0], base_x, base_y)

        scx_bx = scale_x * base_x
        scy_by = scale_y * base_y

        flip_x = -1 if scale_x < 0 else 1
        flip_y = -1 if scale_y < 0 else 1
        t_piv_x = self.pivot_x * scx_bx * flip_x
        t_piv_y = self.pivot_y * scy_by * flip_y

        m0 = matrix[0] * flip_x
        m3 = matrix[3] * flip_x
        m1 = matrix[1] * flip_y
        m4 = matrix[4] * flip_y

        sc_w = rct.width * scx_bx
        sc_h = rct.height * scy_by
        painter.setTransform(
            QtGui.QTransform(m0, m3, m1, m4, matrix[2], matrix[5]),
            True,
        )
        if not in_valid and not just_overlay:
            alpha = self.get_recursive_alpha()
            self.draw_img(
                self.image,
                (t_piv_x, t_piv_y),
                (sc_w, sc_h),
                alpha,
                painter,
            )
            if self.glow_support:
                painter.setCompositionMode(
                    QtGui.QPainter.CompositionMode.CompositionMode_SourceOver
                )
            if alpha != 1.0:
                painter.setOpacity(1.0)
        if draw_overlay:
            self.draw_part_overlay(painter, t_piv_x, t_piv_y, sc_w, sc_h)
        painter.setTransform(current_transform)

    def draw_part_overlay(
        self,
        painter: "QtGui.QPainter",
        t_piv_x: float,
        t_piv_y: float,
        sc_w: float,
        sc_h: float,
    ):
        """Draws the overlay for the part.

        Args:
            painter (QtGui.QPainter): The painter to use to draw the overlay on.
            t_piv_x (float): The x position of the pivot.
            t_piv_y (float): The y position of the pivot.
            sc_w (float): The width of the part.
            sc_h (float): The height of the part.
        """
        radius = 50

        x_pos1 = -t_piv_x
        y_pos1 = -t_piv_y
        current_pen = painter.pen()
        painter.setPen(QtGui.QPen(QtGui.QColor(255, 0, 0), 10))
        painter.drawRect(
            QtCore.QRectF(
                x_pos1,
                y_pos1,
                abs(sc_w),
                abs(sc_h),
            )
        )
        painter.setBrush(QtGui.QBrush(QtGui.QColor(255, 0, 0, 255)))
        painter.drawEllipse(
            QtCore.QPointF(0, 0),
            radius,
            radius,
        )

        painter.setPen(current_pen)

    def draw_img(
        self,
        img: "core.BCImage",
        pivot: tuple[float, float],
        size: tuple[float, float],
        alpha: float,
        painter: "QtGui.QPainter",
    ):
        """Draws the part's image.

        Args:
            img (core.BCImage): The image to draw.
            pivot (tuple[float, float]): The pivot of the image.
            size (tuple[float, float]): The size of the image.
            alpha (float): The alpha of the image.
            glow (int): The composition mode of the image. -1, 1, 2, or 3 is plus
            painter (QtGui.QPainter): The painter to use to draw the image on.
        """
        painter.setOpacity(alpha)

        if self.glow_support:
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
        """Gets the flip values for the part.

        Args:
            scale_x (float): The scale on the x axis.
            scale_y (float): The scale on the y axis.

        Returns:
            tuple[int, int]: The flip values for the part. 1 is no flip, -1 is flip.
        """
        flip_x = scale_x < 0
        flip_y = scale_y < 0
        return (
            -1 if flip_x else 1,
            -1 if flip_y else 1,
        )

    def transform(
        self,
        matrix: list[float],
        sizer_x: float,
        sizer_y: float,
    ) -> list[float]:
        """Transforms the part. Recursively calls the parent's transform method.

        Args:
            matrix (list[float]): The matrix to transform the part by.
            sizer_x (float): The multiplier for the x axis.
            sizer_y (float): The multiplier for the y axis.
        """

        siz_x, siz_y = sizer_x, sizer_y
        if self.parent is not None:
            matrix = self.parent.transform(matrix, sizer_x, sizer_y)
            scale_x, scale_y = self.parent.get_recursive_scale()
            siz_x = scale_x * sizer_x
            siz_y = scale_y * sizer_y

        m0, m1, m2, m3, m4, m5 = matrix

        if self.index != 0:
            t_pos_x = self.x * siz_x
            t_pos_y = self.y * siz_y
            m2 += (m0 * t_pos_x) + (m1 * t_pos_y)
            m5 += (m3 * t_pos_x) + (m4 * t_pos_y)
        else:
            if self.ints:
                data = self.ints[0]
            else:
                data = [0, 0, 0, 0]
            p0_x, p0_y = self.get_base_size(False)
            shi_x = data[2] * p0_x
            shi_y = data[3] * p0_y
            p3_x = shi_x * sizer_x
            p3_y = shi_y * sizer_y

            p0_x, p0_y = self.get_recursive_scale()
            px = self.pivot_x * p0_x * sizer_x
            py = self.pivot_y * p0_y * sizer_y
            x = px - p3_x
            y = py - p3_y
            m2 += (m0 * x) + (m1 * y)
            m5 += (m3 * x) + (m4 * y)

        if self.rotation != 0:
            degrees = self.real_rotation * 360
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

        return [m0, m1, m2, m3, m4, m5]

    def get_base_size(self, parent: bool) -> tuple[float, float]:
        """Gets the base size of the part.

        Args:
            parent (bool): If the call is made from the parent.

        Returns:
            tuple[float, float]: The base size of the part.
        """
        if self.__sv_x is not None and self.__sv_y is not None:
            return self.__sv_x, self.__sv_y
        signum_x = 1 if self.scale_x >= 0 else -1
        signum_y = 1 if self.scale_y >= 0 else -1
        if parent:
            if self.parent is not None:
                size_x, size_y = self.parent.get_base_size(True)
                self.__sv_x = size_x * signum_x
                self.__sv_y = size_y * signum_y
                return self.__sv_x, self.__sv_y
            self.__sv_x = signum_x
            self.__sv_y = signum_y
            return self.__sv_x, self.__sv_y
        if self.ints:
            part_id = self.ints[0][0]
        else:
            part_id = -1
        if part_id == -1:
            self.__sv_x = self.real_scale_x
            self.__sv_y = self.real_scale_y
            return self.__sv_x, self.__sv_y
        if part_id == self.index:
            self.__sv_x = self.real_scale_x
            self.__sv_y = self.real_scale_y
            return self.__sv_x, self.__sv_y
        if self.model is None:
            return 1, 1
        part = self.model.get_part_create(part_id)
        size_x, size_y = part.get_base_size(True)
        size_x *= self.real_scale_x
        size_y *= self.real_scale_y
        self.__sv_x = size_x * signum_x
        self.__sv_y = size_y * signum_y
        return self.__sv_x, self.__sv_y

    def get_recursive_scale(self) -> tuple[float, float]:
        """Gets the recursive scale of the part. Recursively calls the parent's
        get_recursive_scale method.

        Returns:
            tuple[float, float]: The recursive scale of the part.
        """
        if self.__scale_x is not None and self.__scale_y is not None:
            return self.__scale_x, self.__scale_y
        current_scale_x = self.real_scale_x
        current_scale_y = self.real_scale_y
        if self.parent is not None:
            parent_scale_x, parent_scale_y = self.parent.get_recursive_scale()
            current_scale_x *= parent_scale_x
            current_scale_y *= parent_scale_y
        self.__scale_x = current_scale_x
        self.__scale_y = current_scale_y
        return current_scale_x, current_scale_y

    def get_recursive_alpha(self) -> float:
        """Gets the recursive alpha of the part. Recursively calls the parent's
        get_recursive_alpha method.

        Returns:
            float: The recursive alpha of the part.
        """
        current_alpha = self.real_alpha
        if self.parent is not None:
            current_alpha *= self.parent.get_recursive_alpha()
        return current_alpha

    def copy(self) -> "ModelPart":
        """Copies the part.

        Returns:
            ModelPart: The copied part.
        """
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

    def set_model(self, model: "core.Model"):
        """Sets the model of the part.

        Args:
            model (model.Model): The model of the part.
        """
        self.model = model

    def set_parent(self, parent: "ModelPart"):
        """Sets the parent of the part.

        Args:
            parent (ModelPart): The parent of the part.
        """
        self.parent = parent

    def set_parent_by_id(self, parent_id: int):
        """Sets the parent of the part by id.

        Args:
            parent_id (int): The id of the parent of the part.
        """
        if parent_id == -1:
            self.parent = None
        else:
            if self.model is None:
                return
            self.parent = self.model.get_part(parent_id)

    def set_children(self, all_parts: list["ModelPart"]):
        """Sets the children of the part.

        Args:
            all_parts (list[ModelPart]): The list of all parts.
        """
        for part in all_parts:
            if part.parent_id == self.index:
                self.children.append(part)

    def set_units(self, scale_unit: int, angle_unit: int, alpha_unit: int):
        """Sets the units of the part.

        Args:
            scale_unit (int): The number to divide the scale by to give a value between 0 and 1.
            angle_unit (int): The number to divide the angle by to give a value between 0 and 1.
            alpha_unit (int): The number to divide the alpha by to give a value between 0 and 1.
        """
        self.scale_unit = scale_unit
        self.gsca = scale_unit
        self.angle_unit = angle_unit
        self.alpha_unit = alpha_unit

        self.real_scale_x = self.scale_x / scale_unit
        self.real_scale_y = self.scale_y / scale_unit
        self.real_rotation = self.rotation / angle_unit
        self.real_alpha = self.alpha / alpha_unit

        self.units_set = True

    def set_keyframes_sets(self, keyframes_sets: list["core.KeyFrames"]):
        """Sets the keyframes sets of the part. Also resets the animation.

        Args:
            keyframes_sets (list[core.KeyFrames]): The keyframes sets of the part.
        """
        self.keyframes_sets = keyframes_sets
        self.reset_anim()

    def set_ints(self, ints: list[list[int]]):
        """Sets the ints of the part. This has something to do with scaling and hitboxes but i haven't really looked into it.

        Args:
            ints (list[list[int]]): The ints of the part.
        """
        self.ints = ints

    def set_unit_id(self, unit_id: int):
        """Sets the unit id of the part. This is the id of the unit that the part belongs to.

        Args:
            unit_id (int): The unit id of the part.
        """
        self.unit_id = unit_id

    @staticmethod
    def create_empty(index: int) -> "ModelPart":
        """Creates an empty part.

        Args:
            index (int): The index of the part in the model.

        Returns:
            ModelPart: The empty part.
        """
        return ModelPart(index, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, "")

    def reset_anim(self):
        """Resets the animation of the part to the original values."""

        self.x = self.pos_x_orig
        self.y = self.pos_y_orig
        self.pivot_x = self.pivot_x_orig
        self.pivot_y = self.pivot_y_orig
        self.alpha = self.alpha_orig
        self.rotation = self.rotation_orig
        self.scale_x = self.scale_x_orig
        self.scale_y = self.scale_y_orig
        self.parent_id = self.parent_id_orig
        self.set_parent_by_id(self.parent_id)
        self.z_depth = self.z_depth_orig
        self.unit_id = self.unit_id_orig
        self.rect_id = self.rect_id_orig
        self.set_rect(self.rect_id)

        self.real_alpha = self.alpha / self.alpha_unit
        self.real_rotation = self.rotation / self.angle_unit
        self.real_scale_x = self.scale_x / self.scale_unit
        self.real_scale_y = self.scale_y / self.scale_unit

    def get_all_children(self) -> list["ModelPart"]:
        """Gets all the children of the part.

        Returns:
            list[ModelPart]: The list of all the children of the part.
        """
        children: list["ModelPart"] = []
        for child in self.children:
            children.append(child)
            children.extend(child.get_all_children())
        return children

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies the data from the dict to the part.

        Args:
            dict_data (dict[str, Any]): The data to apply to the part.
        """
        x = dict_data.get("x")
        if x is not None:
            self.x = x
        y = dict_data.get("y")
        if y is not None:
            self.y = y
        pivot_x = dict_data.get("pivot_x")
        if pivot_x is not None:
            self.pivot_x = pivot_x
        pivot_y = dict_data.get("pivot_y")
        if pivot_y is not None:
            self.pivot_y = pivot_y
        scale_x = dict_data.get("scale_x")
        if scale_x is not None:
            self.scale_x = scale_x
        scale_y = dict_data.get("scale_y")
        if scale_y is not None:
            self.scale_y = scale_y
        rotation = dict_data.get("rotation")
        if rotation is not None:
            self.rotation = rotation
        alpha = dict_data.get("alpha")
        if alpha is not None:
            self.alpha = alpha
        parent_id = dict_data.get("parent_id")
        if parent_id is not None:
            self.parent_id = parent_id
            self.set_parent_by_id(self.parent_id)
        z_depth = dict_data.get("z_depth")
        if z_depth is not None:
            self.z_depth = z_depth
        unit_id = dict_data.get("unit_id")
        if unit_id is not None:
            self.unit_id = unit_id
        rect_id = dict_data.get("rect_id")
        if rect_id is not None:
            self.rect_id = rect_id
            self.set_rect(self.rect_id)

        if self.units_set:
            self.real_alpha = self.alpha / self.alpha_unit
            self.real_rotation = self.rotation / self.angle_unit
            self.real_scale_x = self.scale_x / self.scale_unit
            self.real_scale_y = self.scale_y / self.scale_unit

    def to_dict(self) -> dict[str, Any]:
        """Converts the part to a dictionary.

        Returns:
            dict[str, Any]: The dictionary of the part.
        """
        return {
            "x": self.x,
            "y": self.y,
            "pivot_x": self.pivot_x,
            "pivot_y": self.pivot_y,
            "scale_x": self.scale_x,
            "scale_y": self.scale_y,
            "rotation": self.rotation,
            "alpha": self.alpha,
            "parent_id": self.parent_id,
            "z_depth": self.z_depth,
            "unit_id": self.unit_id,
            "rect_id": self.rect_id,
        }

    def flip_x(self):
        """Flips the part horizontally."""
        if self.index == 0:
            self.scale_x = -self.scale_x
            self.scale_x_orig = -self.scale_x_orig
        self.rotation = -self.rotation
        self.rotation_orig = -self.rotation_orig

    def flip_y(self):
        """Flips the part vertically."""
        if self.index == 0:
            self.scale_y = -self.scale_y
            self.scale_y_orig = -self.scale_y_orig
        self.rotation = -self.rotation
        self.rotation_orig = -self.rotation_orig
