from typing import Any, Optional
from bcml.core.anim import rect, anim_transformer, unit_animation, model
from bcml.core import io
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
        self.keyframes_sets: list[unit_animation.KeyFrames] = []
        self.model: model.Model
        self.scale_unit: int
        self.angle_unit: int
        self.alpha_unit: int

    def load_texs(self):
        """Loads the texture and rect for the part."""
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
        """Sets the rect ID of the part and loads the rect and texture.

        Args:
            rect_id (int): The rect ID to set the part to.
        """
        self.rect_id = rect_id
        self.load_texs()

    def get_end_frame(self) -> int:
        """Gets the end frame of the part. Note that this doesn't really work for infinite looping animations.

        Returns:
            int: The end frame of the part.
        """
        if len(self.keyframes_sets) == 0:
            return 0
        return max([keyframes.get_end_frame() for keyframes in self.keyframes_sets])

    def set_action(self, frame_counter: int, keyframes: unit_animation.KeyFrames):
        """Sets the action of the part. This is used for animations.

        Args:
            frame_counter (int): The current frame of the animation.
            keyframes (unit_animation.PartAnim): The collection of keyframes to use for the animation.
        """
        change_in_value = keyframes.set_action(frame_counter)

        start_frame = keyframes.keyframes[0].frame
        if frame_counter >= start_frame:
            mod = keyframes.modification_type
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

    def set_scale(self, scale_x: int, scale_y: int):
        """Sets the scale of the part.

        Args:
            scale_x (int): Scale on the x axis. Should not have been divided by the scale unit.
            scale_y (int): Scale on the y axis. Should not have been divided by the scale unit.
        """
        self.scale_x = scale_x
        self.scale_y = scale_y
        scl_x = scale_x / self.scale_unit
        scl_y = scale_y / self.scale_unit
        gcsa = self.gsca / self.scale_unit
        self.real_scale_x = scl_x * gcsa
        self.real_scale_y = scl_y * gcsa

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
    def from_data(data: list["io.data.Data"], index: int) -> "ModelPart":
        """Creates a ModelPart from a list of data.

        Args:
            data (list[io.data.Data]): The data to use to create the ModelPart.
            index (int): The index of the part.

        Returns:
            ModelPart: The created ModelPart.
        """
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
        """Converts the ModelPart to a list of data.

        Returns:
            list[Any]: The list of data.
        """
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
        local: bool = False,
        draw_overlay: bool = False,
        just_overlay: bool = False,
    ):
        """Draws the part.

        Args:
            painter (QtGui.QPainter): The painter to use to draw the part on.
            base_x (float): A base scale on the x axis. Used for zooming.
            base_y (float): A base scale on the y axis. Used for zooming.
            local (bool, optional): Whether to not draw it in relation to the parent. Defaults to False.
            draw_overlay (bool, optional): Whether to draw the overlay. Defaults to False.
            just_overlay (bool, optional): Whether to only draw the overlay. Defaults to False.
        """
        img = self.image
        rct = self.rect
        current_transform = painter.transform()
        transformer = anim_transformer.AnimTransformer()
        scale_x, scale_y = self.get_recursive_scale()
        if local:
            self.local_transform(transformer, base_x, base_y)
        else:
            self.transform(transformer, base_x, base_y)

        flip_x, flip_y = self.get_flip(scale_x, scale_y)
        t_piv_x = self.pivot_x * scale_x * flip_x * base_x
        t_piv_y = self.pivot_y * scale_y * flip_y * base_y
        transformer.scale(flip_x, flip_y)
        sc_w = rct.width * scale_x * base_x
        sc_h = rct.height * scale_y * base_y
        painter.setTransform(transformer.to_q_transform(), True)
        if self.parent_id >= 0 and self.unit_id >= 0 and not just_overlay:
            self.draw_img(
                img,
                (t_piv_x, t_piv_y),
                (sc_w, sc_h),
                self.get_recursive_alpha(),
                self.glow,
                painter,
            )
        painter.setOpacity(1.0)
        painter.setCompositionMode(
            QtGui.QPainter.CompositionMode.CompositionMode_SourceOver
        )
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
        img: "io.bc_image.BCImage",
        pivot: tuple[float, float],
        size: tuple[float, float],
        alpha: float,
        glow: int,
        painter: "QtGui.QPainter",
    ):
        """Draws the part's image.

        Args:
            img (io.bc_image.BCImage): The image to draw.
            pivot (tuple[float, float]): The pivot of the image.
            size (tuple[float, float]): The size of the image.
            alpha (float): The alpha of the image.
            glow (int): The composition mode of the image. -1, 1, 2, or 3 is plus
            painter (QtGui.QPainter): The painter to use to draw the image on.
        """
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

    def local_transform(
        self,
        transformer: anim_transformer.AnimTransformer,
        sizer_x: float,
        sizer_y: float,
    ):
        """Transforms the part without regard to the parent.

        Args:
            transformer (anim_transformer.AnimTransformer): The transformer to use to
            sizer_x (float): The multiplier for the x axis.
            sizer_y (float): The multiplier for the y axis.
        """
        scale_x, scale_y = self.get_recursive_scale()
        siz_x = scale_x * sizer_x
        siz_y = scale_y * sizer_y
        t_pos_x = self.x * siz_x
        t_pos_y = self.y * siz_y
        transformer.translate(t_pos_x, t_pos_y)
        transformer.rotate(fraction=self.real_rotation)

    def transform(
        self,
        transformer: anim_transformer.AnimTransformer,
        sizer_x: float,
        sizer_y: float,
    ):
        """Transforms the part. Recursively calls the parent's transform method.

        Args:
            transformer (anim_transformer.AnimTransformer): The transformer to use to
            sizer_x (float): The multiplier for the x axis.
            sizer_y (float): The multiplier for the y axis.
        """
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
        """Gets the base size of the part.

        Args:
            parent (bool): If the call is made from the parent.

        Returns:
            tuple[float, float]: The base size of the part.
        """
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
        """Gets the recursive scale of the part. Recursively calls the parent's
        get_recursive_scale method.

        Returns:
            tuple[float, float]: The recursive scale of the part.
        """
        current_scale_x = self.real_scale_x
        current_scale_y = self.real_scale_y
        if self.parent is not None:
            parent_scale_x, parent_scale_y = self.parent.get_recursive_scale()
            current_scale_x *= parent_scale_x
            current_scale_y *= parent_scale_y
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

    def serialize(self) -> dict[str, Any]:
        """Serializes the part to a dictionary.

        Returns:
            dict[str, Any]: The serialized part.
        """
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
        """Deserializes the part to a ModelPart object.

        Args:
            data (dict[str, Any]): The serialized part.

        Returns:
            ModelPart: The deserialized part.
        """
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

    def __repr__(self) -> str:
        """Gets the string representation of the part.

        Returns:
            str: The string representation of the part.
        """
        return f"ModelPart({self.index}, {self.parent_id}, {self.unit_id}, {self.rect_id}, {self.z_depth}, {self.x}, {self.y}, {self.pivot_x}, {self.pivot_y}, {self.scale_x}, {self.scale_y}, {self.rotation}, {self.alpha}, {self.glow}, {self.name})"

    def __str__(self) -> str:
        """Gets the string representation of the part.

        Returns:
            str: The string representation of the part.
        """
        return repr(self)

    def __eq__(self, other: Any) -> bool:
        """Checks if the part is equal to another object.

        Args:
            other (Any): The other object.

        Returns:
            bool: True if the part is equal to the other object, False otherwise.
        """
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

    def set_model(self, model: "model.Model"):
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

    def set_keyframes_sets(self, keyframes_sets: list["unit_animation.KeyFrames"]):
        """Sets the part animations of the part. The

        Args:
            keyframes_sets (list[unit_animation.PartAnim]): The part animations of the part.
        """
        self.keyframes_sets = keyframes_sets
        self.reset_anim()

    def set_ints(self, ints: list[list[int]]):
        self.ints = ints

    def set_unit_id(self, unit_id: int):
        self.unit_id = unit_id

    @staticmethod
    def create_empty(index: int) -> "ModelPart":
        return ModelPart(index, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, "")

    def reset_anim(self):
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
        children: list["ModelPart"] = []
        for child in self.children:
            children.append(child)
            children.extend(child.get_all_children())
        return children
