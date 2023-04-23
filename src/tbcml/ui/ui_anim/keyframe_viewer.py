from PyQt5 import QtWidgets, QtCore, QtGui
from tbcml.core import locale_handler, anim
from tbcml.ui import utils
from typing import Callable, Optional


class PartGraphDrawer(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        part: anim.model_part.ModelPart,
        keyframes: anim.unit_animation.KeyFrames,
        clock: utils.clock.Clock,
        width: int = 500,
    ):
        super(PartGraphDrawer, self).__init__(parent)
        self.model = model
        self.part = part
        self.keyframes = keyframes
        self.clock = clock
        self.width_ = width
        self.selected_keyframe = None
        self.clock.connect(self.update)

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()
        self.setup_data()

    def disconnect_clock(self):
        self.clock.disconnect(self.update)

    def setup_ui(self):
        self.setObjectName("part_graph_drawer")
        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._layout.setColumnStretch(0, 1)
        self._layout.setRowStretch(0, 1)

        self.setMinimumSize(self.width_, 100)

        self.setMouseTracking(True)

    def setup_data(self):
        self.total_width = self.width()
        self.fixed_height = 60
        self.y_offset = 20
        self.x_offset = 20

        self.calc()

    def calc(self):
        self.data: dict[int, tuple[int, int]] = {}
        self.total_frames = self.model.get_total_frames()
        self.frame_width = self.total_width // self.total_frames
        self.pen = QtGui.QPen()
        self.pen.setWidth(2)
        self.pen.setColor(QtGui.QColor(0, 0, 0))
        self.calc_maxes()
        self.calc_true()
        self.update()

    def paintEvent(self, a0: QtGui.QPaintEvent) -> None:
        super(PartGraphDrawer, self).paintEvent(a0)

        self.paint()

    def paint(self):
        self.painter = QtGui.QPainter(self)

        self.painter.setPen(self.pen)

        self.draw_0_line()
        self.draw_max_min_lines()

        self.draw_graph_true()

        self.draw_current_frame_line()

        self.painter.end()

    def calc_maxes(self):
        change_in_value = 0
        self.max_change_in_value = 0
        self.min_change_in_value = 0
        self.original_change: list[int] = []
        for frame in range(self.total_frames):
            for keyframe_index in range(len(self.keyframes.keyframes) - 1):
                current_keyframe = self.keyframes.keyframes[keyframe_index]
                next_keyframe = self.keyframes.keyframes[keyframe_index + 1]
                current_keyframe_start_frame = current_keyframe.frame
                next_keyframe_start_frame = next_keyframe.frame
                if (
                    frame < current_keyframe_start_frame
                    or frame >= next_keyframe_start_frame
                ):
                    continue
                else:
                    change_in_value = int(self.keyframes.ease(keyframe_index, frame))
                    break
            if self.keyframes.keyframes:
                last_keyframe = self.keyframes.keyframes[-1]
                if frame >= last_keyframe.frame:
                    change_in_value = int(last_keyframe.change)
            self.max_change_in_value = max(self.max_change_in_value, change_in_value)
            self.min_change_in_value = min(self.min_change_in_value, change_in_value)

            self.original_change.append(change_in_value)

        height_needed = self.max_change_in_value - self.min_change_in_value
        if height_needed == 0:
            height_needed = 1
        self.scale_factor = self.fixed_height / height_needed

    def calc_true(self):
        change_in_value = 0
        self.changed: list[int] = []

        frame_width = self.frame_width
        if frame_width == 0:
            frame_width = 1

        for frame in range(self.total_frames):
            for keyframe_index in range(len(self.keyframes.keyframes) - 1):
                current_keyframe = self.keyframes.keyframes[keyframe_index]
                next_keyframe = self.keyframes.keyframes[keyframe_index + 1]
                if frame == next_keyframe.frame:
                    change_in_value = int(next_keyframe.change)
                    break

                current_keyframe_start_frame = current_keyframe.frame
                next_keyframe_start_frame = next_keyframe.frame
                if (
                    frame < current_keyframe_start_frame
                    or frame >= next_keyframe_start_frame
                ):
                    continue
                else:
                    change_in_value = int(self.keyframes.ease(keyframe_index, frame))
                    break

            chng = int((self.max_change_in_value - change_in_value) * self.scale_factor)
            self.changed.append(chng)
            x_pos = (frame * frame_width) + self.x_offset
            y_pos = chng + self.y_offset
            self.data[frame] = (x_pos, y_pos)

    def get_keyframe(self, frame: int) -> Optional["anim.unit_animation.KeyFrame"]:
        for keyframe in self.keyframes.keyframes:
            if keyframe.frame == frame:
                return keyframe
        return None

    def draw_graph_true(self):
        for frame in range(self.total_frames):
            if frame != 0:
                x_pos, y_pos = self.data[frame]
                previous_x_pos, previous_y_pos = self.data[frame - 1]

                if y_pos == previous_y_pos:
                    self.painter.drawLine(x_pos, y_pos, previous_x_pos, previous_y_pos)
                else:
                    self.painter.drawLine(x_pos, y_pos, x_pos, previous_y_pos)
                    self.painter.drawLine(
                        x_pos, previous_y_pos, previous_x_pos, previous_y_pos
                    )

            keyframe = self.get_keyframe(frame)
            if keyframe is not None:
                self.draw_keyframe(keyframe)

    def draw_keyframe(self, keyframe: "anim.unit_animation.KeyFrame"):
        frame = keyframe.frame
        x_pos = (frame * self.frame_width) + self.x_offset
        y_pos = self.changed[frame] + self.y_offset
        current_pen = self.painter.pen()
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen_color = QtGui.QColor(0, 255, 255)
        brush_color = QtGui.QColor(0, 255, 255, 100)
        if self.selected_keyframe is not None and keyframe == self.selected_keyframe:
            pen_color = QtGui.QColor(255, 255, 0)
            brush_color = QtGui.QColor(255, 255, 0, 100)

        pen.setColor(pen_color)
        self.painter.setPen(pen)
        self.painter.setBrush(brush_color)
        self.painter.drawEllipse(x_pos - 4, y_pos - 4, 8, 8)
        self.painter.setPen(current_pen)

    def draw_current_frame_line(self):
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(QtGui.QColor(255, 0, 0))
        self.painter.setPen(pen)

        current_frame = self.clock.get_frame() % self.total_frames
        x_pos = (current_frame * self.frame_width) + self.x_offset
        y_pos1 = self.y_offset
        y_pos2 = self.fixed_height + self.y_offset
        self.painter.drawLine(
            x_pos,
            y_pos1,
            x_pos,
            y_pos2,
        )

        self.pen.setColor(QtGui.QColor(0, 0, 0))

    def draw_0_line(self):
        current_pen = self.painter.pen()
        grey = QtGui.QColor(200, 200, 200)
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(grey)
        self.painter.setPen(pen)
        x_pos1 = self.x_offset
        x_pos2 = ((self.total_frames) * self.frame_width) + self.x_offset
        y_pos = int((self.max_change_in_value) * self.scale_factor) + self.y_offset
        self.painter.drawLine(
            x_pos1,
            y_pos,
            x_pos2,
            y_pos,
        )
        self.pen.setColor(QtGui.QColor(0, 0, 0))

        # draw the text 0
        self.painter.drawText(
            self.x_offset - 10,
            y_pos + 5,
            "0",
        )
        self.painter.setPen(current_pen)

    def draw_max_min_lines(self):
        self.draw_max_line()
        self.draw_min_line()

    def draw_max_line(self):
        if self.max_change_in_value == 0:
            return
        current_pen = self.painter.pen()
        grey = QtGui.QColor(200, 200, 200)
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(grey)
        self.painter.setPen(pen)
        x_pos1 = self.x_offset
        x_pos2 = ((self.total_frames) * self.frame_width) + self.x_offset
        y_pos = (
            int(
                (self.max_change_in_value - self.max_change_in_value)
                * self.scale_factor
            )
            + self.y_offset
        )
        self.painter.drawLine(
            x_pos1,
            y_pos,
            x_pos2,
            y_pos,
        )
        self.pen.setColor(QtGui.QColor(0, 0, 0))

        # draw the text 0
        self.painter.drawText(
            self.x_offset - 10,
            y_pos + 5,
            str(self.max_change_in_value),
        )
        self.painter.setPen(current_pen)

    def draw_min_line(self):
        if self.min_change_in_value == 0:
            return
        current_pen = self.painter.pen()
        grey = QtGui.QColor(200, 200, 200)
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(grey)
        self.painter.setPen(pen)
        x_pos1 = self.x_offset
        x_pos2 = ((self.total_frames) * self.frame_width) + self.x_offset
        y_pos = (
            int(
                (self.max_change_in_value - self.min_change_in_value)
                * self.scale_factor
            )
            + self.y_offset
        )
        self.painter.drawLine(
            x_pos1,
            y_pos,
            x_pos2,
            y_pos,
        )
        self.pen.setColor(QtGui.QColor(0, 0, 0))

        # draw the text 0
        self.painter.drawText(
            self.x_offset - 10,
            y_pos + 5,
            str(self.min_change_in_value),
        )
        self.painter.setPen(current_pen)

    def get_change_in_value(self) -> int:
        frame = self.clock.get_frame() % self.total_frames
        val = self.original_change[frame]
        return val

    def set_keyframe(self, original_frame: int, new_frame: int, change: float):
        keyframe = self.get_keyframe(original_frame)
        if keyframe is not None:
            keyframe.change = int(change)
            keyframe.frame = new_frame
            self.calc()

    def get_keyframe_poses(self) -> list[int]:
        poses: list[int] = []
        for keyframe in self.keyframes.keyframes:
            frame = keyframe.frame
            pos = (frame * self.frame_width) + self.x_offset
            poses.append(pos)
        return poses

    def get_keyframe_from_pos(
        self, x_pos: int
    ) -> Optional["anim.unit_animation.KeyFrame"]:
        poses = self.get_keyframe_poses()
        for i, pos in enumerate(poses):
            if abs(pos - x_pos) < self.frame_width // 2:
                return self.keyframes.keyframes[i]
        return None

    # select a keyframe if the mouse is clicked over it
    def mousePressEvent(self, a0: QtGui.QMouseEvent):
        x_pos = a0.pos().x()
        y_pos = a0.pos().y()
        keyframe = self.get_keyframe_from_pos(x_pos)
        if keyframe is not None:
            self.selected_keyframe = keyframe
            self.selected_keyframe_original_frame = keyframe.frame
            self.selected_keyframe_original_change = keyframe.change
            self.selected_keyframe_original_x_pos = x_pos
            self.selected_keyframe_original_y_pos = y_pos
            self.selected_keyframe_original_value = self.get_change_in_value()
            self.update()
        else:
            self.selected_keyframe = None

    def select_next_keyframe(self):
        if self.selected_keyframe is None:
            return
        next_keyframe = self.get_next_keyframe(self.selected_keyframe)
        if next_keyframe is not None:
            self.selected_keyframe = next_keyframe
            self.update()

    def select_previous_keyframe(self):
        if self.selected_keyframe is None:
            return
        previous_keyframe = self.get_previous_keyframe(self.selected_keyframe)
        if previous_keyframe is not None:
            self.selected_keyframe = previous_keyframe
            self.update()

    def get_next_keyframe(
        self, keyframe: anim.unit_animation.KeyFrame
    ) -> Optional[anim.unit_animation.KeyFrame]:
        next_keyframe = None
        for i in range(len(self.keyframes.keyframes)):
            if self.keyframes.keyframes[i] == keyframe:
                if i + 1 < len(self.keyframes.keyframes):
                    next_keyframe = self.keyframes.keyframes[i + 1]
                break
        return next_keyframe

    def get_previous_keyframe(
        self, keyframe: anim.unit_animation.KeyFrame
    ) -> Optional[anim.unit_animation.KeyFrame]:
        previous_keyframe = None
        for i in range(len(self.keyframes.keyframes)):
            if self.keyframes.keyframes[i] == keyframe:
                if i - 1 >= 0:
                    previous_keyframe = self.keyframes.keyframes[i - 1]
                break
        return previous_keyframe

    def remove_keyframe(self, keyframe: anim.unit_animation.KeyFrame):
        self.keyframes.remove_keyframe(keyframe)
        self.calc()

    # move the keyframe with arrow keys
    def key_press_event(self, a0: QtGui.QKeyEvent):
        if self.selected_keyframe is None:
            return

        if a0.key() == QtCore.Qt.Key.Key_Escape:
            self.selected_keyframe.frame = self.selected_keyframe_original_frame
            self.selected_keyframe.change = self.selected_keyframe_original_change
            self.selected_keyframe = None
            self.update()
            return

        if a0.key() == QtCore.Qt.Key.Key_Delete:
            selected_keyframe = self.selected_keyframe
            self.select_next_keyframe()
            self.remove_keyframe(selected_keyframe)
            self.update()
            return

        moved = False

        if a0.key() == QtCore.Qt.Key.Key_Left:
            if self.can_move_left(self.selected_keyframe):
                self.selected_keyframe.frame -= 1
                moved = True
        if a0.key() == QtCore.Qt.Key.Key_Right:
            if self.can_move_right(self.selected_keyframe):
                self.selected_keyframe.frame += 1
                moved = True
        if a0.key() == QtCore.Qt.Key.Key_Up:
            self.selected_keyframe.change += 1
            moved = True
        if a0.key() == QtCore.Qt.Key.Key_Down:
            self.selected_keyframe.change -= 1
            moved = True
        if moved:
            self.calc()

    def can_move_left(self, keyframe: anim.unit_animation.KeyFrame) -> bool:
        if keyframe.frame == 0:
            return False
        previous_keyframe = self.get_keyframe(keyframe.frame - 1)
        if previous_keyframe is not None:
            return False
        return True

    def can_move_right(self, keyframe: anim.unit_animation.KeyFrame) -> bool:
        next_keyframe = self.get_keyframe(keyframe.frame + 1)
        if next_keyframe is not None:
            return False
        return True


class PartAnimWidget(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        part: anim.model_part.ModelPart,
        keyframes: anim.unit_animation.KeyFrames,
        clock: utils.clock.Clock,
        width: int,
        update_callback: Callable[[], None],
    ):
        super(PartAnimWidget, self).__init__(parent)
        self.model = model
        self.part = part
        self.keyframes = keyframes
        self.clock = clock
        self.width_ = width
        self.update_callback = update_callback

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("keyframes_widget")
        self._layout = QtWidgets.QVBoxLayout(self)

        self.modification_label = QtWidgets.QLabel(self)
        self.modification_label.setText(
            self.locale_manager.get_key(
                f"modification_{self.keyframes.modification_type.value}"
            )
        )
        self._layout.addWidget(self.modification_label)

        self.keyframes_graph = PartGraphDrawer(
            self.model,
            self,
            self.part,
            self.keyframes,
            self.clock,
            self.width_,
        )
        self._layout.addWidget(self.keyframes_graph)

        self.change_in_value_label = QtWidgets.QLabel(self)
        self.change_in_value_label.setText(self.locale_manager.get_key("value"))
        self._layout.addWidget(self.change_in_value_label)

        self.change_in_value_spinbox = QtWidgets.QSpinBox(self)
        self.change_in_value_spinbox.setRange(-(2**31), 2**31 - 1)
        self.change_in_value_spinbox.setValue(
            self.keyframes_graph.get_change_in_value()
        )
        self.change_in_value_spinbox.setReadOnly(True)
        self._layout.addWidget(self.change_in_value_spinbox)
        self.clock.connect(self.update_spin_box)

        self._layout.addStretch(1)

    def set_frame(self, frame: int):
        self.update_spin_box()
        self.keyframes_graph.update()

    def disconnect_clock(self):
        self.clock.disconnect(self.update_spin_box)
        self.keyframes_graph.disconnect_clock()

    def update_spin_box(self):
        self.change_in_value_spinbox.setValue(
            self.keyframes_graph.get_change_in_value()
        )
        self.update_callback()

    def key_press_event(self, a0: QtGui.QKeyEvent) -> None:
        self.keyframes_graph.key_press_event(a0)
        self.update_spin_box()
