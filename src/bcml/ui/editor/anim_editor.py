from PyQt5 import QtWidgets, QtCore, QtGui
from bcml.core import locale_handler, anim
from bcml.ui.editor import anim_viewer
from bcml.ui import utils, main
from typing import Callable


class AnimViewerBox(QtWidgets.QGroupBox):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        anim_id: int,
        frame_tick: Callable[..., None],
    ):
        super(AnimViewerBox, self).__init__(parent)
        self.model = model
        self.anim_id = anim_id
        self.frame_tick = frame_tick

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("anim_viewer_box")
        self._layout = QtWidgets.QGridLayout(self)

        self.anim_label = QtWidgets.QLabel(self)
        self.anim_label.setObjectName("anim_label")
        self.anim_label.setText(self.locale_manager.search_key("anim"))
        self._layout.addWidget(self.anim_label, 0, 0)

        self.anim_viewer = anim_viewer.AnimViewer(
            self.model,
            self,
            self.anim_id,
            False if self.anim_id == 0 else True,
        )
        self._layout.addWidget(self.anim_viewer, 1, 0)

        self._layout.setColumnStretch(0, 1)
        self._layout.setRowStretch(1, 1)

        self.anim_viewer.clock.connect(self.frame_tick)

    def set_overlay_part(self, part_id: int):
        self.anim_viewer.set_overlay_id(part_id)
        self.anim_viewer.update()


class PartViewerBox(QtWidgets.QGroupBox):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        anim_id: int,
        clock: utils.clock.Clock,
    ):
        super(PartViewerBox, self).__init__(parent)
        self.model = model
        self.anim_id = anim_id
        self.clock = clock

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("part_viewer_box")
        self._layout = QtWidgets.QGridLayout(self)

        self.part_label = QtWidgets.QLabel(self)
        self.part_label.setObjectName("part_label")
        self.part_label.setText(self.locale_manager.search_key("part"))
        self._layout.addWidget(self.part_label, 0, 0)

        self.part_viewer = anim_viewer.PartViewer(
            self.model,
            [0],
            self.anim_id,
            self.clock,
            self,
            False if self.anim_id == 0 else True,
            True,
        )
        self._layout.addWidget(self.part_viewer, 1, 0)

        self._layout.setColumnStretch(0, 1)
        self._layout.setRowStretch(1, 1)


class AnimViewerPage(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        anim_id: int,
        update_frame: Callable[..., None],
    ):
        super(AnimViewerPage, self).__init__(parent)
        self.model = model
        self.anim_id = anim_id
        self.update_frame_out = update_frame

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("anim_viewer_page")
        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self.anim_viewer_box = AnimViewerBox(
            self.model,
            self,
            self.anim_id,
            self.frame_tick,
        )
        self._layout.addWidget(self.anim_viewer_box, 0, 0)

        self.part_viewer_box = PartViewerBox(
            self.model,
            self,
            self.anim_id,
            self.anim_viewer_box.anim_viewer.clock,
        )
        self._layout.addWidget(self.part_viewer_box, 0, 1)
        end_frame = self.model.get_end_frame()

        interval = end_frame // 30
        if interval == 0:
            interval = 1

        self.frame_slider_group = QtWidgets.QGroupBox(self)
        self.frame_slider_group.setObjectName("frame_slider_group")
        self.frame_slider_layout = QtWidgets.QVBoxLayout(self.frame_slider_group)
        self.frame_slider = utils.label_slider.LabeledSlider(
            0,
            end_frame,
            interval,
            parent=self,
            value_changed_callback=self.update_frame,
        )
        self.frame_slider.setObjectName("frame_slider")
        self.frame_slider.set_value(0)
        self.frame_slider_layout.addWidget(self.frame_slider)
        self._layout.addWidget(self.frame_slider_group, 1, 0, 1, 2)

        self.play_button = QtWidgets.QPushButton(self)
        self.play_button.setObjectName("play_button")
        self.play_svg = utils.asset_loader.AssetLoader.from_config().load_svg(
            "play.svg"
        )
        self.pause_svg = utils.asset_loader.AssetLoader.from_config().load_svg(
            "pause.svg"
        )
        self.play_button.setIcon(self.pause_svg)
        self.play_button.clicked.connect(self.toggle_play)
        self.button_layout = QtWidgets.QHBoxLayout()
        self.button_layout.addWidget(self.play_button)
        self.button_layout.setContentsMargins(0, 0, 0, 0)
        self.button_layout.setSpacing(0)

        self.seek_back_button = QtWidgets.QPushButton(self)
        self.seek_back_button.setObjectName("seek_back_button")
        self.seek_back_svg = utils.asset_loader.AssetLoader.from_config().load_svg(
            "seek_backward.svg"
        )
        self.seek_back_button.setIcon(self.seek_back_svg)
        self.seek_back_button.clicked.connect(self.seek_backwards)
        self.button_layout.addWidget(self.seek_back_button)

        self.seek_forward_button = QtWidgets.QPushButton(self)
        self.seek_forward_button.setObjectName("seek_forward_button")
        self.seek_forward_svg = utils.asset_loader.AssetLoader.from_config().load_svg(
            "seek_forward.svg"
        )
        self.seek_forward_button.setIcon(self.seek_forward_svg)
        self.seek_forward_button.clicked.connect(self.seek_forward)
        self.button_layout.addWidget(self.seek_forward_button)

        self.button_layout.addStretch(1)
        self.current_frame_label = QtWidgets.QLabel(self)
        self.current_frame_label.setObjectName("current_frame_label")
        self.current_frame_label.setText(
            self.locale_manager.search_key("current_frame")
        )
        self.button_layout.addWidget(self.current_frame_label)
        self.current_frame_spinbox = QtWidgets.QSpinBox(self)
        self.current_frame_spinbox.setObjectName("current_frame_spinbox")
        self.current_frame_spinbox.setRange(0, (2**31) - 1)
        self.current_frame_spinbox.setValue(0)
        self.current_frame_spinbox.valueChanged.connect(self.update_frame)
        self.button_layout.addWidget(self.current_frame_spinbox)
        self.button_layout.addStretch(1)

        self.frame_slider_layout.addLayout(self.button_layout)
        self.frame_slider_layout.addStretch(1)

        self.model.set_part_anims(self.anim_id)

        self.anim_part_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.anim_part_splitter.addWidget(self.anim_viewer_box)
        self.anim_part_splitter.addWidget(self.part_viewer_box)
        self._layout.addWidget(self.anim_part_splitter, 0, 0)

        self._layout.setColumnStretch(0, 1)
        self._layout.setRowStretch(0, 1)

    def toggle_play(self):
        if self.anim_viewer_box.anim_viewer.clock.is_playing():
            self.anim_viewer_box.anim_viewer.clock.stop()
            self.play_button.setIcon(QtGui.QIcon(self.play_svg))
        else:
            self.anim_viewer_box.anim_viewer.clock.start()
            self.play_button.setIcon(QtGui.QIcon(self.pause_svg))

    def frame_tick(self):
        self.frame_slider.set_value(self.anim_viewer_box.anim_viewer.clock.get_frame())
        try:
            self.current_frame_spinbox.setValue(
                self.anim_viewer_box.anim_viewer.clock.get_frame()
            )
        except OverflowError:
            pass

    def view_parts(self, part_ids: list[int]):
        self.part_viewer_box.part_viewer.part_ids = part_ids
        self.part_viewer_box.part_viewer.update()
        self.anim_viewer_box.set_overlay_part(part_ids[0])

    def seek_backwards(self):
        self.anim_viewer_box.anim_viewer.clock.decrement()
        self.update_frame(self.anim_viewer_box.anim_viewer.clock.get_frame())
        self.frame_tick()

    def seek_forward(self):
        self.anim_viewer_box.anim_viewer.clock.increment()
        self.update_frame(self.anim_viewer_box.anim_viewer.clock.get_frame())
        self.frame_tick()

    def update_frame(self, frame: int):
        self.update_frame_out(frame)
        self.frame_tick()


class PartGraphDrawer(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        part: anim.model_part.ModelPart,
        part_anim: anim.unit_animation.KeyFrames,
        clock: utils.clock.Clock,
        width: int = 500,
    ):
        super(PartGraphDrawer, self).__init__(parent)
        self.model = model
        self.part = part
        self.part_anim = part_anim
        self.current_frame = clock.get_frame()
        self.clock = clock
        self.width_ = width
        self.clock.connect(self.update_frame)

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()
        self.setup_data()

    def disconnect_clock(self):
        self.clock.disconnect(self.update_frame)

    def setup_ui(self):
        self.setObjectName("part_graph_drawer")
        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._layout.setColumnStretch(0, 1)
        self._layout.setRowStretch(0, 1)

        self.setMinimumSize(self.width_, 100)

    def setup_data(self):
        self.end_frame = self.model.get_end_frame()
        self.total_width = self.width()
        self.frame_width = self.total_width // self.end_frame
        self.fixed_height = 60
        self.y_offset = 20
        self.x_offset = 20

        self.calc_maxes()
        self.calc_true()

    def set_frame(self, frame: int):
        self.current_frame = frame
        self.update()

    def update_frame(self):
        self.current_frame += 1
        self.update()

    def paintEvent(self, a0: QtGui.QPaintEvent) -> None:
        super(PartGraphDrawer, self).paintEvent(a0)
        self.painter = QtGui.QPainter(self)

        self.pen = QtGui.QPen()
        self.pen.setWidth(2)
        self.pen.setColor(QtGui.QColor(0, 0, 0))
        self.painter.setPen(self.pen)

        self.draw_graph_true()
        self.draw_overlay()

        self.painter.end()

    def calc_maxes(self):
        change_in_value = 0
        self.max_change_in_value = 0
        self.min_change_in_value = 0
        self.original_change: list[int] = []
        for frame in range(self.end_frame):
            for keyframe_index in range(len(self.part_anim.keyframes) - 1):
                current_keyframe = self.part_anim.keyframes[keyframe_index]
                next_keyframe = self.part_anim.keyframes[keyframe_index + 1]
                current_keyframe_start_frame = current_keyframe.frame
                next_keyframe_start_frame = next_keyframe.frame
                if (
                    frame < current_keyframe_start_frame
                    or frame >= next_keyframe_start_frame
                ):
                    continue
                else:
                    change_in_value = int(self.part_anim.ease(keyframe_index, frame))
                    break
            self.max_change_in_value = max(self.max_change_in_value, change_in_value)
            self.min_change_in_value = min(self.min_change_in_value, change_in_value)

            self.original_change.append(change_in_value)

        height_needed = self.max_change_in_value - self.min_change_in_value
        if height_needed == 0:
            height_needed = 1
        self.scale_factor = self.fixed_height / height_needed

    def calc_true(self):
        change_in_value = 0
        previous_value = None
        self.changed: list[tuple[int, int]] = []

        end_frame = self.end_frame

        for frame in range(end_frame):
            for keyframe_index in range(len(self.part_anim.keyframes) - 1):
                current_keyframe = self.part_anim.keyframes[keyframe_index]
                next_keyframe = self.part_anim.keyframes[keyframe_index + 1]
                current_keyframe_start_frame = current_keyframe.frame
                next_keyframe_start_frame = next_keyframe.frame
                if (
                    frame < current_keyframe_start_frame
                    or frame >= next_keyframe_start_frame
                ):
                    continue
                else:
                    change_in_value = int(self.part_anim.ease(keyframe_index, frame))
                    break

            if previous_value is None:
                previous_value = change_in_value

            chng = int((self.max_change_in_value - change_in_value) * self.scale_factor)
            png = int((self.max_change_in_value - previous_value) * self.scale_factor)
            self.changed.append((chng, png))
            previous_value = change_in_value

    def draw_graph_true(self):
        end_frame = self.end_frame
        frame_width = self.frame_width
        if frame_width == 0:
            frame_width = 1
        for frame in range(1, end_frame):
            # draw line from previous frame to current fram using only horizontal and vertical lines
            # draw a horizontal line if the previous frame and current frame have the same y value
            # draw a vertical line and then a horizontal line if the previous frame and current frame have different y values
            # draw a vertical line if the previous frame and current frame have the same x value
            # draw a horizontal line and then a vertical line if the previous frame and current frame have different x values
            previous_frame = frame - 1
            previous_frame_x = (previous_frame * frame_width) + self.x_offset
            previous_frame_y = self.changed[previous_frame][0] + self.y_offset
            current_frame_x = (frame * frame_width) + self.x_offset
            current_frame_y = self.changed[frame][0] + self.y_offset

            if previous_frame_x == current_frame_x:
                self.painter.drawLine(
                    previous_frame_x,
                    previous_frame_y,
                    current_frame_x,
                    current_frame_y,
                )
            elif previous_frame_y == current_frame_y:
                self.painter.drawLine(
                    previous_frame_x,
                    previous_frame_y,
                    current_frame_x,
                    current_frame_y,
                )
            else:
                self.painter.drawLine(
                    previous_frame_x,
                    previous_frame_y,
                    previous_frame_x,
                    current_frame_y,
                )
                self.painter.drawLine(
                    previous_frame_x,
                    current_frame_y,
                    current_frame_x,
                    current_frame_y,
                )

    def draw_current_frame_line(self):
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(QtGui.QColor(255, 0, 0))
        self.painter.setPen(pen)

        current_frame = self.clock.get_frame() % self.end_frame
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
        grey = QtGui.QColor(200, 200, 200)
        pen = QtGui.QPen()
        pen.setWidth(1)
        pen.setColor(grey)
        self.painter.setPen(pen)
        x_pos1 = self.x_offset
        x_pos2 = ((self.end_frame - 1) * self.frame_width) + self.x_offset
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

    def draw_overlay(self):
        self.draw_0_line()
        self.draw_current_frame_line()

    def get_change_in_value(self) -> int:
        frame = self.clock.get_frame() % self.end_frame
        val = self.original_change[frame]
        return val


class PartAnimWidget(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        part: anim.model_part.ModelPart,
        part_anim: anim.unit_animation.KeyFrames,
        clock: utils.clock.Clock,
        width: int,
    ):
        super(PartAnimWidget, self).__init__(parent)
        self.model = model
        self.part = part
        self.part_anim = part_anim
        self.clock = clock
        self.width_ = width

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("part_anim_widget")
        self._layout = QtWidgets.QVBoxLayout(self)

        self.modification_label = QtWidgets.QLabel(self)
        self.modification_label.setText(
            self.locale_manager.search_key(
                f"modification_{self.part_anim.modification_type.value}"
            )
        )
        self._layout.addWidget(self.modification_label)

        self.part_anim_graph = PartGraphDrawer(
            self.model,
            self,
            self.part,
            self.part_anim,
            self.clock,
            self.width_,
        )
        self._layout.addWidget(self.part_anim_graph)

        self.change_in_value_label = QtWidgets.QLabel(self)
        self.change_in_value_label.setText(self.locale_manager.search_key("value"))
        self._layout.addWidget(self.change_in_value_label)

        self.change_in_value_spinbox = QtWidgets.QSpinBox(self)
        self.change_in_value_spinbox.setRange(-(2**31), 2**31 - 1)
        self.change_in_value_spinbox.setValue(
            self.part_anim_graph.get_change_in_value()
        )
        self.change_in_value_spinbox.setReadOnly(True)
        self._layout.addWidget(self.change_in_value_spinbox)
        self.clock.connect(self.change_spin_box)

        self._layout.addStretch(1)

    def set_frame(self, frame: int):
        self.part_anim_graph.set_frame(frame)
        self.change_spin_box()

    def disconnect_clock(self):
        self.clock.disconnect(self.change_spin_box)
        self.part_anim_graph.disconnect_clock()

    def change_spin_box(self):
        self.change_in_value_spinbox.setValue(
            self.part_anim_graph.get_change_in_value()
        )


class PartLeftPannel(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        part_id: int,
        on_click: Callable[..., None],
    ):
        super(PartLeftPannel, self).__init__(parent)
        self.model = model
        self.part_id = part_id
        self.part = self.model.get_part(self.part_id)
        self.on_click = on_click
        self.is_highlighted = False

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("part_left_pannel")
        self._layout = QtWidgets.QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self.wrapper = QtWidgets.QWidget(self)
        self.wrapper.setObjectName("wrapper")
        self.wrapper_layout = QtWidgets.QVBoxLayout(self.wrapper)
        self._layout.addWidget(self.wrapper)

        self.part_id_label = QtWidgets.QLabel(self)
        self.part_id_label.setObjectName("part_id_label")
        self.part_id_label.setText(str(self.part_id))
        self.wrapper_layout.addWidget(self.part_id_label)

        self.part_name_label = QtWidgets.QLabel(self)
        self.part_name_label.setObjectName("part_name_label")
        self.part_name_label.setText(self.part.name)
        self.part_name_label.mouseDoubleClickEvent = self.change_label_to_line_edit
        self.wrapper_layout.addWidget(self.part_name_label)

        self.mousePressEvent = self.view_part

    def change_label_to_line_edit(self, a0: QtGui.QMouseEvent):
        if a0.modifiers() == QtCore.Qt.KeyboardModifier.ShiftModifier:
            return
        self.part_name_line_edit = QtWidgets.QLineEdit(self)
        self.part_name_line_edit.setObjectName("part_name_line_edit")
        self.part_name_line_edit.setText(self.part.name)
        self.part_name_line_edit.editingFinished.connect(self.change_line_edit_to_label)
        self.part_name_line_edit.focusOutEvent = (
            self.change_line_edit_to_label_focus_out
        )
        self.part_name_line_edit.setFocus()
        self.wrapper_layout.addWidget(self.part_name_line_edit)
        self.part_name_label.hide()

    def change_line_edit_to_label(self):
        self.part_name_label.setText(self.part_name_line_edit.text())
        self.part_name_label.show()
        self.part_name_line_edit.hide()
        self.part.name = self.part_name_line_edit.text()

    def change_line_edit_to_label_focus_out(self, a0: QtGui.QFocusEvent):
        self.change_line_edit_to_label()

    def view_part(self, a0: QtGui.QMouseEvent):
        if a0.modifiers() == QtCore.Qt.KeyboardModifier.ShiftModifier:
            self.on_click(self.part_id, False)
        else:
            self.on_click(self.part_id, True)

    def highlight(self):
        self.setStyleSheet("background-color: #2b2b2b;")
        self.part_name_label.setStyleSheet("color: #ffffff;")
        self.part_id_label.setStyleSheet("color: #ffffff;")
        self.is_highlighted = True

    def unhighlight(self):
        self.setStyleSheet("background-color: #1b1b1b;")
        self.part_name_label.setStyleSheet("color: #c5c5c5;")
        self.part_id_label.setStyleSheet("color: #c5c5c5;")
        self.is_highlighted = False


class TimeLine(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: QtWidgets.QWidget,
        view_parts: Callable[..., None],
        anim_id: int,
        clock: utils.clock.Clock,
    ):
        super(TimeLine, self).__init__(parent)
        self.model = model
        self.view_parts_out = view_parts
        self.highlighted_parts: list[int] = []
        self.anim_id = anim_id
        self.clock = clock

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("timeline")

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self.left_pannel_scroll_area = QtWidgets.QScrollArea(self)
        self.left_pannel_scroll_area.setObjectName("left_pannel_scroll_area")
        self.left_pannel_scroll_area.setWidgetResizable(True)
        self.left_pannel_scroll_area.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.left_pannel_scroll_area.setFrameShadow(QtWidgets.QFrame.Shadow.Plain)
        self.left_pannel_scroll_area.setLineWidth(0)
        self.left_pannel_scroll_area.keyPressEvent = self.keyPressEvent

        self.left_pannel_group = QtWidgets.QGroupBox(self.left_pannel_scroll_area)
        self.left_pannel_group.setObjectName("left_pannel_group")
        self.left_pannel_group_layout = QtWidgets.QVBoxLayout(self.left_pannel_group)
        self.left_pannel_group_layout.setContentsMargins(0, 0, 0, 0)
        self.left_pannel_group_layout.setSpacing(0)

        self.left_pannel_scroll_area.setWidget(self.left_pannel_group)
        self._layout.addWidget(self.left_pannel_scroll_area, 1, 0)

        for i, part in enumerate(self.model.mamodel.parts):
            part_widget = PartLeftPannel(self.model, self, part.index, self.view_part)
            self.left_pannel_group_layout.addWidget(part_widget)
            if i != len(self.model.mamodel.parts) - 1:
                separator = QtWidgets.QFrame(self.left_pannel_group)
                separator.setFrameShape(QtWidgets.QFrame.Shape.HLine)
                separator.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
                self.left_pannel_group_layout.addWidget(separator)

        self.time_line_scroll_area = QtWidgets.QScrollArea(self)
        self.time_line_scroll_area.setObjectName("time_line_scroll_area")
        self.time_line_scroll_area.setWidgetResizable(True)
        self.time_line_scroll_area.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.time_line_scroll_area.setFrameShadow(QtWidgets.QFrame.Shadow.Plain)
        self.time_line_scroll_area.setLineWidth(0)

        self.time_line_group = QtWidgets.QGroupBox(self.time_line_scroll_area)
        self.time_line_group.setObjectName("time_line_group")
        self.time_line_group_layout = QtWidgets.QVBoxLayout(self.time_line_group)
        self.time_line_group_layout.setContentsMargins(0, 0, 0, 0)
        self.time_line_group_layout.setSpacing(0)

        self.time_line_scroll_area.setWidget(self.time_line_group)
        self._layout.addWidget(self.time_line_scroll_area, 1, 1)

        self.left_pannel_time_line_splitter = QtWidgets.QSplitter(self)
        self.left_pannel_time_line_splitter.setOrientation(
            QtCore.Qt.Orientation.Horizontal
        )
        self.left_pannel_time_line_splitter.addWidget(self.left_pannel_scroll_area)
        self.left_pannel_time_line_splitter.addWidget(self.time_line_scroll_area)
        self._layout.addWidget(self.left_pannel_time_line_splitter, 1, 0)

        self.left_pannel_time_line_splitter.setSizes([200, 800])

    def view_part(self, part_id: int, override_highlight: bool = True):
        if part_id < 0:
            return
        if part_id >= len(self.model.mamodel.parts):
            return
        if part_id not in self.highlighted_parts:
            self.highlighted_parts.append(part_id)
        else:
            self.highlighted_parts.remove(part_id)

        if override_highlight:
            self.highlighted_parts = [part_id]

        self.highlight_parts(self.highlighted_parts)
        self.view_parts_out([part_id])
        self.view_keyframes(part_id)
        self.scroll_to_part(part_id)

    def scroll_to_part(self, part_id: int):
        for i in range(self.left_pannel_group_layout.count()):
            item = self.left_pannel_group_layout.itemAt(i)
            if isinstance(item, QtWidgets.QWidgetItem):
                widget = item.widget()
                if isinstance(widget, PartLeftPannel):
                    if widget.part_id == part_id:  # type: ignore
                        self.left_pannel_scroll_area.ensureWidgetVisible(widget)

    def view_keyframes(self, part_id: int):
        # delete items in time line
        main.clear_layout(self.time_line_group_layout)

        part = self.model.get_part(part_id)
        width = self.time_line_group.width() - 40

        for i, part_anim in enumerate(part.part_anims):
            part_anim_widget = PartAnimWidget(
                self.model, self, part, part_anim, self.clock, width
            )
            self.time_line_group_layout.addWidget(part_anim_widget)
            if i != len(part.part_anims) - 1:
                separator = QtWidgets.QFrame(self.time_line_group)
                separator.setFrameShape(QtWidgets.QFrame.Shape.HLine)
                separator.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
                self.time_line_group_layout.addWidget(separator)

        self.time_line_group_layout.addStretch(1)

    def set_frame(self, frame: int):
        for i in range(self.time_line_group_layout.count()):
            item = self.time_line_group_layout.itemAt(i)
            if isinstance(item, QtWidgets.QWidgetItem):
                widget = item.widget()
                if isinstance(widget, PartAnimWidget):
                    widget.set_frame(frame)  # type: ignore

    def highlight_parts(self, part_ids: list[int]):
        for i in range(self.left_pannel_group_layout.count()):
            item = self.left_pannel_group_layout.itemAt(i)
            if isinstance(item, QtWidgets.QWidgetItem):
                widget = item.widget()
                if isinstance(widget, PartLeftPannel):
                    if widget.part_id in part_ids:  # type: ignore
                        widget.highlight()  # type: ignore
                    else:
                        widget.unhighlight()  # type: ignore

    def keyPressEvent(self, a0: QtGui.QKeyEvent):
        shift: bool = a0.modifiers() & QtCore.Qt.KeyboardModifier.ShiftModifier
        if a0.key() == QtCore.Qt.Key.Key_Up:
            self.view_part(
                self.get_top_highlighted_part() - 1, override_highlight=not shift
            )
        elif a0.key() == QtCore.Qt.Key.Key_Down:
            self.view_part(
                self.get_bottom_highlighted_part() + 1, override_highlight=not shift
            )

    def get_top_highlighted_part(self) -> int:
        for i in range(self.left_pannel_group_layout.count()):
            item = self.left_pannel_group_layout.itemAt(i)
            if isinstance(item, QtWidgets.QWidgetItem):
                widget = item.widget()
                if isinstance(widget, PartLeftPannel):
                    if widget.is_highlighted:  # type: ignore
                        return widget.part_id  # type: ignore
        return 0

    def get_bottom_highlighted_part(self) -> int:
        for i in range(self.left_pannel_group_layout.count(), 0, -1):
            item = self.left_pannel_group_layout.itemAt(i - 1)
            if isinstance(item, QtWidgets.QWidgetItem):
                widget = item.widget()
                if isinstance(widget, PartLeftPannel):
                    if widget.is_highlighted:  # type: ignore
                        return widget.part_id  # type: ignore
        return 0


class AnimEditor(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        anim_id: int,
    ):
        super(AnimEditor, self).__init__()
        self.model = model
        self.anim_id = anim_id

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.asset_loader = utils.asset_loader.AssetLoader()
        self.setup_ui()

    def setup_ui(self):
        self.resize(900, 700)
        self.setWindowIcon(self.asset_loader.load_icon("icon.png"))
        self.showMaximized()

        self.setWindowTitle(self.locale_manager.search_key("anim_editor_title"))

        self.setObjectName("anim_editor")

        self._layout = QtWidgets.QGridLayout(self)

        self.setup_top_half()
        self.setup_bottom_half()

        self.top_bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        self.top_bottom_splitter.addWidget(self.anim_viewer_page)
        self.top_bottom_splitter.addWidget(self.part_timeline)
        self._layout.addWidget(self.top_bottom_splitter, 0, 0)

        self.top_bottom_splitter.setSizes(
            [int(self.height() * 0.6), int(self.height() * 0.4)]
        )

        self.anim_viewer_page.anim_viewer_box.anim_viewer.start_clock()

    def setup_top_half(self):
        self.anim_viewer_page = AnimViewerPage(
            self.model, self, self.anim_id, self.set_frame
        )
        self._layout.addWidget(self.anim_viewer_page, 0, 0)

    def setup_bottom_half(self):
        self.part_timeline = TimeLine(
            self.model,
            self,
            self.view_parts,
            self.anim_id,
            self.anim_viewer_page.anim_viewer_box.anim_viewer.clock,
        )
        self._layout.addWidget(self.part_timeline, 1, 0)

    def set_frame(self, frame: int):
        self.anim_viewer_page.anim_viewer_box.anim_viewer.set_frame(frame)
        self.anim_viewer_page.anim_viewer_box.update()
        self.anim_viewer_page.part_viewer_box.update()

        self.part_timeline.set_frame(frame)

    def frame_tick(self):
        pass

    def view_parts(self, parts: list[int]):
        self.anim_viewer_page.view_parts(parts)
