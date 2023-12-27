import math
from typing import Optional, Callable

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QKeyEvent, QMouseEvent, QPaintEvent


from tbcml import core
from tbcml.ui.anim import frame_counter
from tbcml.ui.utils import fontawsome

try:
    import moviepy.video.io.ImageSequenceClip
except ImportError:
    moviepy = None


class ModelViewer(QtWidgets.QOpenGLWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        model: core.Model,
        anim_id: int,
        get_box_pos: Callable[..., QtCore.QPointF],
        get_box_scale: Callable[..., float],
        align_other_box: Callable[..., None],
        clock: frame_counter.FrameClock,
        parent: Optional[QtWidgets.QWidget] = None,
        is_model_viewer: bool = True,
        other_models: Optional[list[tuple[core.Model, int]]] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.is_model_viewer = is_model_viewer
        self.get_box_pos = get_box_pos
        self.get_box_scale = get_box_scale
        self.align_other_box = align_other_box
        self.clock = clock
        self.model = model
        self.anim_id = anim_id
        self.other_models = other_models
        self.setup()

    def setup(self):
        self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.setup_clock()
        self.setup_context_menu()
        self.setup_bg()
        self.setup_model()
        self.setup_values()

    def setup_clock(self):
        self.clock.add_perm_func(self.update_opacity)
        self.clock.add_perm_func(self.update)

    def setup_values(self):
        self.has_set_pos = False

        self.x_pos = 0
        self.y_pos = 0

        self.start_x_pos = 0.0
        self.start_y_pos = 0.0
        self.end_x_pos = 0.0
        self.end_y_pos = 0.0

        self.bg_alpha = 0

        self.scale = 10.0

        self.always_align = False
        self.show_grid = False
        self.should_loop = True
        self.should_draw_overlay = True
        self.save_frames = False

    def setup_model(self):
        self.model.set_required()
        self.model.set_keyframes_sets(self.anim_id)

        self.parts = self.model.get_sorted_parts()

        self.overlay_part_id = None

        self.other_parts: list[list[core.ModelPart]] = []

        if self.other_models is not None:
            for model, anim_id in self.other_models:
                model.set_required()
                model.set_keyframes_sets(anim_id)
                self.other_parts.append(model.get_sorted_parts())

    def set_anim_id(self, anim_id: int):
        self.anim_id = anim_id
        self.model.set_keyframes_sets(self.anim_id)
        self.parts = self.model.get_sorted_parts()

    def set_overlay_part(self, part_id: int):
        self.overlay_part_id = part_id

    def setup_bg(self):
        gradient_color_1 = QtGui.QColor(88, 184, 204)
        gradient_color_2 = QtGui.QColor(108, 200, 206)
        gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, gradient_color_1)
        gradient.setColorAt(1, gradient_color_2)
        self.gradient = gradient

        bg_texture = core.Texture.load("img016.png", "img016.imgcut", self.game_data)
        bg_image = bg_texture.get_image(0)
        self.bg_image = bg_image

    def update_opacity(self):
        self.bg_alpha += 1

    def setup_context_menu(self) -> None:
        self.should_bring_to_front = False
        self.menu = QtWidgets.QMenu(self)

        self.add_context_actions()

    def add_context_actions(self):
        self.menu.clear()
        # self.menu.addAction(
        #    core.local_manager.get_key("reset_view_position"), self.reset_position
        # )
        # if self.is_model_viewer:
        #    if self.should_bring_to_front:
        #        self.menu.addAction(
        #            core.local_manager.get_key("remove_selected_part_from_front"),
        #            self.toggle_bring_to_front,
        #        )
        #    else:
        #        self.menu.addAction(
        #            core.local_manager.get_key("bring_selected_part_to_front"),
        #            self.toggle_bring_to_front,
        #        )
        #    self.menu.addAction(
        #        core.local_manager.get_key("align_model_to_part"),
        #        self.align_part_view_to_model,
        #    )
        # else:
        #    self.menu.addAction(
        #        core.local_manager.get_key("align_part_to_model"),
        #        self.align_part_view_to_model,
        #    )

    def context_menu(self, pos: QtCore.QPoint) -> None:
        self.menu.exec_(self.mapToGlobal(pos))

    def toggle_bring_to_front(self):
        self.should_bring_to_front = not self.should_bring_to_front
        self.add_context_actions()
        self.update()

    def reset_position(self):
        self.x_pos = self.width() / 2
        self.y_pos = self.height() / 2
        self.scale = 10.0
        if self.always_align:
            self.align_other_box()
        self.update()

    def align_part_view_to_model(self):
        self.x_pos = self.get_box_pos().x()
        self.y_pos = self.get_box_pos().y()
        self.scale = self.get_box_scale()
        self.update()

    def paintEvent(self, e: QtGui.QPaintEvent) -> None:
        if not self.has_set_pos:
            self.x_pos = self.width() / 2
            self.y_pos = self.height() / 2
            self.has_set_pos = True

        self.img = QtGui.QImage(
            self.width(), self.height(), QtGui.QImage.Format.Format_ARGB32
        )
        self.img.fill(QtCore.Qt.GlobalColor.transparent)

        img_painter = QtGui.QPainter(self.img)

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        img_painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        img_painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        # Draw the background
        self.gradient.setFinalStop(0, self.height())
        painter.fillRect(self.rect(), self.gradient)
        img_painter.fillRect(self.rect(), self.gradient)

        delta_x = self.end_x_pos - self.start_x_pos
        delta_y = self.end_y_pos - self.start_y_pos
        self.x_pos += delta_x
        self.y_pos += delta_y

        self.start_x_pos = self.end_x_pos
        self.start_y_pos = self.end_y_pos

        # Draw the model
        painter.translate(self.x_pos, self.y_pos)
        img_painter.translate(self.x_pos, self.y_pos)
        frame = self.clock.get_frame()
        if self.should_loop:
            if frame == self.model.get_end_frame():
                self.save_frames = False
            frame %= self.model.get_total_frames()

        self.model.set_action(frame)

        if self.other_models is not None:
            for model, _ in self.other_models:
                model.set_action(frame)

        if self.show_grid:
            self.draw_grid(painter)

        self.draw(painter, img_painter)
        if self.should_draw_overlay:
            self.draw_overlay(painter)

        if self.save_frames and self.is_model_viewer:
            frames_folder = core.TempFolder("frames")
            self.save_frame(self.img, frames_folder.path.add(f"frame_{frame}.png"))

        # draw self.img as screen
        # painter.end()
        # painter.begin(self)
        # painter.drawImage(0, 0, self.img)

    def draw_grid(self, painter: QtGui.QPainter) -> None:
        render_hints = painter.renderHints()
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, False)
        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform, False)
        square_size = 27
        square_size = int(self.scale * (square_size / 10))
        if square_size < 1:
            square_size = 1

        opacity = 140 + ((255 - 140) * math.cos(math.radians(self.bg_alpha)))

        grid_pen = QtGui.QPen(QtGui.QColor(255, 255, 255, int(opacity)))
        grid_pen.setWidth(3)

        painter.setPen(grid_pen)
        screen_width = self.width()
        screen_height = self.height()
        x_pos = int(self.x_pos)
        y_pos = int(self.y_pos)
        # all 4 quadrants
        for x in range(square_size, screen_width - x_pos, square_size):
            painter.drawLine(x, -(screen_height + y_pos), x, screen_height - y_pos)
        for y in range(square_size, screen_height - y_pos, square_size):
            painter.drawLine(-(screen_width + x_pos), y, screen_width - x_pos, y)

        for x in range(-square_size, -(screen_width + x_pos), -square_size):
            painter.drawLine(x, -(screen_height + y_pos), x, screen_height - y_pos)
        for y in range(-square_size, -(screen_height + y_pos), -square_size):
            painter.drawLine(-(screen_width + x_pos), y, screen_width - x_pos, y)

        painter.setRenderHints(render_hints)

    def draw(
        self, painter: QtGui.QPainter, img_painter: Optional[QtGui.QPainter]
    ) -> None:
        for part in self.parts:
            part.draw_part(painter, self.scale, self.scale)
            if img_painter is not None:
                part.draw_part(img_painter, self.scale, self.scale)

        for parts in self.other_parts:
            for part in parts:
                part.draw_part(painter, self.scale, self.scale)
                if img_painter is not None:
                    part.draw_part(img_painter, self.scale, self.scale)

        if self.overlay_part_id is not None and self.should_draw_overlay:
            part = self.model.get_part(self.overlay_part_id)
            if part is not None:
                part.draw_part(
                    painter,
                    self.scale,
                    self.scale,
                    draw_overlay=True,
                    just_overlay=not self.should_bring_to_front,
                )

    def save_frame(self, img: QtGui.QImage, path: core.Path) -> None:
        img.save(path.to_str())

    def create_video(
        self, paths: list[core.Path], out_path: "core.Path", codec: str = "libx264"
    ) -> None:
        if moviepy is None:
            raise ImportError("Please pip install tbcml[ui] to use this feature")
        image_files = [path.to_str() for path in paths]
        clip = moviepy.video.io.ImageSequenceClip.ImageSequenceClip(
            image_files, fps=self.clock.fps
        )
        clip.write_videofile(out_path.to_str(), codec=codec)

    def draw_overlay(self, painter: QtGui.QPainter) -> None:
        vline = QtGui.QPen(QtGui.QColor(255, 255, 255))
        vline.setWidth(1)
        vline.setStyle(QtCore.Qt.PenStyle.DashLine)
        painter.setPen(vline)
        painter.drawLine(
            0,
            -int(self.height() + self.y_pos + 5),
            0,
            int(self.height() - self.y_pos + 5),
        )
        painter.drawLine(
            -int(self.width() + self.x_pos + 5),
            0,
            int(self.width() - self.x_pos + 5),
            0,
        )

    def mousePressEvent(self, a0: QtGui.QMouseEvent) -> None:
        self.start_x_pos = a0.x()
        self.start_y_pos = a0.y()
        self.end_x_pos = a0.x()
        self.end_y_pos = a0.y()

        if a0.button() == QtCore.Qt.MouseButton.RightButton:
            self.context_menu(a0.pos())

    def mouseMoveEvent(self, a0: QtGui.QMouseEvent) -> None:
        self.end_x_pos = a0.x()
        self.end_y_pos = a0.y()

        if self.always_align:
            self.align_other_box()

        self.update()

    def wheelEvent(self, a0: QtGui.QWheelEvent) -> None:
        self.scale += a0.angleDelta().y() / 120
        self.scale = max(2, self.scale)

        if self.always_align:
            self.align_other_box()

        self.update()


class PartViewer(ModelViewer):
    def __init__(
        self,
        game_data: core.GamePacks,
        model: core.Model,
        anim_id: int,
        part_id: int,
        get_box_pos: Callable[..., QtCore.QPointF],
        get_box_scale: Callable[..., float],
        align_other_box: Callable[..., None],
        clock: frame_counter.FrameClock,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(
            game_data,
            model,
            anim_id,
            get_box_pos,
            get_box_scale,
            align_other_box,
            clock,
            parent,
            is_model_viewer=False,
        )
        self.part_id = part_id
        part = self.model.get_part(part_id)
        if part is None:
            raise ValueError(f"Part with id {part_id} not found")
        self.part = part

    def draw(
        self, painter: QtGui.QPainter, img_painter: Optional[QtGui.QPainter]
    ) -> None:
        self.part.draw_part(
            painter, self.scale, self.scale, draw_overlay=self.should_draw_overlay
        )

    def set_part_id(self, part_id: int):
        self.part_id = part_id
        part = self.model.get_part(part_id)
        if part is None:
            raise ValueError(f"Part with id {part_id} not found")
        self.part = part


class PartBox(QtWidgets.QWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        model: core.Model,
        anim_id: int,
        part_id: int,
        get_box_pos: Callable[..., QtCore.QPointF],
        get_box_scale: Callable[..., float],
        align_other_box: Callable[..., None],
        clock: frame_counter.FrameClock,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.model = model
        self.anim_id = anim_id
        self.part_id = part_id
        self.get_box_pos = get_box_pos
        self.get_box_scale = get_box_scale
        self.align_other_box = align_other_box
        self.clock = clock
        self.part = self.model.get_part(self.part_id)
        self.setup()

    def setup(self):
        self.layout_box = QtWidgets.QGridLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.part_box = PartViewer(
            self.game_data,
            self.model,
            self.anim_id,
            self.part_id,
            self.get_box_pos,
            self.get_box_scale,
            self.align_other_box,
            self.clock,
            self,
        )

        self.split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical, self)
        self.split.setHandleWidth(2)
        self.split.mouseDoubleClickEvent = self.reset_splitter_event
        self.split.addWidget(self.part_box)

        if self.part is not None:
            all_keyframe_sets = self.part.get_all_keyframe_sets_recursive()

            self.keyframe_viewer = KeyFrameViewer(
                self.game_data,
                all_keyframe_sets,
                self.clock,
                self.model,
                self.part_id,
                self,
            )
            self.split.addWidget(self.keyframe_viewer)

        self.layout_box.addWidget(self.split)
        self.reset_splitter()

    def reset_splitter_event(self, a0: Optional[QtGui.QMouseEvent]) -> None:
        self.reset_splitter()

    def reset_splitter(self) -> None:
        self.split.setSizes([self.split.width() // 2] * 2)

    def set_part_id(self, part_id: int) -> bool:
        part = self.model.get_part(part_id)
        if part is None:
            return False
        self.part_id = part_id
        self.part = part
        self.part_box.set_part_id(part_id)
        self.keyframe_viewer.set_part_id(
            part_id, part.get_all_keyframe_sets_recursive()
        )
        return True


class KeyFrameViewer(QtWidgets.QWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        keyframe_sets: list[core.KeyFrames],
        clock: frame_counter.FrameClock,
        model: core.Model,
        part_id: int,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.keyframe_sets = keyframe_sets
        self.clock = clock
        self.model = model
        self.part_id = part_id
        self.setup()

    def setup(self):
        self.layout_box = QtWidgets.QVBoxLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.layout_box.setSpacing(0)

        self.keyframe_title = QtWidgets.QLabel(self)
        self.keyframe_title.setText("Keyframe Sets")
        self.layout_box.addWidget(self.keyframe_title)

        self.part_id_label = QtWidgets.QLabel(self)
        self.part_id_label.setText(f"Part ID: {self.part_id}")
        self.layout_box.addWidget(self.part_id_label)

        self.keyframe_list = QtWidgets.QListWidget(self)
        self.layout_box.addWidget(self.keyframe_list)

        self.max_spacing = 0

        self.add_key_frames()

    def clear_key_frames(self):
        for i in range(self.keyframe_list.count()):
            # remove update func
            widget = self.get_keyframe_set_viewer(i)
            if widget is None:
                continue
            widget.remove_clock_func()

        self.keyframe_list.clear()

    def add_key_frames(self):
        for i, keyframe_set in enumerate(self.keyframe_sets):
            item_widget = QtWidgets.QListWidgetItem(self.keyframe_list)
            key_frame_set_viewer = KeyFrameSetViewer(
                self.game_data,
                keyframe_set,
                self.clock,
                self.model,
                self.part_id,
                self.get_selected_keyframe_set_viewers,
                self.update_spacing,
                i,
                self,
            )
            # disable selection
            item_widget.setSizeHint(
                key_frame_set_viewer.sizeHint()
                + QtCore.QSize(0, key_frame_set_viewer.get_height_needed())
            )

            self.keyframe_list.addItem(item_widget)
            self.keyframe_list.setItemWidget(item_widget, key_frame_set_viewer)

            key_frame_set_viewer.set_splitter(self.width())

        self.keyframe_list.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)

        self.keyframe_list.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
        )

    def get_selected_keyframe_set_viewers(self) -> list["KeyFrameSetViewer"]:
        selected_items = self.keyframe_list.selectedItems()
        return [self.keyframe_list.itemWidget(item) for item in selected_items]

    def set_part_id(self, part_id: int, keyframe_sets: list[core.KeyFrames]):
        self.part_id = part_id
        self.keyframe_sets = keyframe_sets
        self.clear_key_frames()
        self.add_key_frames()

        self.part_id_label.setText(f"Part ID: {self.part_id}")

    def get_keyframe_set_viewer(self, index: int) -> Optional["KeyFrameSetViewer"]:
        item = self.keyframe_list.item(index)
        widget = self.keyframe_list.itemWidget(item)
        if widget is None:
            return None
        return widget

    def update_spacing(self, spacing: int):
        self.max_spacing = max(self.max_spacing, spacing)
        for i in range(self.keyframe_list.count()):
            widget = self.get_keyframe_set_viewer(i)
            if widget is None:
                continue
            widget.set_spacing(self.max_spacing)


class KeyFrameSetViewer(QtWidgets.QWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        keyframe_set: core.KeyFrames,
        clock: frame_counter.FrameClock,
        model: core.Model,
        part_id: int,
        get_selected_keyframe_set_viewers: Callable[[], list["KeyFrameSetViewer"]],
        update_spacing: Callable[[int], None],
        index: int,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.keyframe_set = keyframe_set
        self.clock = clock
        self.model = model
        self.part_id = part_id
        self.get_selected_keyframe_set_viewers = get_selected_keyframe_set_viewers
        self.update_spacing = update_spacing
        self.index = index

        self.setup()

    def is_parent(self) -> bool:
        return self.keyframe_set.part_id != self.part_id

    def keyframe_name_key_press_event(self, a0: Optional[QKeyEvent]) -> None:
        QtWidgets.QLineEdit.keyPressEvent(self.keyframe_name, a0)
        if a0 is None:
            return
        if a0.key() == QtCore.Qt.Key.Key_Return:
            self.keyframe_set.name = self.keyframe_name.text()
            self.keyframe_name.clearFocus()

    def setup(self):
        self.previous_value = 0
        self.layout_box = QtWidgets.QHBoxLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.layout_box.setSpacing(0)

        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal, self)
        self.splitter.setHandleWidth(2)
        self.splitter.mouseDoubleClickEvent = self.reset_splitter_event
        self.splitter.splitterMoved.connect(self.splitter_moved)

        self.layout_box.addWidget(self.splitter)

        self.info_layout_box = QtWidgets.QGroupBox(self)

        self.info_layout = QtWidgets.QHBoxLayout()
        self.info_layout.setContentsMargins(0, 0, 0, 0)
        self.info_layout.setSpacing(0)

        self.info_layout_box.setLayout(self.info_layout)
        self.splitter.addWidget(self.info_layout_box)

        self.add_info_box()
        self.add_previous_keyframe_info_box()
        self.add_next_keyframe_info_box()

        self.keyframe_box = KeyFrameBox(
            self.keyframe_set,
            self.clock,
            self.model,
            self.part_id,
            self.update_spacing,
            self.index,
            self,
        )
        self.splitter.addWidget(self.keyframe_box)

        self.width_splitter = self.width()

        self.clock.add_perm_func(self.update_info)

    def add_info_box(self):
        self.info_box = QtWidgets.QGroupBox(self)
        self.info_box_layout = QtWidgets.QVBoxLayout(self.info_box)
        self.info_layout.addWidget(self.info_box)

        self.keyframe_name = QtWidgets.QLineEdit(self)
        self.keyframe_name.setText(self.keyframe_set.name)
        self.keyframe_name.keyPressEvent = self.keyframe_name_key_press_event
        self.info_box_layout.addWidget(self.keyframe_name)

        self.current_value_layout = QtWidgets.QHBoxLayout()
        self.info_box_layout.addLayout(self.current_value_layout)

        self.current_value_label = QtWidgets.QLabel(self)
        self.current_value_label.setText(f"Current Value:")
        self.current_value_layout.addWidget(self.current_value_label)

        self.current_value_group = QtWidgets.QGroupBox(self)
        self.current_value_layout.addWidget(self.current_value_group)

        self.current_value_group_layout = QtWidgets.QVBoxLayout(
            self.current_value_group
        )

        self.current_value_group.setLayout(self.current_value_group_layout)

        self.previous_value_label_text = QtWidgets.QLabel(self)
        self.previous_value_label_text.setText(f"{self.previous_value}")
        self.current_value_group_layout.addWidget(self.previous_value_label_text)

        self.loop_count_layout = QtWidgets.QHBoxLayout()
        self.info_box_layout.addLayout(self.loop_count_layout)

        self.loop_count_label = QtWidgets.QLabel(self)
        self.loop_count_label.setText(f"Loop Count:")
        self.loop_count_layout.addWidget(self.loop_count_label)

        self.loop_count_spinbox = QtWidgets.QSpinBox(self)
        self.loop_count_spinbox.setMinimum(-1)
        self.loop_count_spinbox.setMaximum(1000)
        self.loop_count_spinbox.setValue(self.keyframe_set.loop)
        self.loop_count_layout.addWidget(self.loop_count_spinbox)

        self.modification_layout = QtWidgets.QHBoxLayout()
        self.info_box_layout.addLayout(self.modification_layout)

        self.modification_label = QtWidgets.QLabel(self)
        self.modification_label.setText(f"Modification:")
        self.modification_layout.addWidget(self.modification_label)

        self.modification_dropdown = QtWidgets.QComboBox(self)
        self.modification_dropdown.addItems(
            [
                "Parent",
                "ID",
                "Sprite",
                "Z Order",
                "X Pos",
                "Y Pos",
                "X Pivot",
                "Y Pivot",
                "Scale",
                "X Scale",
                "Y Scale",
                "Rotation",
                "Opacity",
                "Flip Horizontally",
                "Flip Vertically",
            ]
        )
        self.modification_dropdown.setCurrentIndex(
            self.keyframe_set.modification_type.value
        )
        self.modification_layout.addWidget(self.modification_dropdown)

        self.add_parent_layout()
        self.apply_parent_changes()

        self.info_box_layout.addStretch()

    def add_previous_keyframe_info_box(self):
        self.previous_keyframe_info_box = QtWidgets.QGroupBox(self)
        self.previous_keyframe_info_box_layout = QtWidgets.QVBoxLayout(
            self.previous_keyframe_info_box
        )
        self.info_layout.addWidget(self.previous_keyframe_info_box)

        self.previous_keyframe_layout = QtWidgets.QHBoxLayout()
        self.previous_keyframe_info_box_layout.addLayout(self.previous_keyframe_layout)

        self.keyframe_label = QtWidgets.QLabel(self)
        self.keyframe_label.setText(f"Previous Keyframe:")
        self.previous_keyframe_layout.addWidget(self.keyframe_label)

        self.previous_keyframe_group = QtWidgets.QGroupBox(self)
        self.previous_keyframe_layout.addWidget(self.previous_keyframe_group)

        self.previous_keyframe_group_layout = QtWidgets.QVBoxLayout(
            self.previous_keyframe_group
        )

        self.previous_keyframe_group.setLayout(self.previous_keyframe_group_layout)

        self.previous_keyframe_label_text = QtWidgets.QLabel(self)
        self.previous_keyframe_label_text.setText(f"{0}")
        self.previous_keyframe_group_layout.addWidget(self.previous_keyframe_label_text)

        self.previous_frame_layout = QtWidgets.QHBoxLayout()
        self.previous_keyframe_info_box_layout.addLayout(self.previous_frame_layout)

        self.previous_frame_label = QtWidgets.QLabel(self)
        self.previous_frame_label.setText(f"Start Frame:")
        self.previous_frame_layout.addWidget(self.previous_frame_label)

        self.previous_frame_spinbox = QtWidgets.QSpinBox(self)
        self.previous_frame_spinbox.setMinimum(0)
        self.previous_frame_spinbox.setMaximum(2**31 - 1)
        self.previous_frame_spinbox.setValue(0)
        self.previous_frame_layout.addWidget(self.previous_frame_spinbox)

        self.previous_keyframe_info_box_layout.addStretch()

    def add_next_keyframe_info_box(self):
        self.next_keyframe_info_box = QtWidgets.QGroupBox(self)
        self.next_keyframe_info_box_layout = QtWidgets.QVBoxLayout(
            self.next_keyframe_info_box
        )
        self.info_layout.addWidget(self.next_keyframe_info_box)

        self.next_keyframe_layout = QtWidgets.QHBoxLayout()
        self.next_keyframe_info_box_layout.addLayout(self.next_keyframe_layout)

        self.keyframe_label = QtWidgets.QLabel(self)
        self.keyframe_label.setText(f"Next Keyframe:")
        self.next_keyframe_layout.addWidget(self.keyframe_label)

        self.next_keyframe_group = QtWidgets.QGroupBox(self)
        self.next_keyframe_layout.addWidget(self.next_keyframe_group)

        self.next_keyframe_group_layout = QtWidgets.QVBoxLayout(
            self.next_keyframe_group
        )

        self.next_keyframe_group.setLayout(self.next_keyframe_group_layout)

        self.next_keyframe_label_text = QtWidgets.QLabel(self)
        self.next_keyframe_label_text.setText(f"{0}")
        self.next_keyframe_group_layout.addWidget(self.next_keyframe_label_text)

        self.next_frame_layout = QtWidgets.QHBoxLayout()
        self.next_keyframe_info_box_layout.addLayout(self.next_frame_layout)

        self.next_frame_label = QtWidgets.QLabel(self)
        self.next_frame_label.setText(f"Start frame:")
        self.next_frame_layout.addWidget(self.next_frame_label)

        self.next_frame_spinbox = QtWidgets.QSpinBox(self)
        self.next_frame_spinbox.setMinimum(0)
        self.next_frame_spinbox.setMaximum(2**31 - 1)
        self.next_frame_spinbox.setValue(0)
        self.next_frame_layout.addWidget(self.next_frame_spinbox)

        self.next_keyframe_info_box_layout.addStretch()

    def update_info(self):
        frame = self.clock.get_frame()
        frame_loop = frame % (self.model.get_end_frame() + 1)
        self.previous_value = self.keyframe_set.set_action(frame)
        self.previous_value_label_text.setText(f"{self.previous_value}")

        next_index = None
        for i, keyframe in enumerate(self.keyframe_set.keyframes):
            if keyframe.frame > frame_loop:
                next_index = i
                break

        if next_index is None:
            next_index = len(self.keyframe_set.keyframes)

        previous_index = next_index - 1
        previous_keyframe = self.keyframe_set.keyframes[previous_index]

        if next_index == len(self.keyframe_set.keyframes):
            next_index = 0
        next_keyframe = self.keyframe_set.keyframes[next_index]

        self.previous_frame_spinbox.setValue(previous_keyframe.frame)
        self.previous_keyframe_label_text.setText(f"{previous_index}")

        self.next_frame_spinbox.setValue(next_keyframe.frame)
        self.next_keyframe_label_text.setText(f"{next_index}")

    def set_spacing(self, spacing: int):
        self.keyframe_box.set_spacing(spacing)

    def set_splitter(self, width: int):
        self.width_splitter = width
        self.splitter.setSizes([50, (width - 50 // 2), (width - 50 // 2)])

    def reset_splitter_event(self, a0: Optional[QtGui.QMouseEvent]) -> None:
        self.set_splitter(self.width_splitter)
        for viewer in self.get_selected_keyframe_set_viewers():
            viewer.set_splitter(viewer.width_splitter)

    def add_parent_layout(self):
        self.parent_layout = QtWidgets.QHBoxLayout()

        self.info_box_layout.addLayout(self.parent_layout)

        self.parent_label = QtWidgets.QLabel(self)
        self.parent_label.setText(f"Inherited From:")
        self.parent_layout.addWidget(self.parent_label)

        self.parent_box = QtWidgets.QGroupBox(self)
        self.parent_layout.addWidget(self.parent_box)

        self.parent_box_layout = QtWidgets.QVBoxLayout(self.parent_box)
        self.parent_box.setLayout(self.parent_box_layout)

        self.parent_label_text = QtWidgets.QLabel(self)
        part = self.model.get_part(self.keyframe_set.part_id)
        if part is None:
            raise ValueError(f"Part with id {self.keyframe_set.part_id} not found")

        self.parent_label_text.setText(f"{self.keyframe_set.part_id}: {part.name}")
        self.parent_box_layout.addWidget(self.parent_label_text)

    def remove_clock_func(self):
        self.keyframe_box.remove_func()
        self.clock.remove_perm_func(self.update_info)

    def set_part_id(self, part_id: int):
        self.part_id = part_id
        self.keyframe_box.set_part_id(part_id)
        self.apply_parent_changes()

    def remove_parent_layout(self):
        if hasattr(self, "parent_layout"):
            self.deleteItemsOfLayout(self.parent_layout)

    @staticmethod
    def deleteItemsOfLayout(layout: Optional[QtWidgets.QLayout]) -> None:
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                if item is not None:
                    widget = item.widget()
                    if widget is not None:
                        widget.setParent(None)
                    else:
                        KeyFrameSetViewer.deleteItemsOfLayout(item.layout())

    def apply_parent_changes(self):
        self.remove_parent_layout()
        if self.is_parent():
            self.add_parent_layout()

        # self.setEnabled(not self.is_parent())

    def splitter_moved(self, pos: int, index: int) -> None:
        if index == 1:
            for viewer in self.get_selected_keyframe_set_viewers():
                viewer.splitter.setSizes([pos, viewer.width() - pos])

    def get_height_needed(self) -> int:
        return max(self.keyframe_box.get_height_needed(), self.height())


class KeyFrameBox(QtWidgets.QWidget):
    def __init__(
        self,
        keyframes: core.KeyFrames,
        clock: frame_counter.FrameClock,
        model: core.Model,
        part_id: int,
        update_spacing: Callable[[int], None],
        index: int,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.keyframes = keyframes
        self.clock = clock
        self.model = model
        self.part_id = part_id
        self.part = self.model.get_part(self.part_id)
        self.update_spacing = update_spacing
        self.index = index
        self.setup()

    def set_spacing(self, spacing: int):
        self.spacing = spacing

    def set_part_id(self, part_id: int):
        self.part_id = part_id
        self.part = self.model.get_part(self.part_id)

    def setup(self):
        self.spacing = 20
        self.max_height = 0

        self.mouse_pos = QtCore.QPoint(0, 0)

        self.setMouseTracking(True)

        self.clock.add_perm_func(self.update)

    def remove_func(self):
        self.clock.remove_perm_func(self.update)

    def paintEvent(self, a0: QPaintEvent | None) -> None:
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        background_color = QtGui.QColor(0, 0, 0, 50)
        painter.fillRect(self.rect(), background_color)

        self.vline_pen = QtGui.QPen(QtGui.QColor(255, 255, 255))
        self.vline_pen.setWidth(1)
        self.vline_pen.setStyle(QtCore.Qt.PenStyle.DashLine)

        self.keyframe_pen = QtGui.QPen(QtGui.QColor(255, 255, 255))
        self.keyframe_pen.setWidth(4)

        self.marker_pen = QtGui.QPen(QtGui.QColor(255, 255, 255))
        self.marker_pen.setWidth(1)

        self.marker_pen_color = QtGui.QPen(QtGui.QColor(255, 0, 0))
        self.marker_pen_color.setWidth(1)

        self.marker_text_pen = QtGui.QPen(QtGui.QColor(255, 255, 255))
        self.marker_text_pen.setWidth(1)

        self.draw_cursor(painter)
        self.draw_keyframes(painter)
        self.draw_frame_markings(painter)

    def get_frame_x_pos(self, frame: int) -> int:
        width = self.width() - self.spacing
        return self.spacing // 2 + int((frame / self.keyframes.get_end_frame()) * width)

    def draw_cursor(self, painter: QtGui.QPainter) -> None:
        current_frame = self.clock.get_frame() % (self.model.get_end_frame() + 1)
        height = self.height()
        x_pos = self.get_frame_x_pos(current_frame)
        painter.setPen(self.vline_pen)
        painter.drawLine(x_pos, 0, x_pos, height)

    def draw_keyframes(self, painter: QtGui.QPainter) -> None:
        self.key_frame_coords: list[tuple[int, int]] = []
        dist = 20
        for keyframe in self.keyframes.keyframes:
            frame = keyframe.frame
            height = self.height()
            x_pos = self.get_frame_x_pos(frame)
            y_pos = height // 2

            mouse_x = self.mouse_pos.x()
            # if abs(mouse_x - x_pos) < dist:
            #    self.draw_keyframe_info(painter, keyframe, x_pos, y_pos)
            # else:
            painter.setPen(self.keyframe_pen)
            painter.drawEllipse(x_pos - 2, y_pos, 3, 3)
            if self.keyframes.modification_type == core.AnimModificationType.SPRITE:
                self.draw_sprite_keyframe(painter, keyframe)

            self.key_frame_coords.append((x_pos, y_pos))

    def draw_keyframe_info(
        self, painter: QtGui.QPainter, keyframe: core.KeyFrame, x_pos: int, y_pos: int
    ) -> None:
        frame = keyframe.frame
        change_in_value = keyframe.change
        ease_mode = keyframe.ease_mode
        ease_power = keyframe.ease_power

        text = ["Frame: " + str(frame), "Change In Value: " + str(change_in_value)]
        if ease_mode == core.EaseMode.INSTANT.value:
            text.append("Ease Mode: Instant")
        elif ease_mode == core.EaseMode.LINEAR.value:
            text.append("Ease Mode: Linear")
        elif ease_mode == core.EaseMode.EXPONENTIAL.value:
            text.append("Ease Mode: Exponential")
            text.append("Ease Power: " + str(ease_power))
        elif ease_mode == core.EaseMode.POLYNOMIAL.value:
            text.append("Ease Mode: Polynomial")
        elif ease_mode == core.EaseMode.SINE.value:
            text.append("Ease Mode: Sine")

        text_width = 0
        text_height = 0
        for text_line in text:
            text_width = max(text_width, painter.fontMetrics().width(text_line))
            text_height += painter.fontMetrics().height()

        text_height += 10
        text_width += 20

        x_pos = max(0, x_pos - text_width // 2)
        y_pos = max(0, y_pos - text_height // 2)

        painter.setPen(self.keyframe_pen)
        painter.drawRect(x_pos + 10, y_pos, text_width, text_height)

        painter.setPen(self.keyframe_pen)
        for i, text_line in enumerate(text):
            painter.drawText(
                x_pos
                + 10
                + text_width // 2
                - painter.fontMetrics().width(text_line) // 2,
                y_pos + painter.fontMetrics().height() * (i + 1),
                text_line,
            )

        self.spacing = max(self.spacing, text_width + 20)
        self.update_spacing(self.spacing)

    def draw_frame_markings(self, painter: QtGui.QPainter) -> None:
        all_frames: list[int] = self.get_all_frames()
        for i in range(self.keyframes.get_end_frame() + 1):
            x_pos = self.get_frame_x_pos(i)
            if i in all_frames:
                painter.setPen(self.marker_pen_color)
            else:
                painter.setPen(self.marker_pen)
            painter.drawLine(x_pos, 0, x_pos, 10)

            if i % 5 == 0:
                painter.setPen(self.marker_text_pen)
                text = str(i)
                text_width = painter.fontMetrics().width(text)
                text_height = painter.fontMetrics().height()
                painter.drawText(x_pos - text_width // 2, 10 + text_height, text)

    def apply_keyframe_modification(self, keyframe: core.KeyFrame) -> int:
        if self.part is None:
            return 0
        frame = keyframe.frame
        current_frame = self.part.current_frame
        self.part.set_action(frame, self.keyframes)
        return current_frame

    def reset_keyframe_modification(self, current_frame: int) -> None:
        if self.part is None:
            return
        self.part.set_action(current_frame, self.keyframes)

    def draw_sprite_keyframe(self, painter: QtGui.QPainter, keyframe: core.KeyFrame):
        if self.part is None:
            return
        current_frame = self.apply_keyframe_modification(keyframe)

        frame = keyframe.frame
        height = self.height()

        img = self.part.image.to_qimage()

        xscale = self.width() / img.width() / 2
        yscale = self.height() / img.height() / 2

        scale = min(xscale, yscale)

        x_pos = self.get_frame_x_pos(frame) - img.width() // 2
        y_pos = height // 2 - img.height() // 2

        original_transform = painter.transform()

        painter.scale(scale, scale)
        painter.translate(x_pos / scale, y_pos / scale)

        painter.drawImage(0, 0, img)

        painter.setTransform(original_transform)

        self.reset_keyframe_modification(current_frame)

        self.spacing = max(self.spacing, img.width() + 10)

        self.update_spacing(self.spacing)

        self.max_height = max(self.max_height, img.height())

    def get_height_needed(self) -> int:
        return self.height() + self.max_height

    def get_all_frames(self) -> list[int]:
        return [keyframe.frame for keyframe in self.keyframes.keyframes]

    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        if a0 is None:
            return
        if a0.button() == QtCore.Qt.MouseButton.LeftButton:
            self.set_frame(a0.x())

    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        if a0 is None:
            return
        if a0.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self.set_frame(a0.x())

        self.mouse_pos = a0.pos()

    def set_frame(self, x_pos: int) -> None:
        width = self.width() - self.spacing
        frame = int(
            ((x_pos - self.spacing // 2) / width) * self.keyframes.get_end_frame()
        )
        self.clock.set(frame)


class AnimBox(QtWidgets.QWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        model: core.Model,
        anim_id: int,
        clock: frame_counter.FrameClock,
        parent: Optional[QtWidgets.QWidget] = None,
        other_models: Optional[list[tuple[core.Model, int]]] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.model = model
        self.anim_id = anim_id
        self.clock = clock
        self.other_models = other_models
        self.setup()

    def setup(self):
        self.layout_box = QtWidgets.QHBoxLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.model_box = ModelViewer(
            self.game_data,
            self.model,
            self.anim_id,
            self.get_part_box_pos,
            self.get_part_box_scale,
            self.align_part_box,
            self.clock,
            self,
            other_models=self.other_models,
        )
        part_id = 0
        self.model_box.set_overlay_part(part_id)

        self.part_box = PartBox(
            self.game_data,
            self.model,
            self.anim_id,
            part_id,
            self.get_model_box_pos,
            self.get_model_box_scale,
            self.align_model_box,
            self.clock,
            self,
        )

        self.split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        self.split.mouseDoubleClickEvent = self.reset_splitter_event
        self.split.setHandleWidth(2)
        self.split.addWidget(self.model_box)
        self.split.addWidget(self.part_box)
        self.layout_box.addWidget(self.split)
        self.reset_splitter()

    def reset_splitter_event(self, a0: QtGui.QMouseEvent) -> None:
        self.reset_splitter()

    def reset_splitter(self):
        self.split.setSizes([self.width() // 2, self.width() // 2])

    def get_model_box_pos(self) -> QtCore.QPointF:
        return QtCore.QPointF(self.model_box.x_pos, self.model_box.y_pos)

    def get_model_box_scale(self) -> float:
        return self.model_box.scale

    def get_part_box_pos(self) -> QtCore.QPointF:
        return QtCore.QPointF(
            self.part_box.part_box.x_pos, self.part_box.part_box.y_pos
        )

    def get_part_box_scale(self) -> float:
        return self.part_box.part_box.scale

    def align_model_box(self) -> None:
        self.model_box.align_part_view_to_model()

    def align_part_box(self) -> None:
        self.part_box.part_box.align_part_view_to_model()

    def set_part_id(self, part_id: int) -> bool:
        success = self.part_box.set_part_id(part_id)
        if success:
            self.model_box.set_overlay_part(part_id)
        return success


class AnimControls(QtWidgets.QWidget):
    def __init__(
        self,
        clock: frame_counter.FrameClock,
        link_anim_boxes: Callable[[], None],
        toggle_grid: Callable[[], None],
        parent: Optional[QtWidgets.QWidget] = None,
        model_box: Optional[ModelViewer] = None,
    ):
        super().__init__(parent)
        self.clock = clock
        self.link_anim_boxes = link_anim_boxes
        self.toggle_grid = toggle_grid
        # self.locale_handler = core.local_manager
        self.model_box = model_box
        self.setup()

    def setup(self):
        self.layout_box = QtWidgets.QGridLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.layout_box.setSpacing(0)

        self.check_layout = QtWidgets.QHBoxLayout()
        self.check_layout.setContentsMargins(0, 0, 0, 0)
        self.check_layout.setSpacing(0)
        self.layout_box.addLayout(self.check_layout, 0, 0)

        self.link_check_box = QtWidgets.QCheckBox(self)

        self.link_icon = fontawsome.get_icon("link")
        # self.link_tt = self.locale_handler.get_key("link_tt")

        self.link_check_box.setIcon(self.link_icon)
        # self.link_check_box.setToolTip(self.link_tt)

        self.link_check_box.stateChanged.connect(self.link)
        self.check_layout.addWidget(self.link_check_box)

        self.grid_check_box = QtWidgets.QCheckBox(self)

        self.grid_icon = fontawsome.get_icon("th")
        # self.grid_tt = self.locale_handler.get_key("grid_tt")

        self.grid_check_box.setIcon(self.grid_icon)
        # self.grid_check_box.setToolTip(self.grid_tt)

        self.grid_check_box.stateChanged.connect(self.toggle_grid)
        self.check_layout.addWidget(self.grid_check_box)

        self.check_layout.addStretch(1)

        self.control_layout = QtWidgets.QHBoxLayout()
        self.control_layout.setContentsMargins(0, 0, 0, 0)
        self.control_layout.setSpacing(0)
        self.layout_box.addLayout(self.control_layout, 0, 1)

        self.back_1_frame_button = QtWidgets.QPushButton(self)
        self.back_1_frame_icon = fontawsome.get_icon("step-backward")
        self.back_1_frame_button.setIcon(self.back_1_frame_icon)
        self.back_1_frame_button.clicked.connect(self.go_back_1_frame)
        self.control_layout.addWidget(self.back_1_frame_button, 0)
        self.back_1_frame_button.setFixedWidth(30)

        self.pause_button = QtWidgets.QPushButton(self)
        self.pause_icon = fontawsome.get_icon("pause")
        self.play_icon = fontawsome.get_icon("play")
        self.pause_button.setIcon(self.pause_icon)
        self.pause_button.clicked.connect(self.pause)
        self.control_layout.addWidget(self.pause_button, 0)
        self.pause_button.setFixedWidth(30)

        self.forward_1_frame_button = QtWidgets.QPushButton(self)
        self.forward_1_frame_icon = fontawsome.get_icon("step-forward")
        self.forward_1_frame_button.setIcon(self.forward_1_frame_icon)
        self.forward_1_frame_button.clicked.connect(self.advance_1_frame)
        self.control_layout.addWidget(self.forward_1_frame_button, 0)
        self.forward_1_frame_button.setFixedWidth(30)

        self.save_gif_button = QtWidgets.QPushButton(self)
        self.save_gif_icon = fontawsome.get_icon("save")
        self.save_gif_button.setIcon(self.save_gif_icon)
        self.save_gif_button.clicked.connect(self.save_video)
        self.control_layout.addWidget(self.save_gif_button, 0)
        self.save_gif_button.setFixedWidth(30)

        self.layout_box.setColumnStretch(0, 1)
        self.layout_box.setColumnStretch(1, 1)
        self.layout_box.setColumnStretch(2, 1)

    def save_video(self):
        if self.model_box is None:
            return
        path = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save mp4", "", "mp4 (*.mp4)"
        )[0]
        if path == "":
            return
        self.model_box.save_frames = True
        should_loop = self.model_box.should_loop
        self.model_box.should_loop = True
        self.clock.frame = 0
        was_stopped = self.clock.is_stopped()
        temp_folder = core.TempFolder("frames")
        temp_folder.path.remove()
        self.clock.start()
        for i in range(self.model_box.model.get_total_frames()):
            self.clock.advance(1)
            QtWidgets.QApplication.processEvents()
        self.model_box.save_frames = False
        self.model_box.should_loop = should_loop
        if was_stopped:
            self.clock.stop()
        path = core.Path(path)
        if path.get_extension() != "mp4":
            path = path.change_extension("mp4")
        paths = temp_folder.path.glob("frame_*.png")
        paths.sort(key=lambda x: int(x.basename().split("_")[1].split(".")[0]))
        self.model_box.create_video(paths, path)
        temp_folder.path.remove()

    def go_back_1_frame(self):
        self.clock.go_back(1)

    def advance_1_frame(self):
        self.clock.advance(1)

    def play(self):
        self.clock.start()
        self.pause_button.setIcon(self.pause_icon)
        self.pause_button.clicked.connect(self.pause)
        self.pause_button.clicked.disconnect(self.play)

    def pause(self):
        self.clock.stop()
        self.pause_button.setIcon(self.play_icon)
        self.pause_button.clicked.connect(self.play)
        self.pause_button.clicked.disconnect(self.pause)

    def toggle_play(self):
        if self.clock.is_stopped():
            self.play()
        else:
            self.pause()

    def link(self):
        self.link_anim_boxes()

    def toggle_grid_event(self):
        self.toggle_grid()


class AnimEditor(QtWidgets.QWidget):
    def __init__(
        self,
        game_data: core.GamePacks,
        model: core.Model,
        anim_id: int,
        parent: Optional[QtWidgets.QWidget] = None,
        other_models: Optional[list[tuple[core.Model, int]]] = None,
    ):
        super().__init__(parent)
        self.game_data = game_data
        self.model = model
        self.anim_id = anim_id
        self.other_models = other_models
        self.setup()

    def setup(self):
        self.resize(800, 600)
        self.layout_box = QtWidgets.QGridLayout(self)
        self.layout_box.setContentsMargins(0, 0, 0, 0)
        self.layout_box.setSpacing(0)
        self.clock = frame_counter.FrameClock(30)
        self.clock.start()

        self.anim_box = AnimBox(
            self.game_data,
            self.model,
            self.anim_id,
            self.clock,
            self,
            self.other_models,
        )

        self.anim_controls = AnimControls(
            self.clock,
            self.link_anim_boxes,
            self.toggle_grid,
            self,
            self.anim_box.model_box,
        )

        self.layout_box.addWidget(self.anim_controls, 0, 0, 1, 1)
        self.layout_box.addWidget(self.anim_box, 1, 0, 1, 1)

        self.layout_box.setColumnStretch(0, 1)
        self.layout_box.setRowStretch(1, 1)

    def link_anim_boxes(self):
        self.anim_box.part_box.part_box.always_align = (
            not self.anim_box.part_box.part_box.always_align
        )
        self.anim_box.model_box.always_align = not self.anim_box.model_box.always_align

    def toggle_grid(self):
        self.anim_box.part_box.part_box.show_grid = (
            not self.anim_box.part_box.part_box.show_grid
        )
        self.anim_box.model_box.show_grid = not self.anim_box.model_box.show_grid

    def keyPressEvent(self, a0: Optional[QtGui.QKeyEvent]) -> None:
        if a0 is None:
            return

        if a0.key() == QtCore.Qt.Key.Key_Space:
            self.anim_controls.toggle_play()

        current_part_id = self.anim_box.part_box.part_box.part_id
        should_update = False
        if a0.key() == QtCore.Qt.Key.Key_Right:
            self.anim_box.part_box.part_box.part_id += 1
            should_update = True

        if a0.key() == QtCore.Qt.Key.Key_Left:
            self.anim_box.part_box.part_box.part_id -= 1
            should_update = True

        if should_update:
            success = self.anim_box.set_part_id(self.anim_box.part_box.part_box.part_id)
            if not success:
                self.anim_box.part_box.part_box.part_id = current_part_id


def view_model(
    game_data: core.GamePacks,
    model: core.Model,
    anim_id: int,
    other_models: Optional[list[tuple[core.Model, int]]] = None,
):
    app = QtWidgets.QApplication([])

    img = core.BCImage(core.Path("assets", True).add("logo.png").read())
    img.crop_circle()
    icon = img.to_qicon()

    app.setWindowIcon(icon)

    window = AnimEditor(
        game_data,
        model,
        anim_id,
        other_models=other_models,
    )
    window.show()
    app.exec_()
    return window


if __name__ == "__main__":
    cc = core.CountryCode.EN
    gv = core.GameVersion.from_string_latest("12.3.0", cc)
    apk = core.Apk(gv, cc)
    apk.download()
    apk.extract()

    game_packs = core.GamePacks.from_apk(apk)
    cat_id = 43
    cats = core.Cats.from_game_data(game_packs, [cat_id])
    cat = cats.data[cat_id]
    form = cat.forms[core.CatFormType.FIRST]
    model_ = form.get_anim().model

    spawn_anim = form.get_stats().spawn_anim
    spawn_anim_id = spawn_anim.model_id
    spawn_animation_flag = spawn_anim.has_entry_maanim

    other_model = None

    if spawn_animation_flag:
        battle_entry = f"battle_entry_{spawn_anim_id:03d}"
        other_model = core.Model.load(
            f"{battle_entry}.mamodel",
            f"{battle_entry}.imgcut",
            f"{battle_entry}.png",
            [
                f"{battle_entry}.maanim",
            ],
            game_packs,
        )

    anim_id = 0

    if other_model is not None and anim_id == 4:
        view_model(game_packs, model_, anim_id, other_models=[(other_model, 0)])
    else:
        view_model(game_packs, model_, anim_id)
