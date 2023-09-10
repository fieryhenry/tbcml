import math
from typing import Optional, Callable

from PyQt5 import QtCore, QtGui, QtWidgets

from tbcml import core
from tbcml.ui.anim import frame_counter
from tbcml.ui.utils import fontawsome

import moviepy.video.io.ImageSequenceClip


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
        self.menu.addAction(
            core.local_manager.get_key("reset_view_position"), self.reset_position
        )
        if self.is_model_viewer:
            if self.should_bring_to_front:
                self.menu.addAction(
                    core.local_manager.get_key("remove_selected_part_from_front"),
                    self.toggle_bring_to_front,
                )
            else:
                self.menu.addAction(
                    core.local_manager.get_key("bring_selected_part_to_front"),
                    self.toggle_bring_to_front,
                )
            self.menu.addAction(
                core.local_manager.get_key("align_model_to_part"),
                self.align_part_view_to_model,
            )
        else:
            self.menu.addAction(
                core.local_manager.get_key("align_part_to_model"),
                self.align_part_view_to_model,
            )

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

        self.test_label = QtWidgets.QLabel(self)
        self.test_label.setText("Test")

        self.split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical, self)
        self.split.setHandleWidth(2)
        self.split.mouseDoubleClickEvent = self.reset_splitter_event
        self.split.addWidget(self.part_box)
        self.split.addWidget(self.test_label)

        self.layout_box.addWidget(self.split)
        self.reset_splitter()

    def reset_splitter_event(self, a0: QtGui.QMouseEvent) -> None:
        self.reset_splitter()

    def reset_splitter(self) -> None:
        self.split.setSizes([self.split.width() // 2] * 2)


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
        part_id = 1
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
        self.locale_handler = core.local_manager
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
        self.link_tt = self.locale_handler.get_key("link_tt")

        self.link_check_box.setIcon(self.link_icon)
        self.link_check_box.setToolTip(self.link_tt)

        self.link_check_box.stateChanged.connect(self.link)
        self.check_layout.addWidget(self.link_check_box)

        self.grid_check_box = QtWidgets.QCheckBox(self)

        self.grid_icon = fontawsome.get_icon("th")
        self.grid_tt = self.locale_handler.get_key("grid_tt")

        self.grid_check_box.setIcon(self.grid_icon)
        self.grid_check_box.setToolTip(self.grid_tt)

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
    cc = core.CountryCode.JP
    gv = core.GameVersion.from_string_latest("12.6.1", cc)
    apk = core.Apk(gv, cc)
    apk.extract()
    apk.copy_server_files()

    game_packs = core.GamePacks.from_apk(apk)
    cat_id = 207
    cats = core.Cats.from_game_data(game_packs, [cat_id])
    cat = cats.data[cat_id]
    form = cat.forms[core.CatFormType.SECOND]
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

    anim_id = 4

    if other_model is not None and anim_id == 4:
        view_model(game_packs, model_, anim_id, other_models=[(other_model, 0)])
    else:
        view_model(game_packs, model_, anim_id)
