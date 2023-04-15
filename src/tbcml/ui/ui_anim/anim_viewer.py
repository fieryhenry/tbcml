from PyQt5 import QtCore, QtGui, QtWidgets
from tbcml.core import locale_handler, anim, io
from typing import Optional
from tbcml.ui import utils


class AnimViewer(QtWidgets.QOpenGLWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: Optional[QtWidgets.QWidget] = None,
        anim_id: Optional[int] = None,
        force_repeat: bool = False,
    ):
        super(AnimViewer, self).__init__(parent)
        self.model = model
        self.anim_id = anim_id
        self.index = 0
        self.force_repeat = force_repeat
        self.overlay_part_id = None
        self.raw = False
        self.path = None

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_data()
        self.setup_ui()
        self.setup_gradient()
        self.setup_clock()

    def setup_ui(self):
        self.setObjectName("anim_viewer")
        self.zoom_factor = 0.5
        self.image_pos = QtCore.QPoint(0, 0)

        self.setMouseTracking(True)
        self.resize(400, 400)
        self.setMinimumSize(100, 100)

        if self.anim_id is None:
            self._layout = QtWidgets.QVBoxLayout(self)
            self._layout.setContentsMargins(0, 0, 0, 0)
            self._layout.setSpacing(0)
            self._layout.addStretch(1)

            self.anim_dropdown = QtWidgets.QComboBox(self)
            keys = ["walk", "idle", "attack", "knockback"]
            for key in keys:
                self.anim_dropdown.addItem(self.locale_manager.search_key(key))
            self.anim_dropdown.currentIndexChanged.connect(self.change_anim)
            self._layout.addWidget(self.anim_dropdown)
            self.change_anim(0)
        else:
            self.change_anim(self.anim_id)

    def change_anim(self, index: int):
        self.model.set_keyframes_sets(index)
        self.total_frames = self.model.get_total_frames()
        self.index = index

    def setup_data(self):
        self.sorted_parts = self.model.get_sorted_parts()
        self.model.set_required()
        self.model.set_keyframes_sets(self.index)
        self.total_frames = self.model.get_total_frames()

    def setup_clock(self):
        fps = 30
        self.clock = utils.clock.Clock(fps, 2)
        self.clock.connect(self.update_frame)

    def disconnect_clock(self):
        self.clock.disconnect(self.update_frame)

    def set_frame(self, frame: int):
        self.clock.set_frame(frame)

    def start_clock(self):
        self.clock.start()

    def stop_clock(self):
        self.clock.stop()

    def set_overlay_id(self, part_id: int):
        self.overlay_part_id = part_id

    def setup_gradient(self):
        self.color_1 = QtGui.QColor(70, 140, 160)
        self.color_2 = QtGui.QColor(85, 185, 205)

        self.gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        self.gradient.setColorAt(0, self.color_1)
        self.gradient.setColorAt(0.5, self.color_2)
        self.gradient.setColorAt(1, self.color_1)

    def paintEvent(self, e: QtGui.QPaintEvent) -> None:
        self.paint()

    def paint(self):
        self.gradient.setFinalStop(0, self.height())
        painter = QtGui.QPainter(self)
        if not self.raw:
            painter.fillRect(self.rect(), self.gradient)
        else:
            self.img = QtGui.QImage(self.size(), QtGui.QImage.Format.Format_ARGB32)
            self.img.fill(QtCore.Qt.GlobalColor.transparent)
            painter = QtGui.QPainter(self.img)
            painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        center = self.rect().center()
        painter.translate(
            self.image_pos.x() + center.x(),
            self.image_pos.y() + center.y(),
        )
        zoom_factor = self.zoom_factor

        if not self.raw:
            self.draw_model_rect(painter)
        mult = 16 * zoom_factor
        self.draw_model(
            painter, mult, mult, self.overlay_part_id if not self.raw else None
        )

        self.raw = False
        if self.path is not None:
            self.img.save(self.path.to_str())
            self.path = None

    def draw_model_rect(self, painter: QtGui.QPainter):
        p0_x = -400 * self.zoom_factor
        p0_y = 0 * self.zoom_factor
        p1_x = 800 * self.zoom_factor
        p1_y = 200 * self.zoom_factor
        p2_x = 0 * self.zoom_factor
        p2_y = -500 * self.zoom_factor
        painter.setPen(
            QtGui.QPen(QtCore.Qt.GlobalColor.white, 1, QtCore.Qt.PenStyle.SolidLine)
        )
        painter.drawRect(QtCore.QRectF(p0_x, p0_y, p1_x, p1_y))
        painter.setPen(
            QtGui.QPen(QtCore.Qt.GlobalColor.red, 1, QtCore.Qt.PenStyle.SolidLine)
        )
        painter.drawLine(0, 0, int(p2_x), int(p2_y))

    def get_frame(self):
        return self.clock.get_frame()

    def draw_model(
        self,
        painter: QtGui.QPainter,
        base_x: float,
        base_y: float,
        overlay_part_id: Optional[int] = None,
        frame: Optional[int] = None,
    ):
        if frame is None:
            if self.force_repeat:
                frame = self.get_frame() % self.total_frames
            else:
                frame = self.get_frame()

        self.model.set_action(frame)
        for part in self.sorted_parts:
            part.draw_part(painter, base_x, base_y)
        if overlay_part_id is not None:
            overlay_part = self.model.get_part(overlay_part_id)
            overlay_part.draw_part(
                painter, base_x, base_y, draw_overlay=True, just_overlay=True
            )

    def save_frame_to_png(self, path: "io.path.Path"):
        self.raw = True
        self.path = path
        self.update()

    def update_frame(self):
        self.update()

    def wheelEvent(self, a0: QtGui.QWheelEvent) -> None:
        zoom_delta = a0.angleDelta().y() / 120
        self.zoom_factor *= pow(1.1, zoom_delta)

        self.zoom_pos = a0.pos()

        self.update()

    def mousePressEvent(self, a0: QtGui.QMouseEvent) -> None:
        self.last_mouse_pos = a0.pos()

    def mouseMoveEvent(self, a0: QtGui.QMouseEvent) -> None:
        if a0.buttons() == QtCore.Qt.MouseButton.LeftButton:
            delta: QtCore.QPoint = a0.pos() - self.last_mouse_pos  # type: ignore
            self.image_pos += delta  # type: ignore
            self.last_mouse_pos = a0.pos()

            self.update()


class PartViewer(QtWidgets.QOpenGLWidget):
    def __init__(
        self,
        model: anim.model.Model,
        part_ids: list[int],
        anim_id: int,
        clock: utils.clock.Clock,
        parent: Optional[QtWidgets.QWidget] = None,
        force_repeat: bool = False,
        draw_overlay: bool = False,
    ):
        super().__init__(parent)
        self.model = model
        self.part_ids = part_ids
        self.anim_id = anim_id
        self.clock = clock
        self.force_repeat = force_repeat
        self.draw_overlay = draw_overlay

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_data()
        self.setup_ui()
        self.setup_gradient()
        self.setup_clock()

    def setup_ui(self):
        self.setMouseTracking(True)
        self.zoom_factor = 0.5
        self.image_pos = QtCore.QPoint(0, 0)
        self.resize(400, 400)
        self.setMinimumSize(100, 100)

        self.setMouseTracking(True)

        self.change_anim(self.anim_id)

    def change_anim(self, index: int):
        self.model.set_keyframes_sets(index)
        self.total_frames = self.model.get_total_frames()

    def setup_data(self):
        self.model.set_required()
        self.model.set_keyframes_sets(self.anim_id)
        self.total_frames = self.model.get_total_frames()

    def setup_clock(self):
        self.clock.connect(self.update_frame)

    def disconnect_clock(self):
        self.clock.disconnect(self.update_frame)

    def setup_gradient(self):
        self.color_1 = QtGui.QColor(70, 140, 160)
        self.color_2 = QtGui.QColor(85, 185, 205)

        self.gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        self.gradient.setColorAt(0, self.color_1)
        self.gradient.setColorAt(0.5, self.color_2)
        self.gradient.setColorAt(1, self.color_1)

    def paintEvent(self, e: QtGui.QPaintEvent) -> None:
        self.paint()

    def paint(self):
        self.gradient.setFinalStop(0, self.height())
        painter = QtGui.QPainter(self)
        painter.fillRect(self.rect(), self.gradient)

        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        center = self.rect().center()
        painter.translate(
            self.image_pos.x() + center.x(),
            self.image_pos.y() + center.y(),
        )
        zoom_factor = self.zoom_factor

        self.draw_part_rect(painter)
        self.draw_part(painter, zoom_factor * 16, zoom_factor * 16)

    def update_frame(self):
        self.update()

    def draw_part_rect(self, painter: QtGui.QPainter):
        p0_x = -400 * self.zoom_factor
        p0_y = 0 * self.zoom_factor
        p1_x = 800 * self.zoom_factor
        p1_y = 200 * self.zoom_factor
        p2_x = 0 * self.zoom_factor
        p2_y = -500 * self.zoom_factor
        painter.setPen(
            QtGui.QPen(QtCore.Qt.GlobalColor.white, 1, QtCore.Qt.PenStyle.SolidLine)
        )
        painter.drawRect(QtCore.QRectF(p0_x, p0_y, p1_x, p1_y))
        painter.setPen(
            QtGui.QPen(QtCore.Qt.GlobalColor.red, 1, QtCore.Qt.PenStyle.SolidLine)
        )
        painter.drawLine(0, 0, int(p2_x), int(p2_y))

    def get_valid_parts(self) -> list[anim.model_part.ModelPart]:
        valid_parts: list[anim.model_part.ModelPart] = []
        for part_id in self.part_ids:
            try:
                part = self.model.get_part(part_id)
            except ValueError:
                continue
            for keyframes in part.keyframes_sets:
                part.set_action(self.clock.get_frame(), keyframes)
            valid_parts.append(part)
        return valid_parts

    def draw_part(
        self,
        painter: QtGui.QPainter,
        base_x: float,
        base_y: float,
    ):
        if self.force_repeat:
            frame = self.clock.get_frame() % self.total_frames
        else:
            frame = self.clock.get_frame()

        self.valid_parts: list[anim.model_part.ModelPart] = []
        for part_id in self.part_ids:
            try:
                part = self.model.get_part(part_id)
            except ValueError:
                continue
            for keyframes in part.keyframes_sets:
                part.set_action(frame, keyframes)
            self.valid_parts.append(part)

        parts_sorted = sorted(
            self.valid_parts,
            key=lambda part: part.z_depth,
        )
        for part in parts_sorted:
            part.draw_part(painter, base_x, base_y, draw_overlay=self.draw_overlay)

    def wheelEvent(self, a0: QtGui.QWheelEvent) -> None:
        zoom_delta = a0.angleDelta().y() / 120
        self.zoom_factor *= pow(1.1, zoom_delta)

        self.zoom_pos = a0.pos()

        self.update()

    def mousePressEvent(self, a0: QtGui.QMouseEvent) -> None:
        self.last_mouse_pos = a0.pos()

    def mouseMoveEvent(self, a0: QtGui.QMouseEvent) -> None:
        if a0.buttons() == QtCore.Qt.MouseButton.LeftButton:
            delta: QtCore.QPoint = a0.pos() - self.last_mouse_pos  # type: ignore
            self.image_pos += delta  # type: ignore
            self.last_mouse_pos = a0.pos()

            self.update()
