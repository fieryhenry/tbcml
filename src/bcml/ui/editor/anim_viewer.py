from PyQt5 import QtCore, QtGui, QtWidgets
from bcml.core import locale_handler, anim
from typing import Optional


class AnimViewer(QtWidgets.QWidget):
    def __init__(
        self,
        model: anim.model.Model,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(AnimViewer, self).__init__(parent)
        self.model = model

        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()
        self.setup_data()
        self.setup_gradient()
        self.setup_clock()

    def setup_ui(self):
        self.setObjectName("anim_viewer")
        self.zoom_factor = 0.5
        self.image_pos = QtCore.QPoint(0, 0)

        self.setMouseTracking(True)

        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._layout.addStretch(1)

        self.anim_dropdown = QtWidgets.QComboBox(self)
        self.anim_dropdown.addItems(["Walk", "Idle", "Attack", "Knockback"])
        self.anim_dropdown.currentIndexChanged.connect(self.change_anim)
        self._layout.addWidget(self.anim_dropdown)

    def change_anim(self, index: int):
        self.model.set_part_anims(index)
        self.frame = 0
        self.end_frame = self.model.get_end_frame()

    def setup_data(self):
        self.sorted_parts = self.model.get_sorted_parts()
        self.model.set_required()
        self.model.set_part_anims(0)
        self.end_frame = self.model.get_end_frame()

    def setup_clock(self):
        self.frame = 0
        fps = 30
        self.frame_boost = 2
        fps *= self.frame_boost
        self.clock = QtCore.QTimer(self)
        self.clock.setInterval(1000 // fps)
        self.clock.timeout.connect(self.update)
        self.clock.start()

    def setup_gradient(self):
        self.color_1 = QtGui.QColor(70, 140, 160)
        self.color_2 = QtGui.QColor(85, 185, 205)

        self.gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        self.gradient.setColorAt(0, self.color_1)
        self.gradient.setColorAt(0.5, self.color_2)
        self.gradient.setColorAt(1, self.color_1)

    def paintEvent(self, a0: QtGui.QPaintEvent) -> None:
        self.gradient.setFinalStop(0, self.height())
        painter = QtGui.QPainter(self)
        painter.fillRect(self.rect(), self.gradient)

        # painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform)

        center = self.rect().center()
        painter.translate(
            self.image_pos.x() + center.x(),
            self.image_pos.y() + center.y(),
        )
        zoom_factor = self.zoom_factor

        # cProfile.runctx(
        #     "self.draw_profiler(painter)", globals(), locals(), sort="cumtime"
        # )
        # raise Exception("stop")

        self.draw_model_rect(painter)
        self.draw_model(painter, zoom_factor * 16, zoom_factor * 16)

    def draw_profiler(self, painter: QtGui.QPainter):
        for _ in range(500):
            self.draw_model(painter, 4, 4)

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

    def draw_model(self, painter: QtGui.QPainter, base_x: float, base_y: float):
        frame = int(self.frame / self.frame_boost) % self.end_frame

        self.model.set_action(frame)
        for part in self.sorted_parts:
            if part.parent is None:
                continue
            if part.unit_id < 0:
                continue
            part.draw_part(painter, base_x, base_y)
        self.frame += 1

    def save(self):
        pass

    def wheelEvent(self, a0: QtGui.QWheelEvent) -> None:
        zoom_delta = a0.angleDelta().y() / 120
        self.zoom_factor *= pow(1.1, zoom_delta)

        self.zoom_pos = a0.pos()

        # self.update()

    def mousePressEvent(self, a0: QtGui.QMouseEvent) -> None:
        self.last_mouse_pos = a0.pos()

    def mouseMoveEvent(self, a0: QtGui.QMouseEvent) -> None:
        if a0.buttons() == QtCore.Qt.MouseButton.LeftButton:
            delta: QtCore.QPoint = a0.pos() - self.last_mouse_pos
            self.image_pos += delta
            self.last_mouse_pos = a0.pos()

            # self.update()
