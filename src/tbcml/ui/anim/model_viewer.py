from typing import Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from tbcml import core
from tbcml.ui.anim import frame_counter


class ModelViewer(QtWidgets.QOpenGLWidget):
    def __init__(
        self,
        model: core.Model,
        anim_id: int,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super().__init__(parent)
        self.model = model
        self.anim_id = anim_id
        self.setup()

    def setup(self):
        gradient_color_1 = QtGui.QColor(70, 140, 160)
        gradient_color_2 = QtGui.QColor(85, 185, 205)
        gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, gradient_color_1)
        gradient.setColorAt(0.5, gradient_color_2)
        gradient.setColorAt(1, gradient_color_1)
        self.gradient = gradient

        self.model.set_required()
        self.model.set_keyframes_sets(self.anim_id)

        self.x_pos = self.width() / 2
        self.y_pos = self.height() / 2

        self.prev_x_pos = 0.0
        self.prev_y_pos = 0.0

        self.scale = 10.0

        self.parts = self.model.get_sorted_parts()

        self.frame_counter = frame_counter.FrameClock(30)
        self.frame_counter.add_func(self.update)

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)

        # Draw the background
        self.gradient.setFinalStop(0, self.height())
        painter.fillRect(self.rect(), self.gradient)

        # Draw the model
        painter.translate(self.x_pos, self.y_pos)
        self.model.set_action(self.frame_counter.get_frame())

        for part in self.parts:
            part.draw_part(painter, self.scale, self.scale)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        self.prev_x_pos = event.x()
        self.prev_y_pos = event.y()

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:
        self.x_pos += event.x() - self.prev_x_pos
        self.y_pos += event.y() - self.prev_y_pos
        self.prev_x_pos = event.x()
        self.prev_y_pos = event.y()

        self.update()

    def wheelEvent(self, event: QtGui.QWheelEvent) -> None:
        self.scale += event.angleDelta().y() / 120
        self.scale = max(0.5, self.scale)
        self.update()


# if __name__ == "__main__":
#     cc = core.CountryCode.EN
#     gv = core.GameVersion.from_string_latest("12.3.0", cc)
#     apk = core.Apk(gv, cc)
#     apk.extract()
#     apk.copy_server_files()
#
#     game_packs = core.GamePacks.from_apk(apk)
#     cat_id = 43
#     cats = core.Cats.from_game_data(game_packs, [cat_id])
#     cat = cats.cats[cat_id]
#     form = cat.forms[core.CatFormType.THIRD]
#     model = form.anim.model
#
#     app = QtWidgets.QApplication([])
#     window = ModelViewer(model, 0)
#     window.show()
#     app.exec_()
#
