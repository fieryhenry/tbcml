import tbcml

try:
    from PyQt5 import QtWidgets, QtGui, QtCore
except ImportError:
    pass
import time


class AnimViewer(QtWidgets.QOpenGLWidget):
    def __init__(self, model: "tbcml.Model"):
        super().__init__()
        self.model = model
        self.anim = tbcml.Anim(model, 2)

        self.x_offset = 0
        self.y_offset = 0
        self.last_pos = None
        self.prev_time = time.perf_counter()
        self.curr_time = time.perf_counter()

        # set opengl format
        fmt = self.format()
        fmt.setSwapInterval(0)
        self.setFormat(fmt)

        self.zoom = 1
        self.anim.set_part_vals()

        self.gradient = QtGui.QLinearGradient(0, 0, 0, self.height())
        self.gradient.setColorAt(0, QtGui.QColor(88, 184, 204))
        self.gradient.setColorAt(1, QtGui.QColor(108, 200, 206))

        self.frame = 0
        self.clock = QtCore.QTimer()
        self.clock.timeout.connect(self.update_frame)
        self.clock.start()

        self.setMouseTracking(True)

    def draw(self, painter: QtGui.QPainter):
        painter.translate(self.x_offset, self.y_offset)
        self.anim.set_frame(self.frame)
        self.anim.draw_frame(painter, 10 * self.zoom, 10 * self.zoom)

        # print(self.get_fps())

    def paintEvent(self, event: QtGui.QPaintEvent):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setRenderHint(QtGui.QPainter.SmoothPixmapTransform)
        self.draw_bg(painter)

        self.draw(painter)

    def draw_bg(self, painter: QtGui.QPainter):
        self.gradient.setFinalStop(0, self.height())
        painter.setBrush(self.gradient)
        painter.drawRect(0, 0, self.width(), self.height())

    def update_frame(self):
        self.prev_time = self.curr_time
        self.curr_time = time.perf_counter()
        self.frame += 1
        # force paint event
        self.update()

    def get_fps(self):
        diff = self.curr_time - self.prev_time
        if diff == 0:
            return 0
        return 1 / diff

    # drag camera
    def mousePressEvent(self, event: QtGui.QMouseEvent):
        self.last_pos = event.pos()

    def mouseMoveEvent(self, event: QtGui.QMouseEvent):
        if self.last_pos is None:
            return

        delta = event.pos() - self.last_pos
        self.x_offset += delta.x()
        self.y_offset += delta.y()
        self.last_pos = event.pos()
        self.update()

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent):
        self.last_pos = None

    # zoom
    def wheelEvent(self, event: QtGui.QWheelEvent):
        if event.angleDelta().y() > 0:
            self.zoom *= 1.1
        else:
            self.zoom /= 1.1
        self.update()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, model: "tbcml.Model"):
        super().__init__()
        self.model = model
        self.init_ui()

    def init_ui(self):
        self.anim_viewer = AnimViewer(self.model)
        self.setCentralWidget(self.anim_viewer)
        self.show()


def main():
    loader = tbcml.ModLoader("en", "13.1.1")
    loader.initialize()

    form = tbcml.CatForm(tbcml.CatFormType.THIRD)
    form.read_anim(43, loader.get_game_packs())
    model = form.get_anim()

    app = QtWidgets.QApplication([])
    window = MainWindow(model)
    app.exec_()


if __name__ == "__main__":
    main()
