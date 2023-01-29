from typing import Optional
from PyQt5 import QtCore, QtGui, QtWidgets
from bcml.ui import apk_manager
from bcml.core import io


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super(MainWindow, self).__init__(parent)
        self.setup_ui()

    def create_toolbar(self):
        self.toolbar = QtWidgets.QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setFloatable(False)
        self.toolbar.setToolButtonStyle(
            QtCore.Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        self.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        self.file_menu = QtWidgets.QMenu("File")
        self.file_menu.addAction("APK Manager", self.open_apk_manager)
        self.toolbar.addAction(self.file_menu.menuAction())

    def setup_ui(self):
        self.setObjectName("MainWindow")
        self.resize(800, 600)
        self.create_toolbar()
        self.setWindowTitle("Battle Cats Mod Loader")
        icon_path = io.path.Path(is_relative=True).add("assets", "icon.png")
        self.setWindowIcon(QtGui.QIcon(str(icon_path)))

    def run(self):
        self.show()
        self.raise_()
        self.activateWindow()

        app = QtWidgets.QApplication.instance()
        app.exec_()

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if (
            event.key() == QtCore.Qt.Key.Key_C
            and event.modifiers() == QtCore.Qt.KeyboardModifier.ControlModifier
        ):
            self.close()

    def open_apk_manager(self):
        self.apk_man = apk_manager.ApkManager()
        self.apk_man.show()


def clear_layout(layout: QtWidgets.QLayout):
    while layout.count():
        child = layout.takeAt(0)
        try:
            child.widget().deleteLater()
        except AttributeError:
            pass
        try:
            clear_layout(child.layout())
        except AttributeError:
            pass
