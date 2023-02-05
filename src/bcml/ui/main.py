from typing import Optional
from PyQt5 import QtCore, QtGui, QtWidgets
from bcml.ui import (
    apk_manager,
    mod_manager,
    server_files_manager,
    mod_loader,
)
from bcml.core import io


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super(MainWindow, self).__init__(parent)
        self.setup_ui()

    def create_toolbar(self):
        self.toolbar = QtWidgets.QToolBar()
        self.toolbar.setToolButtonStyle(
            QtCore.Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        self.addToolBar(QtCore.Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        self.file_menu = QtWidgets.QMenu("File")
        self.file_menu.addAction("APK Manager", self.open_apk_manager)
        self.file_menu.addAction("Server Files Manager", self.open_server_files_manager)
        self.file_menu.addAction("Load Mods into Game", self.load_mods_into_game)
        self.toolbar.addAction(self.file_menu.menuAction())

    def setup_ui(self):
        self.setObjectName("MainWindow")
        self.resize(900, 700)
        self.create_toolbar()
        self.setWindowTitle("Battle Cats Mod Loader")
        icon_path = io.path.Path(is_relative=True).add("assets", "icon.png")
        self.setWindowIcon(QtGui.QIcon(str(icon_path)))

        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.setCentralWidget(self.centralwidget)

        self._layout = QtWidgets.QVBoxLayout()
        self.centralwidget.setLayout(self._layout)

        self.mod_view = mod_manager.ModView(self)
        self._layout.addWidget(self.mod_view)

        # self.check_apk_selected()

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

    def open_server_files_manager(self):
        self.server_files_manager = server_files_manager.ServerFilesManager()
        self.server_files_manager.show()

    def load_mods_into_game(self):
        self.mod_loader = mod_loader.ModLoader()
        self.mod_loader.show()

    def check_apk_selected(self):
        if not io.config.Config().get(io.config.Key.SELECTED_APK):
            self.open_apk_manager()


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
