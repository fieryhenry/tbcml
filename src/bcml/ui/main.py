from typing import Any, Callable, Optional
from PyQt5 import QtCore, QtGui, QtWidgets
from bcml.ui import (
    apk_manager,
    mod_manager,
    ui_dialog,
    server_files_manager,
    mod_loader,
)
from bcml.core import io


class Change:
    def __init__(
        self,
        on_has_changes: Callable[[], bool],
        on_save: Callable[..., Any],
        on_has_changes_args: Optional[list[Any]] = None,
        save_args: Optional[list[Any]] = None,
    ):
        self.on_has_changes = on_has_changes
        self.on_save = on_save
        if save_args is None:
            save_args = []
        if on_has_changes_args is None:
            on_has_changes_args = []
        self.save_args = save_args
        self.on_has_changes_args = on_has_changes_args

    def save(self):
        if self.has_changes():
            self.on_save(*self.save_args)

    def has_changes(self):
        return self.on_has_changes(*self.on_has_changes_args)


class Changes:
    def __init__(self):
        self._changes: list[Change] = []
        self.canceled = False

    def add(self, change: Change):
        self._changes.append(change)

    def save(self):
        if self.has_changes():
            ui_dialog.Dialog.save_changes_dialog(
                self.on_save, self.clear, self.on_cancel
            )

    def on_save(self):
        for change in self._changes:
            change.save()
        self.clear()

    def clear(self):
        self._changes = []

    def has_changes(self):
        for change in self._changes:
            if change.has_changes():
                return True
        return False

    def on_cancel(self):
        self.canceled = True


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
        self.resize(800, 600)
        self.create_toolbar()
        self.setWindowTitle("Battle Cats Mod Loader")
        icon_path = io.path.Path(is_relative=True).add("assets", "icon.png")
        self.setWindowIcon(QtGui.QIcon(str(icon_path)))

        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.setCentralWidget(self.centralwidget)

        self._layout = QtWidgets.QVBoxLayout()
        self.centralwidget.setLayout(self._layout)

        self.changes = Changes()

        self.mod_view = mod_manager.ModView(self.changes, self)
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
            self.close_wrapper()

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

    def close_wrapper(self) -> bool:
        self.changes.save()
        if self.changes.canceled:
            self.changes.canceled = False
            return False
        return True

    def closeEvent(self, event: QtGui.QCloseEvent):  # type: ignore
        close = self.close_wrapper()
        if close:
            event.accept()
        else:
            event.ignore()


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
