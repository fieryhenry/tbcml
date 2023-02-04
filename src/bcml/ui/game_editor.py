from typing import Callable, Optional
from PyQt5 import QtWidgets
from bcml.core import io, mods, game_data
from bcml.ui import ui_thread, shop_editor


class GameEditor(QtWidgets.QWidget):
    def __init__(
        self,
        mod: mods.bc_mod.Mod,
        on_back: Callable[[], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(GameEditor, self).__init__(parent)
        self.mod = mod
        self.on_back = on_back
        self.setup_ui()

    def set_up_data(self):
        self.apk = io.apk.Apk(self.mod.game_version, self.mod.country_code)
        self.apk.extract()
        self.apk.copy_server_files()
        self.game_data = game_data.pack.GamePacks.from_apk(self.apk)

        self.game_data.apply_mod(self.mod)

    def setup_ui(self):
        self.setObjectName("GameEditor")

        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self.setLayout(self._layout)

        self.loading_label = QtWidgets.QLabel(self)
        self.loading_label.setObjectName("loading_label")
        self.loading_label.setText(self.tr("Loading..."))
        self._layout.addWidget(self.loading_label)

        self._tab_widget = QtWidgets.QTabWidget(self)
        self._tab_widget.setObjectName("tab_widget")
        self._layout.addWidget(self._tab_widget)

        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.set_up_data, self.add_tabs
        )

    def add_tabs(self):
        self.loading_label.hide()

        self.save_button = QtWidgets.QPushButton(self)
        self.save_button.setObjectName("save_button")
        self.save_button.setText(self.tr("Save"))
        self.save_button.clicked.connect(self.save)  # type: ignore
        self._layout.addWidget(self.save_button)

        self.back_button = QtWidgets.QPushButton(self)
        self.back_button.setObjectName("back_button")
        self.back_button.setText(self.tr("Back"))
        self.back_button.clicked.connect(self.back)  # type: ignore
        self._layout.addWidget(self.back_button)

        self._tab_widget.addTab(self.create_item_shop_tab(), self.tr("Item Shop"))

    def create_item_shop_tab(self):
        self.shop_editor = shop_editor.ShopEditor(self.mod, self.game_data, self)
        return self.shop_editor

    def save(self):
        self._save_thread = ui_thread.ThreadWorker.run_in_thread(self.save_thread)

    def save_thread(self):
        self.shop_editor.save()
        self.game_data.apply_mod(self.mod)
        mods.mod_manager.ModManager().save_mod(self.mod)

    def back(self):
        self.on_back()
