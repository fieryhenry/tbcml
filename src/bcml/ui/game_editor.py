from typing import Callable, Optional
from PyQt5 import QtWidgets, QtCore
from bcml.core import io, mods, game_data, locale_handler
from bcml.ui import ui_thread, shop_editor, progress, apk_manager, localizable


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
        self.local_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def set_up_data(self):
        self.apk = io.apk.Apk(self.mod.game_version, self.mod.country_code)
        if not self.apk.is_downloaded():
            self.apk_manager = apk_manager.ApkManager()
            self.apk_manager.show()
            self.apk_manager.download_specific_apk(self.apk)
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("extracting_apk_progress"), 0
        )
        self.apk.extract()
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("copying_server_files_progress"), 30
        )
        self.apk.copy_server_files()
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("loading_game_data_progress"), 50
        )
        self.game_data = game_data.pack.GamePacks.from_apk(self.apk)
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("loading_original_game_data_progress"), 70
        )
        self.original_game_data = game_data.pack.GamePacks.from_apk(self.apk)
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("loading_mod_data_progress"), 90
        )

        self.game_data.apply_mod(self.mod)
        self.progress_bar.set_progress_str(
            self.local_manager.search_key("done_progress"), 100
        )

    def setup_ui(self):
        self.setObjectName("GameEditor")

        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self._layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self._layout)

        self.progress_bar = progress.ProgressBar(
            self.local_manager.search_key("loading_game_data_progress"), None, self
        )
        self._layout.addWidget(self.progress_bar)
        self._layout.setAlignment(
            self.progress_bar, QtCore.Qt.AlignmentFlag.AlignVCenter
        )

        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.set_up_data, self.add_tabs
        )

    def add_tabs(self):
        self._tab_widget = QtWidgets.QTabWidget(self)
        self._tab_widget.setObjectName("tab_widget")
        self._layout.addWidget(self._tab_widget)

        self.progress_bar.hide()

        self.save_button = QtWidgets.QPushButton(self)
        self.save_button.setObjectName("save_button")
        self.save_button.setText(self.local_manager.search_key("save"))
        self.save_button.clicked.connect(self.save)  # type: ignore
        self._layout.addWidget(self.save_button)

        self.refresh_button = QtWidgets.QPushButton(self)
        self.refresh_button.setObjectName("reload_button")
        self.refresh_button.setText(self.local_manager.search_key("reload"))
        self.refresh_button.clicked.connect(self.refresh_tabs)  # type: ignore
        self._layout.addWidget(self.refresh_button)

        self.back_button = QtWidgets.QPushButton(self)
        self.back_button.setObjectName("back_button")
        self.back_button.setText(self.local_manager.search_key("back"))
        self.back_button.clicked.connect(self.back)  # type: ignore
        self._layout.addWidget(self.back_button)

        self._tab_widget.addTab(
            self.create_item_shop_tab(), self.local_manager.search_key("item_shop_tab")
        )
        self._tab_widget.addTab(
            self.create_text_tab(),
            self.local_manager.search_key("text_tab"),
        )

        self.tab_changed(0)

        self._tab_widget.currentChanged.connect(self.tab_changed)

    def create_item_shop_tab(self):
        self.shop_editor = shop_editor.ShopEditor(
            self.mod, self.game_data, self.original_game_data, self
        )
        return self.shop_editor

    def create_text_tab(self):
        self.text_editor = localizable.TextEditor(
            self.mod, self.game_data, self.original_game_data, self
        )
        return self.text_editor

    def save(self):
        self._save_thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.save_thread
        )

    def save_thread(self):
        self.shop_editor.save()
        self.text_editor.save()
        self.game_data.apply_mod(self.mod)
        mods.mod_manager.ModManager().save_mod(self.mod)

    def back(self):
        self.on_back()

    def refresh_tabs(self):
        current_tab = self._tab_widget.currentIndex()
        self._tab_widget.removeTab(0)
        self._tab_widget.removeTab(0)
        self._tab_widget.addTab(
            self.create_item_shop_tab(), self.local_manager.search_key("item_shop_tab")
        )
        self._tab_widget.addTab(
            self.create_text_tab(), self.local_manager.search_key("text_tab")
        )
        self._tab_widget.setCurrentIndex(current_tab)

    def tab_changed(self, index: int):
        if index == 0:
            self.shop_editor.setup_ui()
        elif index == 1:
            self.text_editor.setup_ui()
