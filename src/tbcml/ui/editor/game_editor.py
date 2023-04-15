import enum
from typing import Callable, Optional

from PyQt5 import QtCore, QtWidgets

from tbcml.core import game_data, io, locale_handler, mods
from tbcml.ui.editor import cat_editor, localizable, shop_editor, audio_editor
from tbcml.ui.utils import ui_progress, ui_thread


class Tabs(enum.Enum):
    CAT = 0
    LOCALIZABLE = 1
    SHOP = 2
    AUDIO = 3


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
        self.game_data: Optional[game_data.pack.GamePacks] = None
        self.setup_ui()

    def set_up_data(self, progress_signal: QtCore.pyqtSignal):
        progress_signal.emit(  # type: ignore
            self.local_manager.get_key("extracting_apk_progress"), 0, 100
        )
        self.apk.extract()
        progress_signal.emit(  # type: ignore
            self.local_manager.get_key("copying_server_files_progress"), 30, 100
        )
        self.apk.copy_server_files()
        progress_signal.emit(  # type: ignore
            self.local_manager.get_key("loading_game_data_progress"), 50, 100
        )
        self.game_data = game_data.pack.GamePacks.from_apk(self.apk)
        progress_signal.emit(  # type: ignore
            self.local_manager.get_key("loading_mod_data_progress"), 90, 100
        )

        self.game_data.apply_mod(self.mod)
        progress_signal.emit(self.local_manager.get_key("done_progress"), 100, 100)  # type: ignore

    def setup_ui(self):
        self.setObjectName("GameEditor")

        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self._layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self._layout)

        self.progress_bar = ui_progress.ProgressBar(
            self.local_manager.get_key("loading_game_data_progress"), None, self
        )
        self._layout.addWidget(self.progress_bar)
        self._layout.setAlignment(
            self.progress_bar, QtCore.Qt.AlignmentFlag.AlignVCenter
        )

        self.apk = io.apk.Apk(self.mod.game_version, self.mod.country_code)

        self._thread = ui_thread.ThreadWorker.run_in_thread_progress_on_finished(
            self.set_up_data, ui_thread.ProgressMode.TEXT, self.add_tabs
        )
        self._thread.progress_text.connect(self.progress_bar.set_progress_str)

    def add_tabs(self):
        self._tab_widget = QtWidgets.QTabWidget(self)
        self._tab_widget.setObjectName("tab_widget")
        self._layout.addWidget(self._tab_widget)

        self.progress_bar.hide()

        self.save_button = QtWidgets.QPushButton(self)
        self.save_button.setObjectName("save_button")
        self.save_button.setText(self.local_manager.get_key("save"))
        self.save_button.clicked.connect(self.save)  # type: ignore
        self._layout.addWidget(self.save_button)

        self.refresh_button = QtWidgets.QPushButton(self)
        self.refresh_button.setObjectName("reload_button")
        self.refresh_button.setText(self.local_manager.get_key("reload"))
        self.refresh_button.clicked.connect(self.refresh_tabs)  # type: ignore
        self._layout.addWidget(self.refresh_button)

        self.back_button = QtWidgets.QPushButton(self)
        self.back_button.setObjectName("back_button")
        self.back_button.setText(self.local_manager.get_key("back"))
        self.back_button.clicked.connect(self.back)  # type: ignore
        self._layout.addWidget(self.back_button)
        self.insert_tabs()

    def insert_tabs(self):
        self._tab_widget.addTab(
            self.create_cat_tab(),
            self.local_manager.get_key("cats_tab"),
        )
        self._tab_widget.addTab(
            self.create_text_tab(),
            self.local_manager.get_key("text_tab"),
        )
        self._tab_widget.addTab(
            self.create_item_shop_tab(),
            self.local_manager.get_key("item_shop_tab"),
        )
        self._tab_widget.addTab(
            self.create_audio_tab(),
            self.local_manager.get_key("audio_tab"),
        )

        self.tab_changed(0)

        self._tab_widget.currentChanged.connect(self.tab_changed)

    def create_item_shop_tab(self):
        if self.game_data is None:
            return
        self.shop_editor = shop_editor.ShopEditor(self.mod, self.game_data, self)
        return self.shop_editor

    def create_text_tab(self):
        if self.game_data is None:
            return
        self.text_editor = localizable.TextEditor(self.mod, self.game_data, self)
        return self.text_editor

    def create_cat_tab(self):
        if self.game_data is None:
            return
        self.cat_editor = cat_editor.CatEditor(self.mod, self.game_data, self)
        return self.cat_editor

    def create_audio_tab(self):
        if self.game_data is None:
            return
        self.audio_editor = audio_editor.AudioEditor(self.mod, self.apk, self)
        return self.audio_editor

    def save(self):
        self._save_thread = ui_thread.ThreadWorker.run_in_thread(self.save_thread)

    def save_thread(self):
        self.shop_editor.save()
        self.text_editor.save()
        self.cat_editor.save()
        self.audio_editor.save()
        mods.mod_manager.ModManager().save_mod(self.mod)

    def back(self):
        self.on_back()

    def refresh_tabs(self):
        current_tab = self._tab_widget.currentIndex()
        for _ in range(self._tab_widget.count()):
            self._tab_widget.removeTab(0)

        self.insert_tabs()
        self._tab_widget.setCurrentIndex(current_tab)

    def tab_changed(self, index: int):
        if index == Tabs.SHOP.value:
            self.shop_editor.setup_ui()
        elif index == Tabs.LOCALIZABLE.value:
            self.text_editor.setup_ui()
        elif index == Tabs.CAT.value:
            self.cat_editor.setup_ui()
        elif index == Tabs.AUDIO.value:
            self.audio_editor.setup_ui()
