from typing import Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from bcml.core import game_data, io, locale_handler, mods
from bcml.ui.editor import gatya_item, localizable
from bcml.ui.utils import ui_dialog, ui_file_dialog, ui_thread


class CatEditor(QtWidgets.QWidget):
    def __init__(
        self,
        mod: mods.bc_mod.Mod,
        game_packs: game_data.pack.GamePacks,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(CatEditor, self).__init__(parent)
        self.mod = mod
        self.game_packs = game_packs
        self.setup = False

    def setup_ui(self):
        if self.setup:
            return
        self.setup = True
        self.local_manager = locale_handler.LocalManager.from_config()
        self.setObjectName("CatEditor")
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self._layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self._layout)

        self._layout.addWidget(QtWidgets.QLabel("test", self))
