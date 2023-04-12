from typing import Optional

from PyQt5 import QtCore, QtWidgets

from bcml.core import io, locale_handler, mods
from bcml.ui.utils import ui_file_dialog


class AudioEditor(QtWidgets.QWidget):
    def __init__(
        self,
        mod: mods.bc_mod.Mod,
        apk: io.apk.Apk,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(AudioEditor, self).__init__(parent)
        self.mod = mod
        self.apk = apk
        self.setup = False

    def setup_ui(self):
        if self.setup:
            return
        self.setup = True
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setObjectName("AudioEditor")
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self.setLayout(self._layout)

        self.audio_files_list = AudioFilesList(self, self.apk, self.mod)
        self._layout.addWidget(self.audio_files_list)

    def save(self):
        self.audio_files_list.save()


class AudioFilesList(QtWidgets.QWidget):
    def __init__(
        self, parent: QtWidgets.QWidget, apk: io.apk.Apk, mod: mods.bc_mod.Mod
    ):
        super(AudioFilesList, self).__init__(parent)
        self.apk = apk
        self.mod = mod
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.modified_audio: dict[str, io.audio.AudioFile] = {}
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("AudioFilesList")
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")
        self._layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(self._layout)

        self._layout.addWidget(
            QtWidgets.QLabel(self.locale_manager.search_key("audio_files"))
        )
        self.audio_files_list = QtWidgets.QListWidget(self)
        self.audio_files_list.setObjectName("audio_files_list")
        self.audio_files_list.setContextMenuPolicy(
            QtCore.Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.audio_files_list.customContextMenuRequested.connect(self.context_menu)
        self._layout.addWidget(self.audio_files_list)

        self.all_files = self.apk.get_all_audio()
        self.all_files.import_audio(self.mod.audio)
        self.modified_audio = self.mod.audio.audio_files
        self.all_files.sort_by_id()

        self.fill_list()

    def fill_list(self):
        self.audio_files_list.clear()

        for file in self.all_files.audio_files.values():
            self.audio_files_list.addItem(file.file_name)

    def context_menu(self, pos: QtCore.QPoint):
        menu = QtWidgets.QMenu(self)
        menu.addAction(
            self.locale_manager.search_key("add_audio_file"), self.add_audio_file
        )
        if self.is_selected():
            menu.addAction(
                self.locale_manager.search_key("reveal_in_explorer"),
                self.reveal_in_explorer,
            )
        menu.exec_(self.audio_files_list.mapToGlobal(pos))

    def add_audio_file(self):
        file_path = ui_file_dialog.FileDialog(self).select_file(
            self.locale_manager.search_key("select_audio_file"),
            self.apk.get_server_path(self.apk.country_code).to_str(),
            self.locale_manager.search_key("audio_files")
            + " (*.ogg *.wav *.caf *.mp3)",
        )
        if file_path:
            path = io.path.Path(file_path)
            if path.basename() not in self.all_files.audio_files:
                self.audio_files_list.addItem(path.basename())
            audio_obj = io.audio.AudioFile.from_file(path)
            self.modified_audio[path.basename()] = audio_obj
            self.all_files.audio_files[path.basename()] = audio_obj

    def get_audio_files(self):
        return [
            self.audio_files_list.item(i).text()
            for i in range(self.audio_files_list.count())
        ]

    def save(self):
        self.mod.audio = io.audio.Audio(self.modified_audio)

    def is_selected(self):
        return self.audio_files_list.currentRow() != -1

    def get_selected_audio_file(self):
        name = self.audio_files_list.currentItem().text()
        return self.all_files.get(name)

    def reveal_in_explorer(self):
        audio_file = self.get_selected_audio_file()
        name = audio_file.file_name
        data = audio_file.data
        path = io.temp_file.TempFile.get_temp_path(name=name)
        data.to_file(path)
        path.open()
