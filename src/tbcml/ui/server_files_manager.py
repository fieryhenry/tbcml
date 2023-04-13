from typing import Optional
from PyQt5 import QtCore, QtWidgets

from tbcml.core import country_code, game_version, io, locale_handler
from tbcml.ui.utils import ui_progress, ui_thread


class ServerFilesManager(QtWidgets.QDialog):
    def __init__(self):
        super(ServerFilesManager, self).__init__()
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ServerFilesManager")
        self.resize(700, 700)
        self.setWindowTitle(
            self.locale_manager.search_key("server_files_manager_title")
        )
        self.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)

        self._layout = QtWidgets.QVBoxLayout(self)
        self.setLayout(self._layout)

        self.add_ui()

    def add_ui(self):
        ccs = country_code.CountryCode.get_all_str()
        self._cc_combo = QtWidgets.QComboBox(self)
        self._cc_combo.addItems(ccs)
        self._cc_combo.currentTextChanged.connect(self.on_cc_changed)  # type: ignore
        self._layout.addWidget(self._cc_combo)

        self._server_files = ServerFilesList(
            country_code.CountryCode.from_code(ccs[0]), self
        )
        self._layout.addWidget(self._server_files)

        self.refresh_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("refresh"), self
        )
        self.refresh_button.clicked.connect(self._server_files.refresh)  # type: ignore
        self._layout.addWidget(self.refresh_button)

        self.open_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("open_server_files_folder"), self
        )
        self.open_button.clicked.connect(self.open_folder)  # type: ignore
        self._layout.addWidget(self.open_button)

        self.download_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("download_missing_server_files"), self
        )
        self.download_button.clicked.connect(self.download_server_files_wrapper)  # type: ignore
        self._layout.addWidget(self.download_button)

        self.progress_bar = ui_progress.ProgressBar(
            self.locale_manager.search_key("downloading_missing_server_files_progress"),
            None,
            self,
        )
        self.progress_bar.hide()
        self._layout.addWidget(self.progress_bar)

        self.on_cc_changed(ccs[0])

    def get_current_cc(self) -> str:
        return self._cc_combo.currentText()

    def on_cc_changed(self, cc: str):
        self._server_files.set_cc(country_code.CountryCode.from_code(cc))
        self._server_files.refresh()

    def open_folder(self):
        cc_obj = country_code.CountryCode.from_code(self.get_current_cc())
        server_files_dir = io.apk.Apk.get_server_path(cc_obj).generate_dirs()
        server_files_dir.open()

    def download_server_files_wrapper(self):
        cc_obj = country_code.CountryCode.from_code(self.get_current_cc())
        gv = game_version.GameVersion.from_string_latest("latest", cc_obj)
        self.progress_bar.show()
        self._thread = ui_thread.ThreadWorker.run_in_thread(
            self.download_server_files, gv, cc_obj
        )

    def download_server_files(
        self, gv: game_version.GameVersion, cc_obj: country_code.CountryCode
    ):
        apk = io.apk.Apk(gv, cc_obj)
        apk.extract()
        apk.copy_packs()
        apk.download_server_files(
            self.progress_bar.set_progress_full_no_text,
            self.progress_bar.set_progress_no_bar,
            False,
        )
        self.progress_bar.hide()
        apk.copy_packs()


class ServerFilesList(QtWidgets.QWidget):
    def __init__(
        self, cc: country_code.CountryCode, parent: Optional[QtWidgets.QWidget] = None
    ):
        super(ServerFilesList, self).__init__(parent)
        self._cc = cc
        self.server_files_dir = io.apk.Apk.get_server_path(self._cc).generate_dirs()
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self._layout = QtWidgets.QVBoxLayout(self)
        self.setLayout(self._layout)
        self.tab_widget = QtWidgets.QTabWidget(self)
        self._layout.addWidget(self.tab_widget)

        self.pack_file_tab = QtWidgets.QWidget()
        self.tab_widget.addTab(
            self.pack_file_tab, self.locale_manager.search_key("pack_files")
        )
        self.pack_file_layout = QtWidgets.QVBoxLayout(self.pack_file_tab)
        self.pack_file_tab.setLayout(self.pack_file_layout)
        self.pack_file_list = FileList(self.pack_file_tab)
        self.pack_file_layout.addWidget(self.pack_file_list)

        self.list_file_tab = QtWidgets.QWidget()
        self.tab_widget.addTab(
            self.list_file_tab, self.locale_manager.search_key("list_files")
        )
        self.list_file_layout = QtWidgets.QVBoxLayout(self.list_file_tab)
        self.list_file_tab.setLayout(self.list_file_layout)
        self.list_file_list = FileList(self.list_file_tab)
        self.list_file_layout.addWidget(self.list_file_list)

        self.audio_file_tab = QtWidgets.QWidget()
        self.tab_widget.addTab(
            self.audio_file_tab, self.locale_manager.search_key("audio_files")
        )
        self.audio_file_layout = QtWidgets.QVBoxLayout(self.audio_file_tab)
        self.audio_file_tab.setLayout(self.audio_file_layout)
        self.audio_file_list = FileList(self.audio_file_tab)
        self.audio_file_layout.addWidget(self.audio_file_list)

        self.tab_widget.currentChanged.connect(self.on_tab_changed)  # type: ignore

    def refresh(self):
        self.refresh_pack_files()
        self.refresh_list_files()
        self.refresh_audio_files()

    def refresh_pack_files(self):
        pack_files = self.server_files_dir.get_files("\\.(pack)$")
        self.pack_file_list.set_files(pack_files)

    def refresh_list_files(self):
        list_files = self.server_files_dir.get_files("\\.(list)$")
        self.list_file_list.set_files(list_files)

    def refresh_audio_files(self):
        audio_files = self.server_files_dir.get_files("\\.(ogg|caf)$")
        self.audio_file_list.set_files(audio_files)

    def set_cc(self, cc: country_code.CountryCode):
        self._cc = cc
        self.server_files_dir = io.apk.Apk.get_server_path(self._cc).generate_dirs()
        self.refresh()

    def on_tab_changed(self, index: int):
        if index == 0:
            self.refresh_pack_files()
        elif index == 1:
            self.refresh_list_files()
        elif index == 2:
            self.refresh_audio_files()


class FileList(QtWidgets.QListWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super(FileList, self).__init__(parent)
        self._files = []
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setSortingEnabled(True)
        self.addItems([f.get_file_name() for f in self._files])
        self.context_menu = QtWidgets.QMenu(self)
        self.context_menu.addAction(
            self.locale_manager.search_key("reveal_in_explorer"),
            self.reveal_in_explorer,
        )
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def get_files(self) -> list[io.path.Path]:
        return self._files

    def get_selected_file(self) -> io.path.Path:
        name = self.selectedItems()[0].text()
        return next(f for f in self._files if f.get_file_name() == name)

    def reveal_in_explorer(self):
        self.get_selected_file().open()

    def show_context_menu(self, pos: QtCore.QPoint):
        self.context_menu.exec_(self.mapToGlobal(pos))

    def set_files(self, files: list[io.path.Path]):
        self._files = files
        self.clear()
        self.addItems([f.get_file_name() for f in self._files])

    def refresh(self):
        self.set_files(self._files)
