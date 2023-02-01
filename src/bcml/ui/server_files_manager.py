from PyQt5 import QtCore, QtWidgets
from bcml.core import io, country_code, game_version
from bcml.ui import progress, ui_thread


class ServerFilesManager(QtWidgets.QDialog):
    def __init__(self):
        super(ServerFilesManager, self).__init__()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ServerFilesManager")
        self.resize(600, 600)
        self.setWindowTitle("Server Files Manager")
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

        self._layout.addWidget(QtWidgets.QLabel("Server files:"))
        self._server_files = ServerFilesList(self)
        self._layout.addWidget(self._server_files)

        self.refresh_button = QtWidgets.QPushButton("Refresh", self)
        self.refresh_button.clicked.connect(self._server_files.refresh)  # type: ignore
        self._layout.addWidget(self.refresh_button)

        self.open_button = QtWidgets.QPushButton("Open Folder", self)
        self.open_button.clicked.connect(self.open_folder)  # type: ignore
        self._layout.addWidget(self.open_button)

        self.download_button = QtWidgets.QPushButton(
            "Download Missing Server Files", self
        )
        self.download_button.clicked.connect(self.download_server_files_wrapper)  # type: ignore
        self._layout.addWidget(self.download_button)

        self.progress_bar = progress.ProgressBar(
            "Downloading server files...", self.on_progress, self
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
        apk.download_server_files(self.progress_bar.set_progress_full)
        self.progress_bar.hide()

    def on_progress(self, progress: int, total: int):
        self._server_files.refresh()


class ServerFilesList(QtWidgets.QWidget):
    def __init__(self, cc: country_code.CountryCode):
        super(ServerFilesList, self).__init__()
        self._cc = cc
        self.setup_ui()

    def setup_ui(self):
        self._layout = QtWidgets.QVBoxLayout(self)
        self.setLayout(self._layout)
        self._server_files_list = QtWidgets.QListWidget(self)
        self._layout.addWidget(self._server_files_list)

        self._server_files_list.setContextMenuPolicy(
            QtCore.Qt.ContextMenuPolicy.CustomContextMenu
        )
        self._server_files_list.customContextMenuRequested.connect(self.on_context_menu)  # type: ignore

        # scroll to bottom on new item
        self._server_files_list.itemChanged.connect(  # type: ignore
            lambda x: self._server_files_list.scrollToBottom()  # type: ignore
        )

    def refresh(self):
        server_files_dir = io.apk.Apk.get_server_path(self._cc).generate_dirs()

        self._server_files_list.clear()
        files = server_files_dir.get_files(".*\\.pack.*")
        files = sorted(files, key=lambda x: x.get_file_name_without_extension())
        for file in files:
            self._server_files_list.addItem(file.get_file_name_without_extension())
            self._server_files_list.item(
                self._server_files_list.count() - 1
            ).setToolTip(file.to_str())

    def set_cc(self, cc: country_code.CountryCode):
        self._cc = cc
        self.refresh()

    def on_context_menu(self, pos: QtCore.QPoint):
        item = self._server_files_list.itemAt(pos)
        if item is None:
            return
        menu = QtWidgets.QMenu()
        menu.exec_(self._server_files_list.mapToGlobal(pos))
