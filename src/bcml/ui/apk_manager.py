"""Dialog for managing APKs""" ""
from typing import Any, Callable, Optional
import webbrowser
from PyQt5 import QtCore, QtWidgets, QtGui
from bcml.core import io, country_code, game_version
from bcml.ui import main, progress, ui_thread, ui_dialog


class ApkManager(QtWidgets.QDialog):
    """Dialog for managing APKs"""

    def __init__(self):
        super(ApkManager, self).__init__()
        self.setup_ui()

    def setup_ui(self):
        """Sets up the UI"""
        self.setObjectName("ApkManager")
        self.resize(400, 300)
        self.setWindowTitle("APK Manager")
        self.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)

        self._layout = QtWidgets.QVBoxLayout()
        self.setLayout(self._layout)

        self.add_ui()

    def add_ui(self):
        io.apk.Apk.clean_up()

        self.selected_apk_label = QtWidgets.QLabel("Selected APK:")
        self._layout.addWidget(self.selected_apk_label)

        self.selected_apk = io.config.Config().get(io.config.Key.SELECTED_APK)
        self.selected_apk_label = QtWidgets.QLineEdit()
        self.selected_apk_label.setReadOnly(True)
        self.selected_apk_label.setPlaceholderText("None")
        if self.selected_apk:
            self.selected_apk_label.setText(self.selected_apk)
        else:
            self.selected_apk_label.setText("None")
        self._layout.addWidget(self.selected_apk_label)

        self.apk_list = ApkList(self.select_apk, self)
        self.apk_list.get_apks()
        self._layout.addWidget(self.apk_list)

        self.button_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.button_layout)

        self.download_apk = QtWidgets.QPushButton("Download APK")
        self.download_apk.clicked.connect(self.download_apk_clicked)  # type: ignore
        self.button_layout.addWidget(self.download_apk)

        self.add_apk_file = QtWidgets.QPushButton("Add APK from File")
        self.add_apk_file.clicked.connect(self.add_apk_clicked)  # type: ignore
        self.button_layout.addWidget(self.add_apk_file)

        self.refresh_apk_list_button = QtWidgets.QPushButton("Refresh APK List")
        self.refresh_apk_list_button.clicked.connect(self.refresh_apk_list)  # type: ignore
        self._layout.addWidget(self.refresh_apk_list_button)

        self.open_folder_button = QtWidgets.QPushButton("Open APK Folder")
        self.open_folder_button.clicked.connect(self.open_apk_folder)  # type: ignore
        self._layout.addWidget(self.open_folder_button)

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.close()

    def download_apk_clicked(self):
        self.apk_downloader = ApkDownloader(
            self.add_apk_call, self.refresh_apk_list, self
        )
        main.clear_layout(self._layout)
        self._layout.addWidget(self.apk_downloader)

    def refresh_apk_list(self):
        main.clear_layout(self._layout)
        self.add_ui()

    def add_apk_call(self, apk: io.apk.Apk):
        self.refresh_apk_list()

    def open_apk_folder(self):
        io.apk.Apk.get_default_apk_folder().open()

    def add_apk_clicked(self):
        file_filter = "APK Files (*.apk);;All Files (*)"
        apk_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select APK",
            io.apk.Apk.get_default_apk_folder().path,
            file_filter,
        )
        if apk_path:
            path = io.path.Path(apk_path)
            apk = io.apk.Apk.from_apk_path(path)
            self.add_apk_call(apk)

    def select_apk(self, apk: io.apk.Apk):
        io.config.Config().set(io.config.Key.SELECTED_APK, apk.format())
        self.selected_apk_label.setText(apk.format())


class ApkList(QtWidgets.QListWidget):
    def __init__(
        self,
        on_select_apk: Callable[[io.apk.Apk], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ApkList, self).__init__(parent)
        self.on_select_apk = on_select_apk
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ApkList")

        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)  # type: ignore

    def show_context_menu(self, pos: QtCore.QPoint):
        menu = QtWidgets.QMenu()
        if not self.currentItem():
            return
        delete_action = menu.addAction("Delete APK")
        extraction_action = menu.addAction("Extract APK")
        select_apk_action = menu.addAction("Select APK")
        action = menu.exec_(self.mapToGlobal(pos))
        if action == delete_action:
            self.delete_apk()
        elif action == extraction_action:
            self.extract_apk()
        elif action == select_apk_action:
            self.select_apk()

    def get_apks(self):
        self.apks = io.apk.Apk.get_all_downloaded()
        for apk in self.apks:
            self.addItem(apk.format())

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Delete:
            self.delete_apk()

    def get_selected_apk(self):
        return self.currentItem().text()

    def delete_apk(self):
        ui_dialog.Dialog.yes_no_box(
            icon=QtWidgets.QMessageBox.Icon.Question,
            text="Are you sure you want to delete this APK?",
            informative_text="This will delete the APK file.",
            window_title="Confirm APK Deletion",
            default_button=QtWidgets.QMessageBox.StandardButton.No,
            on_yes=self.delete_apk_call,
        )

    def delete_apk_call(self):
        apk = io.apk.Apk.from_format_string(self.get_selected_apk())
        apk.delete()
        self.takeItem(self.currentRow())

    def extract_apk(self):
        if not io.apk.Apk.check_apktool_installed():
            ui_dialog.Dialog.yes_no_box(
                icon=QtWidgets.QMessageBox.Icon.Warning,
                text="APKTool is not installed.",
                informative_text="APKTool is required to extract APK files. Install from https://ibotpeaches.github.io/Apktool/install/. Would you like to open the APKTool installation page?",
                window_title="APKTool Not Installed",
                default_button=QtWidgets.QMessageBox.StandardButton.No,
                on_yes=self.open_apktool_install_page,
            )
        else:
            apk = io.apk.Apk.from_format_string(self.get_selected_apk())
            apk.extract()
            apk.extracted_path.open()

    def open_apktool_install_page(self):
        webbrowser.open("https://ibotpeaches.github.io/Apktool/install/")

    def select_apk(self):
        apk = io.apk.Apk.from_format_string(self.get_selected_apk())
        self.on_select_apk(apk)


class ApkDownloader(QtWidgets.QWidget):
    def __init__(
        self,
        add_call: Callable[..., Any],
        go_back_call: Callable[..., Any],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ApkDownloader, self).__init__(parent)
        self.add_call = add_call
        self.go_back_call = go_back_call
        self.downloading_apks: list[str] = []
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ApkAdder")
        self._layout = QtWidgets.QVBoxLayout()
        self.setLayout(self._layout)

        self.downloadable_apks_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.downloadable_apks_layout)

        for cc in country_code.CountryCode.get_all():
            self.downloadable_apks_layout.addWidget(
                DownloadableApksList(cc, self.download_apk)
            )

        self.button_layout = QtWidgets.QGridLayout()
        self._layout.addLayout(self.button_layout)

        self.button_layout.setColumnStretch(1, 1)
        self.button_layout.setContentsMargins(5, 0, 0, 0)

        self.back_button = QtWidgets.QPushButton("Back")
        self.button_layout.addWidget(self.back_button, 0, 0)
        self.back_button.clicked.connect(self.go_back_call)  # type: ignore

    def download_apk(self, apk: io.apk.Apk):
        apk_id = apk.get_id()
        if apk_id in self.downloading_apks:
            return
        title = f"Downloading {apk.format()}"
        self.downloading_apks.append(apk_id)
        self.progress_bar = progress.ProgressBar(title, self)
        self._layout.addWidget(self.progress_bar)
        self._thread = ui_thread.ThreadWorker.run_in_thread(self.download_thread, apk)

    def download_thread(self, apk: io.apk.Apk):
        apk_id = apk.get_id()
        apk.download_apk(self.progress_bar.set_progress_full)
        if apk_id in self.downloading_apks:
            self.downloading_apks.remove(apk_id)

        if not self.downloading_apks:
            self.add_call(apk)


class DownloadableApksList(QtWidgets.QWidget):
    def __init__(
        self,
        cc: "country_code.CountryCode",
        download_call: Callable[..., Any],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(DownloadableApksList, self).__init__(parent)
        self.cc = cc
        self.download_call = download_call
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("DownloadableApksList")

        self.list_layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.list_layout)

        self.cc_label = QtWidgets.QLabel(self.cc.name)
        self.list_layout.addWidget(self.cc_label)

        self.apk_list = QtWidgets.QListWidget()
        self.list_layout.addWidget(self.apk_list)

        self._thread = ui_thread.ThreadWorker.run_in_thread(self.load_apks)

        self.apk_list.itemDoubleClicked.connect(self.download)  # type: ignore

    def load_apks(self):
        self.apk_versions = io.apk.Apk.get_all_versions(self.cc)
        for apk_version in self.apk_versions:
            self.apk_list.addItem(apk_version.format())

    def get_selected_apk(self):
        return self.apk_list.currentItem().text()

    def download(self):
        gv = game_version.GameVersion.from_string(self.get_selected_apk())
        apk = io.apk.Apk(gv, self.cc)
        self.download_call(apk)

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Return:
            self.download()
