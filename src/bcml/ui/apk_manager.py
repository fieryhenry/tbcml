"""Dialog for managing APKs""" ""
from typing import Any, Callable, Optional
import webbrowser
from PyQt5 import QtCore, QtWidgets, QtGui
from bcml.core import io, country_code, game_version
from bcml.ui import main


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
        self.apk_list = ApkList(self)
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


class ApkList(QtWidgets.QListWidget):
    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super(ApkList, self).__init__(parent)
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
        action = menu.exec_(self.mapToGlobal(pos))
        if action == delete_action:
            self.delete_apk()
        elif action == extraction_action:
            self.extract_apk()

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
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Icon.Question)

        msg.setText("Are you sure you want to delete this APK?")
        msg.setInformativeText("This will delete the APK file.")
        msg.setWindowTitle("Confirm APK Deletion")
        msg.setStandardButtons(
            QtWidgets.QMessageBox.StandardButton.Yes  # type: ignore
            | QtWidgets.QMessageBox.StandardButton.No
        )
        msg.setDefaultButton(QtWidgets.QMessageBox.StandardButton.No)
        msg.buttonClicked.connect(self.delete_apk_call)  # type: ignore

        msg.exec_()

    def delete_apk_call(self, button: QtWidgets.QPushButton):
        if "Yes" in button.text():
            apk = io.apk.Apk.from_format_string(self.get_selected_apk())
            apk.delete()
            self.takeItem(self.currentRow())

    def extract_apk(self):
        if not io.apk.Apk.check_apktool_installed():
            msg = QtWidgets.QMessageBox()
            msg.setIcon(QtWidgets.QMessageBox.Icon.Warning)

            msg.setText("APKTool is not installed.")
            msg.setInformativeText(
                "APKTool is required to extract APK files. Install from https://ibotpeaches.github.io/Apktool/install/. Would you like to open the APKTool installation page?"
            )
            msg.setWindowTitle("APKTool Not Installed")
            msg.setStandardButtons(
                QtWidgets.QMessageBox.StandardButton.Yes  # type: ignore
                | QtWidgets.QMessageBox.StandardButton.No
            )
            msg.setDefaultButton(QtWidgets.QMessageBox.StandardButton.No)
            msg.buttonClicked.connect(self.open_apktool_install_page)  # type: ignore

            msg.exec_()
        else:
            apk = io.apk.Apk.from_format_string(self.get_selected_apk())
            apk.extract()

    def open_apktool_install_page(self, button: QtWidgets.QPushButton):
        if "Yes" in button.text():
            webbrowser.open("https://ibotpeaches.github.io/Apktool/install/")


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
        print("Downloading APK: " + apk.format())
        apk.download_apk()
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

        self.apk_versions = io.apk.Apk.get_all_versions(self.cc)
        for apk_version in self.apk_versions:
            self.apk_list.addItem(apk_version.format())

        self.apk_list.itemDoubleClicked.connect(self.download)  # type: ignore

    def get_selected_apk(self):
        return self.apk_list.currentItem().text()

    def download(self):
        gv = game_version.GameVersion.from_string(self.get_selected_apk())
        apk = io.apk.Apk(gv, self.cc)
        self.download_call(apk)

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Return:
            self.download()
