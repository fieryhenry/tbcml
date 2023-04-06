"""Dialog for managing APKs""" ""
import webbrowser
from typing import Any, Callable, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from bcml.core import country_code, game_data, game_version, io, locale_handler, mods
from bcml.ui import main
from bcml.ui.utils import ui_dialog, ui_file_dialog, ui_progress, ui_thread


class ApkManager(QtWidgets.QDialog):
    """Dialog for managing APKs"""

    def __init__(self):
        super(ApkManager, self).__init__()
        self.locale_manager = locale_handler.LocalManager.from_config()
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

        self.selected_apk_label = QtWidgets.QLabel(
            self.locale_manager.search_key("selected_apk_label")
        )
        self._layout.addWidget(self.selected_apk_label)

        self.selected_apk = io.config.Config().get(io.config.Key.SELECTED_APK)
        self.selected_apk_label = QtWidgets.QLineEdit()
        self.selected_apk_label.setReadOnly(True)
        if self.selected_apk:
            self.selected_apk_label.setText(self.selected_apk)
            self.selected_apk_label.setStyleSheet("color: #4e9a06")
        else:
            self.selected_apk_label.setText(self.locale_manager.search_key("none"))
            self.selected_apk_label.setStyleSheet("color: #b00020")

        self._layout.addWidget(self.selected_apk_label)

        self.apk_list = ApkList(self.select_apk, self.decrypt_apk, self)
        self.apk_list.get_apks()
        self._layout.addWidget(self.apk_list)

        self.button_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.button_layout)

        self.download_apk = QtWidgets.QPushButton(
            self.locale_manager.search_key("download_apk")
        )
        self.download_apk.clicked.connect(self.download_apk_clicked)  # type: ignore
        self.button_layout.addWidget(self.download_apk)

        self.add_apk_file = QtWidgets.QPushButton(
            self.locale_manager.search_key("add_apk")
        )
        self.add_apk_file.clicked.connect(self.add_apk_clicked)  # type: ignore
        self.button_layout.addWidget(self.add_apk_file)

        self.refresh_apk_list_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("refresh_apk")
        )
        self.refresh_apk_list_button.clicked.connect(self.refresh_apk_list)  # type: ignore
        self._layout.addWidget(self.refresh_apk_list_button)

        self.open_folder_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("open_apk_folder")
        )
        self.open_folder_button.clicked.connect(self.open_apk_folder)  # type: ignore
        self._layout.addWidget(self.open_folder_button)

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.close()

    def download_apk_clicked(self):
        self.apk_downloader = ApkDownloader(
            self.add_apk_call, self.refresh_apk_list, None, self
        )
        main.clear_layout(self._layout)
        self._layout.addWidget(self.apk_downloader)

    def download_specific_apk(self, apk: io.apk.Apk):
        self.apk_downloader = ApkDownloader(
            self.add_apk_call, self.refresh_apk_list, None, self
        )
        main.clear_layout(self._layout)
        self._layout.addWidget(self.apk_downloader)
        self.apk_downloader.download_apk(apk)

    def prompt_download(self, apk: io.apk.Apk):
        self.prompt_label = QtWidgets.QLabel(
            self.locale_manager.search_key("prompt_download") % apk.format()
        )
        main.clear_layout(self._layout)
        self._layout.addWidget(self.prompt_label)

        self.apk = apk
        self.apk_downloader = ApkDownloader(
            self.add_apk_call, self.refresh_apk_list, self.prompt_download_ready, self
        )
        self._layout.addWidget(self.apk_downloader)

    def prompt_download_ready(self):
        self.apk_downloader.select_element(self.apk)

    def refresh_apk_list(self):
        main.clear_layout(self._layout)
        self.add_ui()

    def add_apk_call(self, apk: io.apk.Apk):
        self.refresh_apk_list()

    def open_apk_folder(self):
        io.apk.Apk.get_default_apk_folder().open()

    def add_apk_clicked(self):
        file_filter = self.locale_manager.search_key("apk_filter")
        apk_path = ui_file_dialog.FileDialog(self).select_file(
            self.locale_manager.search_key("select_apk"),
            io.apk.Apk.get_default_apk_folder().path,
            file_filter,
            None,
        )
        if apk_path:
            path = io.path.Path(apk_path)
            apk = io.apk.Apk.from_apk_path(path)
            self.add_apk_call(apk)

    def select_apk(self, apk: io.apk.Apk):
        io.config.Config().set(io.config.Key.SELECTED_APK, apk.format())
        self.selected_apk_label.setText(apk.format())
        self.selected_apk_label.setStyleSheet("color: #00b000")

    def decrypt_apk(self, apk: io.apk.Apk, with_mods: Optional[bool] = False):
        directory = ui_file_dialog.FileDialog(self).select_directory(
            self.locale_manager.search_key("decrypt_folder_select_title"),
            apk.decrypted_path.to_str(),
            QtWidgets.QFileDialog.Option.ShowDirsOnly,  # type: ignore
        )
        if directory:
            path = io.path.Path(directory)
        else:
            return

        self.progress_bar = ui_progress.ProgressBar(
            self.locale_manager.search_key("decrypt_progress_bar_title"), None, self
        )
        self._layout.addWidget(self.progress_bar)
        self.progress_bar.show()

        self.decrypt_thread = ui_thread.ThreadWorker.run_in_thread(
            self.decrypt_apk_thread, apk, path, with_mods
        )

    def decrypt_apk_thread(self, apk: io.apk.Apk, path: io.path.Path, with_mods: bool):
        apk.extract()
        apk.copy_server_files()
        game_packs = game_data.pack.GamePacks.from_apk(apk)
        if with_mods:
            mds = mods.mod_manager.ModManager().get_mods()
            game_packs.apply_mods(mds)

        total_packs = len(game_packs.packs)
        for i, pck in enumerate(game_packs.packs.values()):
            pck.extract(path)
            self.progress_bar.set_progress(i + 1, total_packs)
        self.progress_bar.close()
        path.open()


class ApkList(QtWidgets.QListWidget):
    def __init__(
        self,
        on_select_apk: Callable[[io.apk.Apk], None],
        on_decrypt_apk: Callable[[io.apk.Apk, Optional[bool]], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ApkList, self).__init__(parent)
        self.on_select_apk = on_select_apk
        self.on_decrypt_apk = on_decrypt_apk
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ApkList")

        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)  # type: ignore

    def show_context_menu(self, pos: QtCore.QPoint):
        menu = QtWidgets.QMenu()
        if not self.currentItem():
            return
        select_apk_action = menu.addAction(self.locale_manager.search_key("select_apk"))
        extraction_action = menu.addAction(
            self.locale_manager.search_key("extract_apk")
        )
        decryption_action = menu.addAction(
            self.locale_manager.search_key("decrypt_apk")
        )
        decryption_mods_action = menu.addAction(
            self.locale_manager.search_key("decrypt_apk_mods")
        )
        delete_action = menu.addAction(self.locale_manager.search_key("delete_apk"))
        action = menu.exec_(self.mapToGlobal(pos))
        if action == delete_action:
            self.delete_apk()
        elif action == extraction_action:
            self.extract_apk()
        elif action == select_apk_action:
            self.select_apk()
        elif action == decryption_action:
            self.decrypt_apk()
        elif action == decryption_mods_action:
            self.decrypt_apk_with_mods()

    def get_apks(self):
        self.apks = io.apk.Apk.get_all_downloaded()
        for apk in self.apks:
            self.addItem(apk.format())

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Delete:
            self.delete_apk()

    def get_selected_apk_text(self):
        return self.currentItem().text()

    def get_selected_apk(self):
        return io.apk.Apk.from_format_string(self.get_selected_apk_text())

    def delete_apk(self):
        ui_dialog.Dialog().yes_no_box(
            icon=QtWidgets.QMessageBox.Icon.Question,
            text=self.locale_manager.search_key("delete_apk_text"),
            informative_text=self.locale_manager.search_key("delete_apk_info"),
            window_title=self.locale_manager.search_key("delete_apk_title"),
            default_button=QtWidgets.QMessageBox.StandardButton.No,
            on_yes=self.delete_apk_call,
        )

    def delete_apk_call(self):
        apk = self.get_selected_apk()
        apk.delete()
        self.takeItem(self.currentRow())

    def extract_apk(self):
        if not io.apk.Apk.check_apktool_installed():
            ui_dialog.Dialog().yes_no_box(
                icon=QtWidgets.QMessageBox.Icon.Warning,
                text=self.locale_manager.search_key("apk_tool_missing_text"),
                informative_text=self.locale_manager.search_key(
                    "apk_tool_missing_info"
                ),
                window_title=self.locale_manager.search_key("apk_tool_missing_title"),
                default_button=QtWidgets.QMessageBox.StandardButton.No,
                on_yes=self.open_apktool_install_page,
            )
        else:
            apk = self.get_selected_apk()
            apk.extract()
            apk.extracted_path.open()

    def open_apktool_install_page(self):
        webbrowser.open("https://ibotpeaches.github.io/Apktool/install/")

    def select_apk(self):
        apk = self.get_selected_apk()
        self.on_select_apk(apk)

    def decrypt_apk(self):
        apk = self.get_selected_apk()
        self.on_decrypt_apk(apk, False)

    def decrypt_apk_with_mods(self):
        apk = self.get_selected_apk()
        self.on_decrypt_apk(apk, True)


class ApkDownloader(QtWidgets.QWidget):
    def __init__(
        self,
        add_call: Callable[..., Any],
        go_back_call: Callable[..., Any],
        on_load_apks: Optional[Callable[..., Any]] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ApkDownloader, self).__init__(parent)
        self.add_call = add_call
        self.go_back_call = go_back_call
        self.downloading_apks: list[str] = []
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.on_load_apks = on_load_apks
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ApkAdder")
        self._layout = QtWidgets.QVBoxLayout()
        self.setLayout(self._layout)

        self.resize(600, 500)

        self.downloadable_apks_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.downloadable_apks_layout)

        for cc in country_code.CountryCode.get_all():
            self.downloadable_apks_layout.addWidget(
                DownloadableApksList(cc, self.download_apk, self.on_load_apks)
            )

        self.button_layout = QtWidgets.QGridLayout()
        self._layout.addLayout(self.button_layout)

        self.button_layout.setColumnStretch(1, 1)
        self.button_layout.setContentsMargins(5, 0, 0, 0)

        self.back_button = QtWidgets.QPushButton(self.locale_manager.search_key("back"))
        self.button_layout.addWidget(self.back_button, 0, 0)
        self.back_button.clicked.connect(self.go_back_call)  # type: ignore

    def download_apk(self, apk: io.apk.Apk):
        apk_id = apk.get_id()
        if apk_id in self.downloading_apks:
            return
        title = self.locale_manager.search_key("downloading_apk") % apk.format()
        self.downloading_apks.append(apk_id)
        self.progress_bar = ui_progress.ProgressBar(title, None, self)
        self._layout.addWidget(self.progress_bar)
        self.progress_bar.show()
        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished_args(
            self.download_thread, self.on_download_finished, [apk], [apk]
        )

    def on_download_finished(self, apk: io.apk.Apk):
        apk_id = apk.get_id()
        if apk_id in self.downloading_apks:
            self.downloading_apks.remove(apk_id)
        if not self.downloading_apks:
            self.add_call(apk)

    def download_thread(self, apk: io.apk.Apk):
        apk.download_apk()  # self.progress_bar.set_progress_full)

    def select_element(self, apk: io.apk.Apk):
        for i in range(self.downloadable_apks_layout.count()):
            widget = self.downloadable_apks_layout.itemAt(i).widget()
            if isinstance(widget, DownloadableApksList):
                if widget.cc == apk.country_code:  # type: ignore
                    widget.select_element(apk)  # type: ignore
                    break


class DownloadableApksList(QtWidgets.QWidget):
    def __init__(
        self,
        cc: "country_code.CountryCode",
        download_call: Callable[..., Any],
        on_load: Optional[Callable[..., Any]] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(DownloadableApksList, self).__init__(parent)
        self.cc = cc
        self.download_call = download_call
        self.on_load = on_load
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("DownloadableApksList")

        self.list_layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.list_layout)

        self.cc_label = QtWidgets.QLabel(self.cc.name)
        self.list_layout.addWidget(self.cc_label)

        self.apk_list = QtWidgets.QListWidget()
        self.list_layout.addWidget(self.apk_list)

        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.load_apks, self.on_load
        )

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

    def select_element(self, apk: io.apk.Apk):
        for i in range(self.apk_list.count()):
            if apk.game_version.format() == self.apk_list.item(i).text():
                self.apk_list.setCurrentRow(i)
                break
