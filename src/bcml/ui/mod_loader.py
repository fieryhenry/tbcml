from PyQt5 import QtCore, QtWidgets
from bcml.core import io, game_data, mods
from bcml.ui import progress, ui_thread, apk_manager


class ModLoader(QtWidgets.QDialog):
    def __init__(self):
        super(ModLoader, self).__init__()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ModLoader")
        self.resize(400, 300)
        self.setWindowTitle("Mod Loader")
        self.setWindowModality(QtCore.Qt.WindowModality.WindowModal)

        self._layout = QtWidgets.QVBoxLayout(self)
        self.setLayout(self._layout)

        self.add_ui()

    def load_data(self):
        self.apk.extract()
        self.apk.copy_server_files()

    def add_ui(self):
        self.loading_mods = False
        self.selected_apk = io.config.Config().get(io.config.Key.SELECTED_APK)
        if not self.selected_apk:
            self._layout.addWidget(QtWidgets.QLabel("No APK selected."))
            self.apk_manager = apk_manager.ApkManager()
            self.apk_manager.show()
            return
        self.apk = io.apk.Apk.from_format_string(self.selected_apk)

        self._data_thread = ui_thread.ThreadWorker.run_in_thread(self.load_data)

        self._layout.addWidget(QtWidgets.QLabel(f"Selected APK: {self.apk.format()}"))

        self.mod_list = QtWidgets.QListWidget()
        self.mod_list.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._layout.addWidget(self.mod_list)

        self.load_button = QtWidgets.QPushButton("Load Selected Mods")
        self.load_button.clicked.connect(self.load_mods)  # type: ignore
        self._layout.addWidget(self.load_button)

        self.load_all_button = QtWidgets.QPushButton("Load All Mods")
        self.load_all_button.clicked.connect(self.load_all_mods)  # type: ignore
        self._layout.addWidget(self.load_all_button)

        self.refresh_button = QtWidgets.QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_mods)  # type: ignore
        self._layout.addWidget(self.refresh_button)

        self.refresh_mods()

    def refresh_mods(self):
        self.mod_list.clear()
        for mod in mods.mod_manager.ModManager().get_mods():
            self.mod_list.addItem(mod.get_full_mod_name())

    def load_mods_wrapper(self, mod_names: list[str]):
        if self.loading_mods:
            return
        try:
            self.progress_bar.close()
        except AttributeError:
            pass
        self.progress_bar = progress.ProgressBar("Loading mods...", None, self)
        self._layout.addWidget(self.progress_bar)
        self.progress_bar.show()

        self._thread = ui_thread.ThreadWorker.run_in_thread(
            self.load_mods_thread, mod_names
        )

    def load_mods_thread(self, mod_names: list[str]):
        self.loading_mods = True
        total_progress = 100
        self.progress_bar.set_progress_str("Loading Game Data", 0, total_progress)
        game_packs = game_data.pack.GamePacks.from_apk(self.apk)
        self.progress_bar.set_progress_str("Applying Mods", 10, total_progress)
        mds: list[mods.bc_mod.Mod] = []
        for mod_name in mod_names:
            md = mods.mod_manager.ModManager().get_mod_by_full_name(mod_name)
            if md is not None:
                mds.append(md)
        game_packs.apply_mods(mds)
        self.progress_bar.set_progress(15, total_progress)
        self.apk.load_packs_into_game(
            game_packs, self.progress_bar.set_progress_str, 15, 100
        )
        self.progress_bar.set_progress_str("Finished", 100, total_progress)

        self.loading_mods = False

    def load_mods(self):
        indexes = self.mod_list.selectedIndexes()
        mod_names = [self.mod_list.item(index.row()).text() for index in indexes]
        self.load_mods_wrapper(mod_names)

    def load_all_mods(self):
        mod_names = [
            self.mod_list.item(index).text() for index in range(self.mod_list.count())
        ]
        self.load_mods_wrapper(mod_names)
