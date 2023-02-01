from typing import Callable, Optional
from PyQt5 import QtWidgets, QtCore, QtGui
from bcml.core import io, country_code, game_version, mods
from bcml.ui import ui_dialog, ui_file_dialog, main


class ModView(QtWidgets.QWidget):
    def __init__(
        self,
        changes: "main.Changes",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ModView, self).__init__(parent)
        self.changes = changes
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ModView")

        self._layout = QtWidgets.QHBoxLayout()
        self.setLayout(self._layout)

        self.mod_list = ModList(
            self.create_mod, self.show_mod_info, self.hide_mod_info, self
        )
        self._layout.addWidget(self.mod_list)

        self.mod_info = ModInfoView(
            self.on_create_mod, self.on_save_mod, self.hide_mod_info, self.changes, self
        )
        self.mod_info.hide()
        self._layout.addWidget(self.mod_info)

    def create_mod(self):
        self.mod_info.reset()
        self.mod_info.load_defaults()
        self.mod_info.show()
        self.mod_info.create_mod_button.show()
        self.mod_info.save_mod_button.hide()
        self.mod_info.delete_mod_button.hide()

    def on_create_mod(self, md: mods.bc_mod.Mod):
        self.mod_info.hide()
        self.mod_list.add_mod_obj(md)

    def on_save_mod(self, md: mods.bc_mod.Mod):
        self.mod_list.add_mod_obj(md)

    def show_mod_info(self, md: mods.bc_mod.Mod):
        self.mod_info.load_mod(md)
        self.mod_info.show()
        self.mod_info.create_mod_button.hide()
        self.mod_info.save_mod_button.show()
        self.mod_info.delete_mod_button.show()

    def hide_mod_info(self):
        self.mod_info.hide()
        self.refresh()

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if event.key() == QtCore.Qt.Key.Key_Escape:
            self.mod_info.close_wrapper()

    def refresh(self):
        self.mod_list.refresh_mods()


class ModInfoView(QtWidgets.QWidget):
    def __init__(
        self,
        on_create_mod: Callable[[mods.bc_mod.Mod], None],
        on_save_mod: Callable[[mods.bc_mod.Mod], None],
        hide_mod_info: Callable[[], None],
        changes: "main.Changes",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ModInfoView, self).__init__(parent)
        self.on_create_mod = on_create_mod
        self.on_save_mod = on_save_mod
        self.hide_mod_info = hide_mod_info
        self.changes = changes
        self.mod: Optional[mods.bc_mod.Mod] = None
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ModInfoView")

        self._layout = QtWidgets.QGridLayout()
        self.setLayout(self._layout)

        self._layout.setColumnStretch(0, 1)
        self._layout.setColumnStretch(1, 5)

        self.mod_name_label = QtWidgets.QLabel("Mod Name (Required)")
        self._layout.addWidget(self.mod_name_label, 0, 0)
        self.mod_name = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_name, 0, 1)

        self.mod_desc_label = QtWidgets.QLabel("Mod Description")
        self._layout.addWidget(self.mod_desc_label, 1, 0)
        self.mod_desc = QtWidgets.QTextEdit()

        self._layout.addWidget(self.mod_desc, 1, 1)

        self.mod_author_label = QtWidgets.QLabel("Mod Author (Required)")
        self._layout.addWidget(self.mod_author_label, 2, 0)
        self.mod_author = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_author, 2, 1)

        self.mod_game_version_label = QtWidgets.QLabel("Mod Game Version (Required)")
        self._layout.addWidget(self.mod_game_version_label, 3, 0)
        self.mod_game_version = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_game_version, 3, 1)

        self.mod_country_code_label = QtWidgets.QLabel("Mod Country Code (Required)")
        self._layout.addWidget(self.mod_country_code_label, 4, 0)
        self.mod_country_code_dropdown = QtWidgets.QComboBox()
        self.mod_country_code_dropdown.addItems(country_code.CountryCode.get_all_str())
        self._layout.addWidget(self.mod_country_code_dropdown, 4, 1)

        self.mod_version_label = QtWidgets.QLabel("Mod Version (Required)")
        self._layout.addWidget(self.mod_version_label, 5, 0)
        self.mod_version = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_version, 5, 1)

        self.mod_url_label = QtWidgets.QLabel("Mod Website")
        self._layout.addWidget(self.mod_url_label, 6, 0)
        self.mod_url = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_url, 6, 1)

        self.mod_id_label = QtWidgets.QLabel("Mod ID")
        self._layout.addWidget(self.mod_id_label, 7, 0)
        self.mod_id = QtWidgets.QLineEdit()
        self._layout.addWidget(self.mod_id, 7, 1)
        self.mod_id.setReadOnly(True)

        self._layout.setRowStretch(8, 1)

        self.button_layout = QtWidgets.QVBoxLayout()
        self._layout.addLayout(self.button_layout, 9, 0, 1, 2)

        self.create_mod_button = QtWidgets.QPushButton("Create Mod")
        self.create_mod_button.clicked.connect(self.create_mod)  # type: ignore
        self.button_layout.addWidget(self.create_mod_button)
        self.create_mod_button.hide()

        self.save_mod_button = QtWidgets.QPushButton("Save Changes")
        self.save_mod_button.clicked.connect(self.save_mod)  # type: ignore
        self.button_layout.addWidget(self.save_mod_button)
        self.save_mod_button.hide()

        self.delete_mod_button = QtWidgets.QPushButton("Delete Mod")
        self.delete_mod_button.clicked.connect(self.delete_mod)  # type: ignore
        self.button_layout.addWidget(self.delete_mod_button)
        self.delete_mod_button.hide()

        self.cancel_button = QtWidgets.QPushButton("Close")
        self.cancel_button.clicked.connect(self.close_wrapper)  # type: ignore
        self.button_layout.addWidget(self.cancel_button)

        self._layout.setRowStretch(10, 1)

        change = main.Change(self.has_changed, self.save_and_close_wrapper)
        self.changes.add(change)

    def get_all_attrs(self):
        return [
            self.mod_name,
            self.mod_desc,
            self.mod_author,
            self.mod_game_version,
            self.mod_country_code_dropdown,
            self.mod_version,
            self.mod_url,
            self.mod_id,
        ]

    def get_required_attrs(self):
        required_attrs = [
            "mod_name",
            "mod_author",
            "mod_game_version",
            "mod_country_code_dropdown",
            "mod_version",
        ]
        return [getattr(self, attr) for attr in required_attrs]

    def has_attrs(self):
        required_attrs = self.get_required_attrs()
        for attr in required_attrs:
            if isinstance(attr, QtWidgets.QLineEdit):
                if attr.text() == "":
                    return False
            elif isinstance(attr, QtWidgets.QComboBox):
                if attr.currentText() == "":
                    return False
            elif isinstance(attr, QtWidgets.QTextEdit):
                if attr.toPlainText() == "":
                    return False
        return True

    def get_attrs_dict(self) -> dict[str, str]:
        attrs = self.get_all_attrs()
        return {
            "name": attrs[0].text(),  # type: ignore
            "desc": attrs[1].toPlainText(),  # type: ignore
            "author": attrs[2].text(),  # type: ignore
            "game_version": attrs[3].text(),  # type: ignore
            "country_code": attrs[4].currentText(),  # type: ignore
            "version": attrs[5].text(),  # type: ignore
            "url": attrs[6].text(),  # type: ignore
            "id": attrs[7].text(),  # type: ignore
        }

    def create_mod(self):
        md = self.gen_mod()
        if md is None:
            return
        self.on_create_mod(md)

    def gen_mod(self):
        if not self.has_attrs():
            return
        attrs = self.get_attrs_dict()
        cc = country_code.CountryCode.from_code(attrs["country_code"])
        gv = game_version.GameVersion.from_string_latest(attrs["game_version"], cc)
        md = mods.bc_mod.Mod(
            attrs["name"],
            attrs["author"],
            attrs["desc"],
            cc,
            gv,
            attrs["id"],
            attrs["version"],
            attrs["url"],
        )
        return md

    def load_defaults(self):
        self.mod_version.setText("1.0.0")

        default_author = io.config.Config().get(io.config.Key.DEFAULT_AUTHOR)
        if default_author is not None:
            self.mod_author.setText(default_author)

        mod_id = mods.bc_mod.Mod.create_mod_id()
        self.mod_id.setText(mod_id)

        selected_apk = io.apk.Apk.get_selected_apk()
        if selected_apk is None:
            return
        self.mod_country_code_dropdown.setCurrentText(
            selected_apk.country_code.get_code()
        )
        self.mod_game_version.setText(selected_apk.game_version.to_string())

    def load_mod(self, mod: mods.bc_mod.Mod):
        self.mod = mod
        self.mod_name.setText(mod.name)
        self.mod_desc.setText(mod.description)
        self.mod_author.setText(mod.author)
        self.mod_game_version.setText(mod.game_version.to_string())
        self.mod_country_code_dropdown.setCurrentText(mod.country_code.get_code())
        self.mod_version.setText(mod.mod_version)
        self.mod_url.setText(mod.mod_url if mod.mod_url else "")
        self.mod_id.setText(mod.mod_id)

    def save_mod(self):
        md = self.gen_mod()
        if md is None:
            return
        mods.mod_manager.ModManager().save_mod(md)
        self.mod = md
        self.on_save_mod(md)

    def reset(self):
        self.mod_name.setText("")
        self.mod_desc.setText("")
        self.mod_author.setText("")
        self.mod_game_version.setText("")
        self.mod_country_code_dropdown.setCurrentIndex(0)
        self.mod_version.setText("")
        self.mod_url.setText("")

    def keyPressEvent(self, event: QtGui.QKeyEvent):  # type: ignore
        if (
            event.key() == QtCore.Qt.Key.Key_S
            and event.modifiers() == QtCore.Qt.KeyboardModifier.ControlModifier
        ):
            self.save_mod()
            return
        elif event.key() == QtCore.Qt.Key.Key_Escape:
            self.close_wrapper()
            return
        super().keyPressEvent(event)

    def has_changed(self) -> bool:
        md = self.gen_mod()
        if md is None:
            return False
        if self.mod is None:
            return True
        return self.mod.get_hash() != md.get_hash()

    def close_wrapper(self):
        if self.has_changed():
            ui_dialog.Dialog.save_changes_dialog(
                self.save_and_close_wrapper, self.hide_mod_info
            )
        else:
            self.hide_mod_info()

    def save_and_close_wrapper(self):
        self.save_mod()
        self.hide_mod_info()

    def delete_mod(self):
        if self.mod is None:
            return

        ui_dialog.Dialog.yes_no_box(
            QtWidgets.QMessageBox.Icon.Warning,
            "Delete Mod",
            f"Are you sure you want to delete\n{self.mod.get_full_mod_name()}?",
            "Delete",
            QtWidgets.QMessageBox.StandardButton.No,
            self.delete_mod_wrapper,
        )

    def delete_mod_wrapper(self):
        if self.mod is None:
            return
        mods.mod_manager.ModManager().remove_mod(self.mod)
        self.hide_mod_info()


class ModList(QtWidgets.QWidget):
    def __init__(
        self,
        on_create_mod: Callable[..., None],
        show_mod_info: Callable[[mods.bc_mod.Mod], None],
        on_delete_mod: Callable[..., None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ModList, self).__init__(parent)
        self.on_create_mod = on_create_mod
        self.show_mod_info = show_mod_info
        self.on_delete_mod = on_delete_mod
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ModList")

        self._layout = QtWidgets.QVBoxLayout()
        self.setLayout(self._layout)

        self.add_ui()

    def add_ui(self):
        self.label = QtWidgets.QLabel("Mods")
        self._layout.addWidget(self.label)

        self.mod_list = QtWidgets.QListWidget()
        self._layout.addWidget(self.mod_list)
        self.mod_list.itemSelectionChanged.connect(self.show_mod_info_wrapper_selected)  # type: ignore
        self.mod_list.itemClicked.connect(self.show_mod_info_wrapper)  # type: ignore

        self.button_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.button_layout)

        self.add_mod_button = QtWidgets.QPushButton("Add Mod from File")
        self.add_mod_button.clicked.connect(self.add_mod)  # type: ignore
        self.button_layout.addWidget(self.add_mod_button)

        self.create_mod_button = QtWidgets.QPushButton("Create Mod")
        self.create_mod_button.clicked.connect(self.create_mod)  # type: ignore
        self.button_layout.addWidget(self.create_mod_button)

        self.button_layout.addStretch(1)

        self.refresh_mod_button = QtWidgets.QPushButton("Refresh Mods")
        self.refresh_mod_button.clicked.connect(self.refresh_mods)  # type: ignore
        self.button_layout.addWidget(self.refresh_mod_button)

        self.open_mod_folder_button = QtWidgets.QPushButton("Open Mod Folder")
        self.open_mod_folder_button.clicked.connect(self.open_mod_folder)  # type: ignore
        self.button_layout.addWidget(self.open_mod_folder_button)

        self.get_add_mods()

        self.mod_list.setContextMenuPolicy(
            QtCore.Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.mod_list.customContextMenuRequested.connect(self.show_context_menu)  # type: ignore

    def show_context_menu(self, pos: QtCore.QPoint):
        item = self.mod_list.itemAt(pos)
        if item is None:
            return
        menu = QtWidgets.QMenu()
        menu.addAction("Delete Mod", self.delete_mod_wrapper)
        menu.exec_(self.mod_list.mapToGlobal(pos))

    def delete_mod_wrapper(self):
        items = self.mod_list.selectedItems()
        if len(items) > 0:
            md = mods.mod_manager.ModManager().get_mod_by_full_name(items[0].text())
            if md is not None:
                ui_dialog.Dialog.yes_no_box(
                    QtWidgets.QMessageBox.Icon.Warning,
                    "Delete Mod",
                    f"Are you sure you want to delete\n{md.get_full_mod_name()}?",
                    "Delete",
                    QtWidgets.QMessageBox.StandardButton.No,
                    self.delete_mod,
                )

    def delete_mod(self):
        items = self.mod_list.selectedItems()
        if len(items) > 0:
            md = mods.mod_manager.ModManager().get_mod_by_full_name(items[0].text())
            if md is not None:
                mods.mod_manager.ModManager().remove_mod(md)
                self.refresh_mods()
                self.on_delete_mod()

    def show_mod_info_wrapper(self, item: QtWidgets.QListWidgetItem):
        mod_name = item.text()
        md = mods.mod_manager.ModManager().get_mod_by_full_name(mod_name)
        if md is not None:
            self.show_mod_info(md)

    def show_mod_info_wrapper_selected(self):
        items = self.mod_list.selectedItems()
        if len(items) > 0:
            self.show_mod_info_wrapper(items[0])

    def get_add_mods(self):
        mds = mods.mod_manager.ModManager().get_mods()
        for md in mds:
            self.mod_list.addItem(md.get_full_mod_name())

    def add_mod(self):
        extension = mods.bc_mod.Mod.get_extension()
        files = ui_file_dialog.FileDialog(self).select_files(
            "Select Mod Files",
            "",
            f"Mod Files (*{extension});;All Files (*)",
            None,
        )
        for file in files:
            path = io.path.Path(file)
            md = mods.bc_mod.Mod.load(path)
            if md is not None:
                mods.mod_manager.ModManager().add_mod(md)
                self.refresh_mods()
            else:
                ui_dialog.Dialog.error_dialog(
                    "Failed to load mod",
                    f"Failed to load mod from:\n {path}.\nThe file may be corrupted or not a valid mod.",
                )

    def add_mod_obj(self, md: mods.bc_mod.Mod):
        mods.mod_manager.ModManager().add_mod(md)
        self.refresh_mods()

    def create_mod(self):
        self.on_create_mod()

    def refresh_mods(self):
        self.mod_list.clear()
        self.get_add_mods()

    def open_mod_folder(self):
        mods.mod_manager.ModManager().mod_folder.open()
