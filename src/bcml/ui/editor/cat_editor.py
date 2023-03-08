import time
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
        self._cat_list = QtWidgets.QListWidget(self)
        self._cat_list.setObjectName("cat_list")
        self._layout.addWidget(self._cat_list)

        self.search_bar = QtWidgets.QLineEdit(self)
        self.search_bar.setPlaceholderText("Search")
        self.search_bar.textChanged.connect(self.search)
        self._layout.addWidget(self.search_bar)

        self.load_cat_thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.load_cats, self.load_cats_finished
        )

    def load_cats(self):
        self.all_cats = game_data.cat_base.cats.Cats.from_game_data(self.game_packs)
        self.all_cats.import_cats(self.mod.cat_base.cats, self.game_packs)
        self.blank_uni_path = io.path.Path("assets", True)
        names = ["uni_c.png", "uni_f.png", "uni_s.png"]
        paths = [self.blank_uni_path.add(name) for name in names]
        self.blank_icons = {
            game_data.cat_base.cats.FormType.FIRST: io.bc_image.BCImage(
                paths[0].read()
            ),
            game_data.cat_base.cats.FormType.SECOND: io.bc_image.BCImage(
                paths[1].read()
            ),
            game_data.cat_base.cats.FormType.THIRD: io.bc_image.BCImage(
                paths[2].read()
            ),
        }

    def load_cats_finished(self):
        self._cat_list.clear()
        for cat in self.all_cats.cats.values():
            cat_widget = CatListItem(cat, self.blank_icons, self._cat_list)
            item = QtWidgets.QListWidgetItem(self._cat_list)
            size_hint = cat_widget.sizeHint()
            size_hint.setHeight(size_hint.height() // 2)
            item.setSizeHint(size_hint)
            self._cat_list.addItem(item)
            self._cat_list.setItemWidget(item, cat_widget)

        self._cat_list.itemDoubleClicked.connect(self.edit_cat)

        self.last_time = time.time()
        self._cat_list.verticalScrollBar().valueChanged.connect(self.check_items)
        self.check_items(True)

    def is_cat_item_visible(self, item: QtWidgets.QListWidgetItem):
        return self._cat_list.visualItemRect(item).bottom() <= self._cat_list.height()

    def check_items(self, force: bool = False):
        if time.time() - self.last_time < 0.2 and not force:
            return
        self.last_time = time.time()

        i = 0
        start = -1
        stop = -1
        while i < self._cat_list.count():
            item = self._cat_list.item(i)
            if self.is_cat_item_visible(item) and start == -1:
                start = i
            elif not self.is_cat_item_visible(item) and start != -1:
                stop = i
                break

            i += 1

        if start == -1:
            return

        if stop == -1:
            stop = self._cat_list.count()

        for i in range(start - 1, stop + 1):
            item = self._cat_list.item(i)
            cat_widget = self._cat_list.itemWidget(item)
            try:
                cat_widget.add_ui()
            except AttributeError:
                pass

    def edit_cat(self, item: QtWidgets.QListWidgetItem):
        cat_widget = self._cat_list.itemWidget(item)
        cat_widget.edit_cat()

    def search(self, text: str):
        for i in range(self._cat_list.count()):
            item = self._cat_list.item(i)
            cat_widget = self._cat_list.itemWidget(item)
            if isinstance(cat_widget, CatListItem):
                if cat_widget.has_name(text):
                    item.setHidden(False)
                else:
                    item.setHidden(True)

        self.check_items(True)


class CatListItem(QtWidgets.QListWidget):
    def __init__(
        self,
        cat: "game_data.cat_base.cats.Cat",
        blank_icons: dict["game_data.cat_base.cats.FormType", "io.bc_image.BCImage"],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(CatListItem, self).__init__(parent)
        self.cat = cat
        self.blank_icons = blank_icons
        self.ui_added = False
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("CatListItem")
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(0)
        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.setObjectName("layout")

        self.wrapper = QtWidgets.QWidget(self)
        self.wrapper.setContentsMargins(0, 0, 0, 0)
        self.wrapper.setObjectName("wrapper")
        self.wrapper_layout = QtWidgets.QGridLayout(self.wrapper)
        self.wrapper_layout.setObjectName("wrapper_layout")
        self.wrapper_layout.setColumnStretch(0, 1)
        self.wrapper_layout.setColumnStretch(1, 10)
        self._layout.addWidget(self.wrapper, 0, 0)

    def add_ui(self):
        if self.ui_added:
            return
        self.ui_added = True
        self.id_label = QtWidgets.QLabel()
        self.id_label.setObjectName("id_label")
        self.id_label.setText(str(self.cat.cat_id).zfill(3))
        self.wrapper_layout.addWidget(self.id_label, 0, 0)

        self.cat_form_layout = QtWidgets.QGridLayout()
        self.cat_form_layout.setObjectName("cat_form_layout")
        self.cat_form_layout.setContentsMargins(0, 0, 0, 0)
        self.cat_form_layout.setSpacing(0)
        self.wrapper_layout.addLayout(self.cat_form_layout, 0, 1)

        self.cat_form_layout.setColumnStretch(0, 1)
        self.cat_form_layout.setColumnStretch(1, 1)
        self.cat_form_layout.setColumnStretch(2, 1)

        for form in self.cat.forms.values():
            form_layout = QtWidgets.QGridLayout()
            form_layout.setContentsMargins(0, 0, 0, 0)
            form_layout.setSpacing(0)
            form_layout.setObjectName("form_layout")
            self.cat_form_layout.addLayout(form_layout, 0, form.form.get_index())

            form_name = QtWidgets.QLabel()
            form_name.setObjectName("form_name")
            form_name.setText(form.name)
            form_layout.addWidget(form_name, 0, 0)

            form_image = QtWidgets.QLabel()
            form_image.setObjectName("form_image")
            icon = form.deploy_icon
            if icon.is_empty() or icon.width == 1 or icon.height == 1:
                icon = self.blank_icons[form.form]
            img_data = icon.to_data().to_bytes()
            img = QtGui.QImage.fromData(img_data)
            img = img.copy(img.width() // 2 - 55, img.height() // 2 - 42, 110, 85)
            img = img.scaled(
                80,
                80,
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            )
            form_image.setPixmap(QtGui.QPixmap.fromImage(img))

            form_layout.addWidget(form_image, 0, 1)

        total_forms = len(self.cat.forms)
        widgets_to_add = 3 - total_forms
        for i in range(widgets_to_add):
            widget = QtWidgets.QWidget()
            widget.setObjectName("spacer")
            self.cat_form_layout.addWidget(widget, 0, total_forms + i)

    def edit_cat(self):
        print("open cat editor")
        print(self.cat.unit_buy_data.egg_id)
        print(self.cat.unit_buy_data.egg_val)

    def has_name(self, name: str):
        for form in self.cat.forms.values():
            if name.lower() in form.name.lower():
                return True
        return False
