import time
import enum
from typing import Any, Callable, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from bcml.core import game_data, io, locale_handler, mods
from bcml.ui.utils import ui_thread


class SearchMode(enum.Enum):
    CONTAINS = 0
    STARTS_WITH = 1
    ENDS_WITH = 2
    EXACT = 3


class SearchFilter:
    def __init__(
        self,
        form_name: str,
        rarities: Optional[list[int]] = None,
        or_mode: bool = False,
        name_mode: SearchMode = SearchMode.CONTAINS,
        case_sensitive: bool = False,
    ):
        self.form_name = form_name
        self.rarities = rarities
        self.or_mode = or_mode
        self.name_mode = name_mode
        self.case_sensitive = case_sensitive

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SearchFilter):
            return False
        return (
            self.form_name == other.form_name
            and self.rarities == other.rarities
            and self.or_mode == other.or_mode
            and self.name_mode == other.name_mode
            and self.case_sensitive == other.case_sensitive
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __str__(self) -> str:
        return f"SearchFilter(form_name={self.form_name}, rarities={self.rarities}, or_mode={self.or_mode}, name_mode={self.name_mode}, case_sensitive={self.case_sensitive})"

    def __repr__(self) -> str:
        return self.__str__()


class CatSearchBox(QtWidgets.QWidget):
    def __init__(
        self,
        rarities: dict[int, str],
        on_search: Callable[[SearchFilter], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(CatSearchBox, self).__init__(parent)
        self.on_search = on_search
        self.rarities = rarities
        self.setup_ui()

    def setup_ui(self):
        self.locale_manager = locale_handler.LocalManager.from_config()
        self._layout = QtWidgets.QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._search_box = QtWidgets.QLineEdit(self)
        self._search_box.setPlaceholderText(
            self.locale_manager.search_key("search_placeholder")
        )
        self._layout.addWidget(self._search_box)

        self._search_box.textChanged.connect(self.on_search_text)

        self.filter_button = QtWidgets.QPushButton(self)
        self.filter_button.setText(self.locale_manager.search_key("filter"))
        self.filter_button.setFixedWidth(100)
        self.filter_button.clicked.connect(self.on_filter)
        self.filter: Optional[SearchFilter] = None
        self._layout.addWidget(self.filter_button)

    def on_search_text(self, text: str):
        if self.filter is None:
            self.filter = SearchFilter(text)
        else:
            self.filter.form_name = text
        self.on_search(self.filter)

    def on_filter(self):
        self.filter_window = FilterWindow(self.rarities, self.on_search_window, self)
        self.filter_window.show()

    def on_search_window(self, filter: SearchFilter):
        if filter == SearchFilter("") or filter == SearchFilter(
            "", list(self.rarities.keys())
        ):
            self.set_filter_changed(False)
        else:
            self.set_filter_changed(True)
        self.filter = filter
        self.on_search(filter)

    def set_filter_changed(self, changed: bool):
        if changed:
            self.filter_button.setText(self.locale_manager.search_key("filter_applied"))
        else:
            self.filter_button.setText(self.locale_manager.search_key("filter"))


class FilterWindow(QtWidgets.QDialog):
    def __init__(
        self,
        rarities: dict[int, str],
        on_change: Callable[[SearchFilter], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(FilterWindow, self).__init__(parent)
        self.on_change = on_change
        self.rarities = rarities
        self.setup_ui()

    def setup_ui(self):
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setWindowTitle(self.locale_manager.search_key("filter_title"))
        self.resize(400, 300)

        self._layout = QtWidgets.QVBoxLayout(self)

        self.form_name_layout = QtWidgets.QHBoxLayout()
        self._layout.addLayout(self.form_name_layout)

        self._form_name = QtWidgets.QLineEdit(self)
        self._form_name.setPlaceholderText(
            self.locale_manager.search_key("cat_editor_form_name")
        )
        self.form_name_layout.addWidget(self._form_name)

        self._form_name.textChanged.connect(self.on_form_name)
        self.form_name = ""

        self.case_sensitive = QtWidgets.QCheckBox(self)
        self.case_sensitive.setText(self.locale_manager.search_key("case_sensitive"))
        self.case_sensitive.setChecked(False)
        self.case_sensitive.stateChanged.connect(self.update_filter)
        self.form_name_layout.addWidget(self.case_sensitive)

        self.name_search_mode = QtWidgets.QComboBox(self)
        self.name_search_mode.addItem(self.locale_manager.search_key("contains"))
        self.name_search_mode.addItem(self.locale_manager.search_key("starts_with"))
        self.name_search_mode.addItem(self.locale_manager.search_key("ends_with"))
        self.name_search_mode.addItem(self.locale_manager.search_key("exact_match"))
        self.name_search_mode.currentIndexChanged.connect(self.on_name_search_mode)
        self.name_mode = 0
        self.form_name_layout.addWidget(self.name_search_mode)

        self._rarity_layout = QtWidgets.QGridLayout()
        self._layout.addLayout(self._rarity_layout)

        self._rarity_label = QtWidgets.QLabel(self)
        self._rarity_label.setText(self.locale_manager.search_key("cat_editor_rarity"))
        self._rarity_layout.addWidget(self._rarity_label, 0, 0, 1, 2)

        self._rarity_buttons: dict[int, QtWidgets.QCheckBox] = {}
        for rarity_id, name in self.rarities.items():
            button = QtWidgets.QCheckBox(self)
            button.setText(name)
            button.setChecked(True)
            button.stateChanged.connect(self.on_rarity)
            row = rarity_id // 2 + 1
            column = rarity_id % 2
            self._rarity_layout.addWidget(button, row, column)
            self._rarity_buttons[rarity_id] = button

        self.select_all_rarities = QtWidgets.QPushButton(self)
        self.select_all_rarities.setText(
            self.locale_manager.search_key("cat_editor_select_all_rarities")
        )
        self.select_all_rarities.clicked.connect(self.on_select_all_rarities)
        self._rarity_layout.addWidget(self.select_all_rarities, 4, 0, 1, 2)

        self.rarities_selected: list[int] = list(self.rarities.keys())

        self._layout.addStretch()

        self.or_mode = QtWidgets.QCheckBox(self)
        self.or_mode.setText(self.locale_manager.search_key("or_filter_mode"))
        self.or_mode.setChecked(False)
        self.or_mode.stateChanged.connect(self.update_filter)
        self._layout.addWidget(self.or_mode)

        self.clear_filter = QtWidgets.QPushButton(self)
        self.clear_filter.setText(self.locale_manager.search_key("reset"))
        self.clear_filter.clicked.connect(self.on_clear_filter)
        self._layout.addWidget(self.clear_filter)

    def on_form_name(self, text: str):
        self.form_name = text
        self.update_filter()

    def update_filter(self):
        self.filter = SearchFilter(
            self.form_name,
            self.rarities_selected,
            self.or_mode.isChecked(),
            SearchMode(self.name_mode),
            self.case_sensitive.isChecked(),
        )
        self.on_change(self.filter)

    def on_rarity(self):
        rarities: list[int] = []
        for rarity_id, button in self._rarity_buttons.items():
            if button.isChecked():
                rarities.append(rarity_id)
        self.rarities_selected = rarities
        self.update_filter()

    def on_select_all_rarities(self):
        flip = True
        if len(self.rarities_selected) == len(self.rarities):
            flip = False
        for button in self._rarity_buttons.values():
            button.disconnect()
            button.setChecked(flip)
            button.stateChanged.connect(self.on_rarity)
        self.on_rarity()

    def on_name_search_mode(self, index: int):
        self.name_mode = index
        self.update_filter()

    def on_clear_filter(self):
        self._form_name.setText("")
        self.or_mode.setChecked(False)
        self.case_sensitive.setChecked(False)
        self.name_search_mode.setCurrentIndex(0)
        for button in self._rarity_buttons.values():
            button.disconnect()
            button.setChecked(True)
            button.stateChanged.connect(self.on_rarity)
        self.on_rarity()


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
        self._cat_list = QtWidgets.QListWidget(self)
        self._cat_list.setObjectName("cat_list")
        self._layout.addWidget(self._cat_list)

        self.load_cat_thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.load_cats, self.load_cats_finished
        )

    def load_cats(self):
        self.total_cats = game_data.cat_base.cats.Cats.get_total_cats(self.game_packs)
        self.unit_buy = game_data.cat_base.cats.UnitBuy.from_game_data(self.game_packs)
        self.localizable = self.game_packs.localizable
        self.rarities = self.unit_buy.get_rarities(self.localizable)
        self.talents = game_data.cat_base.cats.Talents.from_game_data(self.game_packs)
        self.nyanko_picture_book = (
            game_data.cat_base.cats.NyankoPictureBook.from_game_data(self.game_packs)
        )
        self.evolve_text = game_data.cat_base.cats.EvolveText.from_game_data(
            self.game_packs
        )

        self.edited_cats: list[game_data.cat_base.cats.Cat] = list(
            self.mod.cat_base.cats.cats.values()
        )
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
        self.search_bar = CatSearchBox(self.rarities, self.search, self)
        self._layout.addWidget(self.search_bar)
        self._cat_list.clear()
        for cat_id in range(self.total_cats):
            cat_widget = CatListItem(cat_id, self.blank_icons, self._cat_list)
            item = QtWidgets.QListWidgetItem(self._cat_list)
            size_hint = cat_widget.sizeHint()
            size_hint.setHeight(size_hint.height() // 2)
            item.setSizeHint(size_hint)
            self._cat_list.addItem(item)
            self._cat_list.setItemWidget(item, cat_widget)

        self._cat_list.itemDoubleClicked.connect(self.on_edit)

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
            cat_widget: CatListItem = self._cat_list.itemWidget(item)
            try:
                cat_widget.load_cat(  # type: ignore
                    self.game_packs,
                    self.unit_buy,
                    self.talents,
                    self.nyanko_picture_book,
                    self.evolve_text,
                )

            except AttributeError:
                pass

    def search(self, filter: SearchFilter):
        for i in range(self._cat_list.count()):
            item = self._cat_list.item(i)
            cat_widget = self._cat_list.itemWidget(item)
            if isinstance(cat_widget, CatListItem):
                cat_widget = CatListItem.fix_type_hint(cat_widget)
                cat_widget.load_cat(
                    self.game_packs,
                    self.unit_buy,
                    self.talents,
                    self.nyanko_picture_book,
                    self.evolve_text,
                )
                has_name = cat_widget.has_name(
                    filter.form_name, filter.name_mode, filter.case_sensitive
                )
                is_rarities = cat_widget.is_rarities(filter.rarities)
                if filter.or_mode:
                    item.setHidden(not (has_name or is_rarities))
                else:
                    item.setHidden(not (has_name and is_rarities))

        self.check_items(True)

    def on_edit(self, widget: QtWidgets.QListWidgetItem):
        cat_widget = self._cat_list.itemWidget(widget)
        if not isinstance(cat_widget, CatListItem):
            return
        cat: "game_data.cat_base.cats.Cat" = cat_widget.cat  # type: ignore

        self.cat_editor = CatEditScreen(cat, self.on_save, self)
        self.cat_editor.show()

    def save(self):
        for cat in self.edited_cats:
            self.mod.cat_base.cats.set_cat(cat)

    def on_save(self, cat: "game_data.cat_base.cats.Cat"):
        for i, edited_cat in enumerate(self.edited_cats):
            if edited_cat.cat_id == cat.cat_id:
                self.edited_cats[i] = cat
                break
        else:
            self.edited_cats.append(cat)

        self.save()


class CatListItem(QtWidgets.QListWidget):
    def __init__(
        self,
        cat_id: int,
        blank_icons: dict["game_data.cat_base.cats.FormType", "io.bc_image.BCImage"],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(CatListItem, self).__init__(parent)
        self.blank_icons = blank_icons
        self.cat_id = cat_id
        self.ui_added = False
        self.cat: Optional["game_data.cat_base.cats.Cat"] = None
        self.setup_ui()

    @staticmethod
    def fix_type_hint(widget: "CatListItem"):
        return widget

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

    def set_cat(self, cat: "game_data.cat_base.cats.Cat"):
        self.cat = cat
        self.add_ui()

    def load_cat(
        self,
        game_packs: game_data.pack.GamePacks,
        unit_buy: game_data.cat_base.cats.UnitBuy,
        talents: game_data.cat_base.cats.Talents,
        nyanko_pic_book: game_data.cat_base.cats.NyankoPictureBook,
        evov_text: game_data.cat_base.cats.EvolveText,
    ):
        if self.cat is not None:
            return
        cat = game_data.cat_base.cats.Cat.from_game_data(
            game_packs,
            self.cat_id,
            unit_buy,
            talents,
            nyanko_pic_book,
            evov_text,
        )
        if cat is None:
            return
        self.set_cat(cat)

    def add_ui(self):
        if self.ui_added or self.cat is None:
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
            img_data = icon.fix_libpng_warning().to_data().to_bytes()
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

    def has_name(self, name: str, mode: SearchMode, case_sensitive: bool):
        if self.cat is None:
            return False
        for form in self.cat.forms.values():
            form_name = form.name.lower() if not case_sensitive else form.name
            search_name = name.lower() if not case_sensitive else name
            if mode == SearchMode.EXACT:
                if form_name == search_name:
                    return True
            elif mode == SearchMode.CONTAINS:
                if search_name in form_name:
                    return True
            elif mode == SearchMode.STARTS_WITH:
                if form_name.startswith(search_name):
                    return True
            elif mode == SearchMode.ENDS_WITH:
                if form_name.endswith(search_name):
                    return True
        return False

    def is_rarity(self, rarity: int):
        if self.cat is None:
            return False
        return self.cat.unit_buy_data.rarity.value == rarity

    def is_rarities(self, rarities: Optional[list[int]]):
        if self.cat is None:
            return False
        if rarities is None:
            return True
        return self.cat.unit_buy_data.rarity.value in rarities


class CatEditScreen(QtWidgets.QDialog):
    def __init__(
        self,
        cat: "game_data.cat_base.cats.Cat",
        on_save: Callable[["game_data.cat_base.cats.Cat"], None],
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(CatEditScreen, self).__init__(parent)
        self.cat = cat
        self.on_save = on_save
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("CatEditScreen")
        self.setWindowTitle(self.locale_manager.search_key("cat_editor_title"))
        self.resize(800, 600)

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setObjectName("layout")

        self._tab_widget = QtWidgets.QTabWidget(self)
        self._tab_widget.setObjectName("tab_widget")
        self._layout.addWidget(self._tab_widget, 0, 0)

        self._tab_widget.addTab(
            self._create_general_tab(),
            self.locale_manager.search_key("cat_editor_general_tab"),
        )
        self._tab_widget.addTab(
            self._create_forms_tab(),
            self.locale_manager.search_key("cat_editor_forms_tab"),
        )

        self.save_button = QtWidgets.QPushButton(self)
        self.save_button.setObjectName("save_button")
        self.save_button.setText(self.locale_manager.search_key("apply"))
        self.save_button.clicked.connect(self.save)
        self._layout.addWidget(self.save_button, 1, 0)

    def _create_general_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("general_tab")
        tab_layout = QtWidgets.QGridLayout(tab)
        tab_layout.setObjectName("tab_layout")

        self._general_tab = GeneralTab(self.cat, tab)
        tab_layout.addWidget(self._general_tab, 0, 0)

        return tab

    def _create_forms_tab(self):
        tab = QtWidgets.QWidget()
        tab.setObjectName("forms_tab")
        tab_layout = QtWidgets.QGridLayout(tab)
        tab_layout.setObjectName("tab_layout")

        self._forms_tab = FormsTab(self.cat, tab)
        tab_layout.addWidget(self._forms_tab, 0, 0)

        return tab

    def save(self):
        self._forms_tab.save()
        self._general_tab.save()
        self.on_save(self.cat)


class GeneralTab(QtWidgets.QWidget):
    def __init__(
        self,
        cat: "game_data.cat_base.cats.Cat",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(GeneralTab, self).__init__(parent)
        self.cat = cat
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("GeneralTab")

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setObjectName("layout")

        self.evolve_text_group = QtWidgets.QGroupBox(self)
        self.evolve_text_group.setObjectName("evolve_text_group")
        self.evolve_text_group.setTitle(
            self.locale_manager.search_key("cat_editor_evolve_text"),
        )
        self._layout.addWidget(self.evolve_text_group, 0, 0)

        self.evolve_text_layout = QtWidgets.QGridLayout(self.evolve_text_group)
        self.evolve_text_layout.setObjectName("evolve_text_layout")

        self.evolve_text_1_label = QtWidgets.QLabel(self.evolve_text_group)
        self.evolve_text_1_label.setObjectName("evolve_text_1_label")
        self.evolve_text_1_label.setText(
            self.locale_manager.search_key("cat_editor_evolve_text_1_label"),
        )
        self.evolve_text_layout.addWidget(self.evolve_text_1_label, 0, 0)

        self.evolve_text_1_edit = QtWidgets.QTextEdit(self.evolve_text_group)
        self.evolve_text_1_edit.setObjectName("evolve_text_1_edit")
        evolve_text = self.cat.evolve_text
        evolve_text_1 = "\n".join(evolve_text[0].text) if evolve_text else ""
        self.evolve_text_1_edit.setText(evolve_text_1)
        self.evolve_text_layout.addWidget(self.evolve_text_1_edit, 0, 1)

        self.evolve_text_2_label = QtWidgets.QLabel(self.evolve_text_group)
        self.evolve_text_2_label.setObjectName("evolve_text_2_label")
        self.evolve_text_2_label.setText(
            self.locale_manager.search_key("cat_editor_evolve_text_2_label"),
        )
        self.evolve_text_layout.addWidget(self.evolve_text_2_label, 1, 0)

        evolve_text_2 = "\n".join(evolve_text[1].text) if evolve_text else ""
        self.evolve_text_2_edit = QtWidgets.QTextEdit(self.evolve_text_group)
        self.evolve_text_2_edit.setObjectName("evolve_text_2_edit")
        self.evolve_text_2_edit.setText(evolve_text_2)
        self.evolve_text_layout.addWidget(self.evolve_text_2_edit, 1, 1)

        self._layout.setRowStretch(0, 1)
        self._layout.setRowStretch(1, 1)

    def save(self):
        text_1 = self.evolve_text_1_edit.toPlainText().splitlines()
        text_2 = self.evolve_text_2_edit.toPlainText().splitlines()
        text_1_obj = game_data.cat_base.cats.EvolveTextText(0, text_1)
        text_2_obj = game_data.cat_base.cats.EvolveTextText(1, text_2)
        self.cat.evolve_text = {
            0: text_1_obj,
            1: text_2_obj,
        }


class FormsTab(QtWidgets.QWidget):
    def __init__(
        self,
        cat: "game_data.cat_base.cats.Cat",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(FormsTab, self).__init__(parent)
        self.cat = cat
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("FormsTab")

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setObjectName("layout")

        self.form_tabs = QtWidgets.QTabWidget(self)
        self.form_tabs.setObjectName("form_tabs")
        self._layout.addWidget(self.form_tabs, 0, 0)

        for form in self.cat.forms.values():
            self.form_tabs.addTab(
                FormTab(form),
                form.name,
            )

    def save(self):
        for index in range(self.form_tabs.count()):
            tab = self.form_tabs.widget(index)
            if isinstance(tab, FormTab):
                tab.save()  # type: ignore


class FormTab(QtWidgets.QWidget):
    def __init__(
        self,
        form: "game_data.cat_base.cats.Form",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(FormTab, self).__init__(parent)
        self.form = form
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("FormTab")

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setObjectName("layout")

        self.form_tabs = QtWidgets.QTabWidget(self)
        self.form_tabs.setObjectName("form_tabs")
        self._layout.addWidget(self.form_tabs, 0, 0)

        self.form_tabs.addTab(
            FormDataTab(self.form),
            self.locale_manager.search_key("cat_editor_form_data_tab"),
        )
        self.form_tabs.addTab(
            StatsTab(self.form),
            self.locale_manager.search_key("cat_editor_form_stats_tab"),
        )

    def save(self):
        for index in range(self.form_tabs.count()):
            tab = self.form_tabs.widget(index)
            if isinstance(tab, FormDataTab):
                tab.save()  # type: ignore
            elif isinstance(tab, StatsTab):
                tab.save()  # type: ignore


class FormDataTab(QtWidgets.QWidget):
    def __init__(
        self,
        form: "game_data.cat_base.cats.Form",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(FormDataTab, self).__init__(parent)
        self.form = form
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("FormTab")

        self._layout = QtWidgets.QGridLayout(self)
        self._layout.setObjectName("layout")

        self.name_group = QtWidgets.QGroupBox(self)
        self.name_group.setObjectName("name_group")
        self.name_group_layout = QtWidgets.QGridLayout(self.name_group)
        self.name_group_layout.setObjectName("name_group_layout")
        self._layout.addWidget(self.name_group, 0, 0)

        self.name_label = QtWidgets.QLabel(self)
        self.name_label.setObjectName("name_label")
        self.name_label.setText(
            self.locale_manager.search_key("cat_editor_form_name"),
        )
        self.name_group_layout.addWidget(self.name_label, 0, 0)

        self.name_edit = QtWidgets.QLineEdit(self)
        self.name_edit.setObjectName("name_edit")
        self.name_edit.setText(self.form.name)
        self.name_group_layout.addWidget(self.name_edit, 1, 0)
        self.name_edit.setPlaceholderText(
            self.locale_manager.search_key("cat_editor_form_name"),
        )

        self.description_group = QtWidgets.QGroupBox(self)
        self.description_group.setObjectName("description_group")
        self.description_group_layout = QtWidgets.QGridLayout(self.description_group)
        self.description_group_layout.setObjectName("description_group_layout")
        self._layout.addWidget(self.description_group, 1, 0)

        self.description_label = QtWidgets.QLabel(self)
        self.description_label.setObjectName("description_label")
        self.description_label.setText(
            self.locale_manager.search_key("cat_editor_form_description"),
        )
        self.description_group_layout.addWidget(self.description_label, 0, 0)

        self.description_edit = QtWidgets.QTextEdit(self)
        self.description_edit.setObjectName("description_edit")
        self.description_edit.setText("\n".join(self.form.description))
        self.description_group_layout.addWidget(self.description_edit, 1, 0)
        self.description_edit.setPlaceholderText(
            self.locale_manager.search_key("cat_editor_form_description"),
        )

        self._layout.setRowStretch(2, 1)

    def save(self):
        name = self.name_edit.text()
        if name:
            self.form.name = name
        description = self.description_edit.toPlainText()
        if description:
            self.form.description = description.split("\n")


class StatsTab(QtWidgets.QWidget):
    def __init__(
        self,
        form: "game_data.cat_base.cats.Form",
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(StatsTab, self).__init__(parent)
        self.form = form
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("StatsTab")

        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")

        self.stats_scroll = QtWidgets.QScrollArea(self)
        self.stats_scroll.setObjectName("stats_scroll")
        self.stats_scroll.setWidgetResizable(True)
        self.stats_scroll_widget = QtWidgets.QWidget(self.stats_scroll)
        self.stats_scroll_widget.setObjectName("stats_scroll_widget")
        self.stats_scroll_layout = QtWidgets.QVBoxLayout(self.stats_scroll_widget)
        self.stats_scroll_layout.setObjectName("stats_scroll_layout")
        self.stats_scroll.setWidget(self.stats_scroll_widget)

        self.stats_scroll.setContentsMargins(0, 0, 0, 0)
        self.stats_scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.stats_scroll_layout.setSpacing(0)
        self.stats_scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)

        self.stats_group = QtWidgets.QGroupBox(self)
        self.stats_group.setObjectName("stats_group")
        self.stats_group_layout = QtWidgets.QGridLayout(self.stats_group)
        self.stats_group_layout.setObjectName("stats_group_layout")
        self.stats_scroll_layout.addWidget(self.stats_group)

        self._layout.addWidget(self.stats_scroll)

        self.column_0_layout = QtWidgets.QVBoxLayout()
        self.column_0_layout.setObjectName("column_0_layout")
        self.stats_group_layout.addLayout(self.column_0_layout, 0, 0)

        self.column_1_layout = QtWidgets.QVBoxLayout()
        self.column_1_layout.setObjectName("column_1_layout")
        self.stats_group_layout.addLayout(self.column_1_layout, 0, 1)

        self.hp_edit = SpinBoxEdit(
            self.locale_manager.search_key("hp"),
            self.form.stats.hp,
            self,
        )
        self.column_0_layout.addWidget(self.hp_edit)

        self.attack_tabs = QtWidgets.QTabWidget(self)
        self.attack_tabs.setObjectName("attack_tabs")
        self.column_1_layout.addWidget(self.attack_tabs)

        self.attack_1_tab = AttackTab(self.form.stats.attack_1, self)
        self.attack_tabs.addTab(
            self.attack_1_tab, self.locale_manager.search_key("attack_1")
        )

        self.attack_2_tab = AttackTab(self.form.stats.attack_2, self)
        self.attack_tabs.addTab(
            self.attack_2_tab, self.locale_manager.search_key("attack_2")
        )

        self.attack_3_tab = AttackTab(self.form.stats.attack_3, self)
        self.attack_tabs.addTab(
            self.attack_3_tab, self.locale_manager.search_key("attack_3")
        )

        self.range_edit = SpinBoxEdit(
            self.locale_manager.search_key("range"),
            self.form.stats.range.raw,
            self,
        )
        self.column_0_layout.addWidget(self.range_edit)

        self.column_0_layout.addStretch(1)
        self.column_1_layout.addStretch(1)
        self._layout.addStretch(1)

    def save(self):
        self.form.stats.hp = self.hp_edit.value_int()
        self.form.stats.range.raw = self.range_edit.value_int()
        self.attack_1_tab.save()
        self.attack_2_tab.save()
        self.attack_3_tab.save()


class AttackTab(QtWidgets.QWidget):
    def __init__(
        self,
        attack: game_data.cat_base.unit.Attack,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(AttackTab, self).__init__(parent)
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.attack = attack
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("layout")

        self._damage_edit = SpinBoxEdit(
            self.locale_manager.search_key("damage"),
            self.attack.damage,
            self,
        )

        self._layout.addWidget(self._damage_edit)

        self._foreswing_edit = SpinBoxEdit(
            self.locale_manager.search_key("foreswing"),
            self.attack.foreswing.frames,
            self,
            show_seconds=True,
        )

        self._layout.addWidget(self._foreswing_edit)

        self._use_ability_box = QtWidgets.QCheckBox(self)
        self._use_ability_box.setObjectName("use_ability_box")
        self._use_ability_box.setText(
            self.locale_manager.search_key("use_ability"),
        )
        self._use_ability_box.setChecked(self.attack.use_ability)
        self._layout.addWidget(self._use_ability_box)

        self.long_distance_group = QtWidgets.QGroupBox(self)
        self.long_distance_group.setObjectName("long_distance_group")
        self.long_distance_group_layout = QtWidgets.QHBoxLayout(
            self.long_distance_group
        )
        self.long_distance_group_layout.setObjectName("long_distance_group_layout")
        self._layout.addWidget(self.long_distance_group)
        self.long_distance_line_edit = QtWidgets.QLineEdit(self.long_distance_group)
        self.long_distance_line_edit.setObjectName("long_distance_line_edit")
        self.long_distance_line_edit.setReadOnly(True)
        self.long_distance_line_edit.setText(
            self.locale_manager.search_key("long_distance"),
        )
        self.long_distance_group_layout.addWidget(self.long_distance_line_edit)

        self.long_distance_group_layout.addStretch(1)

        self._long_distance_start_edit = SpinBoxEdit(
            "",
            self.attack.long_distance_start.raw,
            self,
        )

        self.long_distance_group_layout.addWidget(self._long_distance_start_edit)

        self.long_distance_dash = QtWidgets.QLabel(self.long_distance_group)
        self.long_distance_dash.setObjectName("long_distance_dash")
        self.long_distance_dash.setText("-")
        self.long_distance_group_layout.addWidget(self.long_distance_dash)

        self._long_distance_end_edit = SpinBoxEdit(
            "",
            self.attack.long_distance_range.raw + self.attack.long_distance_start.raw,
            self,
        )

        self.long_distance_group_layout.addWidget(self._long_distance_end_edit)

    def save(self):
        self.attack.damage = self._damage_edit.value_int()
        self.attack.foreswing.frames = self._foreswing_edit.value_int()
        self.attack.use_ability = self._use_ability_box.isChecked()
        self.attack.long_distance_start.raw = self._long_distance_start_edit.value_int()
        self.attack.long_distance_range.raw = (
            self._long_distance_end_edit.value_int()
            - self._long_distance_start_edit.value_int()
        )


class SpinBoxEdit(QtWidgets.QWidget):
    def __init__(
        self,
        name: str,
        value: int,
        parent: Optional[QtWidgets.QWidget] = None,
        min: int = -2147483648,
        max: int = 2147483647,
        show_seconds: bool = False,
    ):
        super(SpinBoxEdit, self).__init__(parent)
        self._layout = QtWidgets.QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.setObjectName("layout")

        if name:
            self.line_edit = QtWidgets.QLineEdit(self)
            self.line_edit.setObjectName("line_edit")
            self.line_edit.setReadOnly(True)
            self.line_edit.setText(name)
            self._layout.addWidget(self.line_edit)
            self._layout.addStretch(1)

        self._spin_box = QtWidgets.QSpinBox(self)
        self._spin_box.setObjectName("spin_box")
        self._spin_box.setRange(min, max)

        self._spin_box.setValue(value)

        self._layout.addWidget(self._spin_box)

        self.raw_value = value

        self._spin_box.valueChanged.connect(self._on_spin_box_value_changed)
        self.show_seconds = show_seconds
        if show_seconds:
            self.locale_manager = locale_handler.LocalManager.from_config()
            self.seconds_text_edit = QtWidgets.QLineEdit(self)
            self.seconds_text_edit.setObjectName("seconds_text_edit")
            self.seconds_text_edit.setReadOnly(True)
            self._layout.addWidget(self.seconds_text_edit)
            self._on_spin_box_value_changed(value)

    def _on_spin_box_value_changed(self, value: int):
        self.raw_value = value
        if self.show_seconds:
            val = game_data.cat_base.unit.Frames(value).seconds_float
            self.seconds_text_edit.setText(
                f"{val:.2f} {self.locale_manager.search_key('seconds')}"
            )

    def value_int(self) -> int:
        return self.raw_value
