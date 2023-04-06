from typing import Callable, Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from bcml.core import game_data, locale_handler, mods
from bcml.ui import main
from bcml.ui.utils import ui_thread


class LocalizableSelector(QtWidgets.QDialog):
    def __init__(
        self,
        current_key: str,
        localizable: game_data.pack.Localizable,
        raw: bool,
        on_select: Callable[[str], None],
    ):
        super(LocalizableSelector, self).__init__()
        self.current_key = current_key
        self.localizable = localizable
        self.raw = raw
        self.localizable.sort()
        self.on_select = on_select
        self.locale_manager = locale_handler.LocalManager.from_config()
        self.setup_ui()

    def setup_ui(self):
        self.resize(600, 500)
        self.setWindowTitle(
            self.locale_manager.search_key("localizable_selector_title")
        )
        layout = QtWidgets.QVBoxLayout(self)
        layout.setObjectName("localizable_selector_layout")
        self.setLayout(layout)

        self.search_bar = QtWidgets.QLineEdit(self)
        self.search_bar.setObjectName("search_bar")
        self.search_bar.setPlaceholderText(
            self.locale_manager.search_key("search_placeholder")
        )
        layout.addWidget(self.search_bar)
        self.search_bar.textChanged.connect(self.on_search)  # type: ignore

        self._localizable_table = QtWidgets.QTableWidget(self)
        self._localizable_table.setObjectName("localizable_table")
        self._localizable_table.setColumnCount(2)
        self._localizable_table.setHorizontalHeaderLabels(
            [
                self.locale_manager.search_key("text_key"),
                self.locale_manager.search_key("rendered_text"),
            ]
        )
        self._localizable_table.verticalHeader().setVisible(False)

        self._localizable_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self._localizable_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        # resize the first column to fit the contents
        self._localizable_table.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        layout.addWidget(self._localizable_table)

        self._localizable_table.setRowCount(len(self.localizable.localizable))
        for i, (key, item) in enumerate(self.localizable.localizable.items()):
            keyo = QtWidgets.QTableWidgetItem(key)
            keyo.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsSelectable  # type: ignore
            )

            self._localizable_table.setItem(i, 0, keyo)

            text = item.value
            if self.raw:
                texto = QtWidgets.QTableWidgetItem(text)
                texto.setFlags(
                    QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsSelectable  # type: ignore
                )
                self._localizable_table.setItem(i, 1, texto)
            else:
                text_renderer = TextRenderBox(
                    text,
                    key,
                    False,
                    self.locale_manager,
                    None,
                    self.on_double_click,
                    self,
                )
                self._localizable_table.setCellWidget(i, 1, text_renderer)

        self._localizable_table.itemDoubleClicked.connect(self.on_item_double_clicked)  # type: ignore

        self._localizable_table.selectRow(
            list(self.localizable.localizable.keys()).index(self.current_key)
        )

    def on_item_double_clicked(self, item: QtWidgets.QTableWidgetItem):
        row = item.row()
        item = self._localizable_table.item(row, 0)
        self.on_select(item.text())
        self.close()

    def on_double_click(self, key: str):
        self.on_select(key)
        self.close()

    def on_search(self, text: str):
        total_rows = 0
        for i in range(self._localizable_table.rowCount()):
            if total_rows > 100:
                break
            self._localizable_table.setRowHidden(i, True)
            key = self._localizable_table.item(i, 0)
            if text.lower() in key.text().lower():
                self._localizable_table.setRowHidden(i, False)
                total_rows += 1


class TextComponent(QtWidgets.QLabel):
    def __init__(
        self,
        text: str,
        flash: bool,
        color: Optional[tuple[int, int, int]] = None,
        new_line: bool = False,
        backslash_n: bool = False,
    ):
        super(TextComponent, self).__init__()
        self.txt = text
        self.flash = flash
        self.color = color
        self.new_line = new_line
        self.backslash_n = backslash_n
        self.flash_setup = False
        if self.flash and self.color is not None:
            raise ValueError("Cannot flash and set color at the same time")

    def start_flash(self):
        if self.flash_setup or not self.flash:
            return
        self.frame_rate = 15  # the game runs at 30 fps and flashes every 2 frames, so 15 fps flashing every frame is equivalent and less taxing
        self.flash_timer = QtCore.QTimer(self)
        self.flash_timer.timeout.connect(self.on_flash)
        self.flash_timer.start(1000 // self.frame_rate)
        self.flash_count = 0
        self.flash_setup = True

    def stop_flash(self):
        if self.flash_setup:
            self.flash_timer.stop()
            self.flash_setup = False

    def setup_ui(self):
        self.setContentsMargins(0, 0, 0, 0)

        if self.color is not None:
            self.setStyleSheet(
                f"color: rgb({self.color[0]}, {self.color[1]}, {self.color[2]});"
            )
        else:
            self.setStyleSheet(
                "#flash_label_on { color: rgb(255, 255, 0); } #flash_label_off { color: rgb(255, 0, 255); }"
            )
        self.setText(self.txt.replace("\\n", "\n"))

    def on_flash(self):
        if self.flash_count % 2 == 0:
            self.setObjectName("flash_label_on")
        else:
            self.setObjectName("flash_label_off")
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()
        self.flash_count += 1

    def __str__(self) -> str:
        return f"TextComponent(text={self.txt}, flash={self.flash}, color={self.color}, new_line={self.new_line}, backslash_n={self.backslash_n})"

    def __repr__(self) -> str:
        return str(self)


class TextRenderBox(QtWidgets.QWidget):
    def __init__(
        self,
        text: str,
        key: str,
        allow_edit: bool,
        locale_manager: locale_handler.LocalManager,
        on_change: Optional[Callable[[str, str], None]] = None,
        on_double_click: Optional[Callable[[str], None]] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(TextRenderBox, self).__init__(parent)
        self.text = text
        self.key = key
        self.allow_edit = allow_edit
        self.on_change = on_change
        self.on_double_click = on_double_click
        self.locale_manager = locale_manager
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setObjectName("text_render_box_layout")
        self.setLayout(self._layout)
        self.setup_ui()

    def setup_ui(self):
        self.components = self.get_components()
        h_layout = QtWidgets.QHBoxLayout()
        h_layout.setSpacing(0)
        h_layout.setContentsMargins(0, 0, 0, 0)
        for component in self.components:
            component.setup_ui()
            if component.new_line:
                h_layout.addStretch()
                self._layout.addLayout(h_layout)
                h_layout = QtWidgets.QHBoxLayout()
                h_layout.setSpacing(0)
                h_layout.setContentsMargins(0, 0, 0, 0)
            if component.txt:
                h_layout.addWidget(component)
        h_layout.addStretch()
        self._layout.addLayout(h_layout)

        self._layout.setSpacing(0)

        self._layout.addStretch()

    def mouseDoubleClickEvent(self, a0: QtGui.QMouseEvent) -> None:
        if not self.allow_edit:
            if self.on_double_click is not None:
                self.on_double_click(self.key)
            return
        self.text_edit = QtWidgets.QTextEdit(self)
        self.text_edit.setPlainText(
            self.text.replace("\\n", "\n").replace("<br>", "\n")
        )

        self.text_edit.setWindowFlag(QtCore.Qt.WindowType.Window)
        self.text_edit.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)
        self.text_edit.setWindowTitle(self.locale_manager.search_key("edit_text"))
        self.text_edit.resize(400, 400)

        self.text_edit.show()

        self.text_edit.textChanged.connect(self.on_text_changed)
        self.text_edit.setWordWrapMode(QtGui.QTextOption.WrapMode.NoWrap)

    def on_text_changed(self):
        new_text = self.text_edit.toPlainText()
        if "\\n" in self.text:
            new_text = new_text.replace("\n", "\\n")
        else:
            new_text = new_text.replace("\n", "<br>")

        self.text = new_text
        if self.on_change is not None:
            self.on_change(new_text, self.key)
        main.clear_layout(self._layout)
        self.setup_ui()

    def get_components(self) -> list[TextComponent]:
        txt = self.text
        char_index = 0
        current_text = ""
        flashing = False
        new_line = False
        back_slash_n = False
        color: Optional[tuple[int, int, int]] = None
        components: list[TextComponent] = []
        iterations = 0
        txt += "<br>"
        while char_index < len(txt):
            iterations += 1
            if iterations > 5000:
                raise ValueError("Too many iters")
            char = txt[char_index]
            current_text += char
            char_index += 1
            if char == "<" or (char == "\\" and txt[char_index] == "n"):
                components.append(
                    TextComponent(
                        current_text[:-1],
                        flashing,
                        color,
                        new_line,
                        back_slash_n,
                    )
                )
                current_text = ""
                new_line = False
                back_slash_n = False
                if char == "<":
                    end_tag_index = txt.find(">", char_index)
                else:
                    end_tag_index = char_index + 1
                if end_tag_index == -1:
                    continue
                tag = txt[char_index:end_tag_index]
                if tag == "flash":
                    flashing = True
                elif tag == "/flash":
                    flashing = False
                elif tag == "br":
                    new_line = True
                elif tag.startswith("color="):
                    colors = tag.split("color=")[1].split(",")
                    try:
                        color = (int(colors[0]), int(colors[1]), int(colors[2]))
                    except ValueError:
                        pass
                elif tag == "/color":
                    color = None
                elif tag == "n":
                    back_slash_n = True
                    new_line = True
                    end_tag_index -= 1
                char_index = end_tag_index + 1
        return components

    def get_text(self) -> str:
        return self.text

    def start_flash(self):
        for component in self.components:
            component.start_flash()

    def stop_flash(self):
        for component in self.components:
            component.stop_flash()


class TextEditor(QtWidgets.QWidget):
    def __init__(
        self,
        mod: mods.bc_mod.Mod,
        game_packs: game_data.pack.GamePacks,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(TextEditor, self).__init__(parent)
        self.mod = mod
        self.game_packs = game_packs
        self.setup = False
        self.locale_manager = locale_handler.LocalManager.from_config()

    def setup_ui(self):
        if self.setup:
            return
        self.setup = True
        layout = QtWidgets.QVBoxLayout(self)
        layout.setObjectName("text_editor_layout")
        self._layout = layout
        self.setLayout(layout)
        self.setup_table()
        self.text_editor_table.itemDoubleClicked.connect(self.on_item_double_clicked)  # type: ignore
        self.text_editor_table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)  # type: ignore
        self.text_editor_table.customContextMenuRequested.connect(self.on_context_menu)  # type: ignore

        self.add_row_button = QtWidgets.QPushButton(self)
        self.add_row_button.setObjectName("add_row_button")
        self.add_row_button.setText(self.locale_manager.search_key("add_text_entry"))
        self.add_row_button.clicked.connect(self.on_add_row_clicked)  # type: ignore
        self._layout.addWidget(self.add_row_button)

        self.reset_button = QtWidgets.QPushButton(self)
        self.reset_button.setObjectName("reset_button")
        self.reset_button.setText(self.locale_manager.search_key("reset_to_original"))
        self.reset_button.clicked.connect(self.reset)  # type: ignore
        self._layout.addWidget(self.reset_button)

        self.create_search_box()

        # enable mouse tracking to get mouse move events
        self.setMouseTracking(True)
        self.text_editor_table.setMouseTracking(True)
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.tick)
        fps = 5
        self.text_editor_table.mouseMoveEvent = self.on_mouse_move  # type: ignore
        self.timer.start(1000 // fps)

    def on_context_menu(self, pos: QtCore.QPoint):
        menu = QtWidgets.QMenu()
        menu.addAction(
            self.locale_manager.search_key("remove_text_entry"),
            self.on_delete_row_clicked,
        )
        menu.exec_(self.text_editor_table.mapToGlobal(pos))

    def on_delete_row_clicked(self):
        row = self.text_editor_table.currentRow()
        key = self.text_editor_table.item(row, 0).text()
        self.localizable.remove(key)
        self.fill_table()

    def create_search_box(self):
        self.search_box = QtWidgets.QLineEdit(self)
        self.search_box.setPlaceholderText(
            self.locale_manager.search_key("search_placeholder")
        )
        self.search_box.textChanged.connect(self.search)  # type: ignore

        self._layout.insertWidget(0, self.search_box)

    def get_text_item(self, row: int) -> TextRenderBox:
        return self.text_editor_table.cellWidget(row, 1)

    def search(self, text: str):
        total_rows_visible = 0
        for i in range(self.text_editor_table.rowCount()):
            if total_rows_visible > 100 and text != "":
                break
            key = self.text_editor_table.item(i, 0).text().lower()
            value = self.get_text_item(i).text.lower()
            if text.lower() in key or text.lower() in value:
                self.text_editor_table.showRow(i)
                total_rows_visible += 1
            else:
                self.text_editor_table.hideRow(i)

    def setup_table(self):
        if hasattr(self, "text_editor_table"):
            self._layout.removeWidget(self.text_editor_table)
            self.text_editor_table.deleteLater()

        self.text_editor_table = QtWidgets.QTableWidget(self)
        self.text_editor_table.setObjectName("text_editor_table")
        self.text_editor_table.setColumnCount(2)
        self.text_editor_table.setHorizontalHeaderLabels(
            [
                self.locale_manager.search_key("text_key"),
                self.locale_manager.search_key("rendered_text"),
            ]
        )
        self.text_editor_table.verticalHeader().setVisible(False)

        self.text_editor_table.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self.text_editor_table.horizontalHeader().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.Stretch
        )

        self.text_editor_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        self._layout.insertWidget(1, self.text_editor_table)

        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.setup_data, self.fill_table
        )

    def setup_data(self):
        self.localizable = game_data.pack.Localizable.from_game_data(self.game_packs)
        self.localizable.import_localizable(self.mod.localizable, self.game_packs)

    def fill_table(self):
        self.localizable.sort()
        self.text_editor_table.clearContents()
        self.text_editor_table.setRowCount(len(self.localizable.localizable))
        for i, (key, item) in enumerate(self.localizable.localizable.items()):
            key_i = QtWidgets.QTableWidgetItem(key)
            key_i.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsSelectable  # type: ignore
            )

            self.text_editor_table.setItem(i, 0, key_i)

            rendered_text = TextRenderBox(
                item.value,
                key,
                True,
                self.locale_manager,
                self.on_item_changed,
                None,
                self,
            )
            self.text_editor_table.setCellWidget(i, 1, rendered_text)
        self.search(self.search_box.text())

    def on_item_changed(self, text: str, key: str):
        self.localizable.set(key, text)
        self.text_editor_table.resizeRowsToContents()

    def on_item_double_clicked(self, item: QtWidgets.QTableWidgetItem):
        row = item.row()
        column = item.column()
        if column == 0:
            self.orignal_key = item.text()
            self.text_edit = QtWidgets.QLineEdit(self)
            self.text_edit.setText(item.text())
            self.text_editor_table.setCellWidget(row, column, self.text_edit)
            self.text_edit.editingFinished.connect(
                lambda: self.on_text_edit_finished(row, column)
            )
            self.text_edit.setFocus()

    def on_text_edit_finished(self, row: int, column: int):
        key = self.text_edit.text()
        self.text_editor_table.removeCellWidget(row, column)
        self.text_editor_table.setItem(row, column, QtWidgets.QTableWidgetItem(key))
        self.localizable.rename(self.orignal_key, key)

    def reset(self):
        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.setup_data, self.fill_table
        )

    def on_add_row_clicked(self):
        search_text = self.search_box.text()
        row = self.text_editor_table.rowCount()
        key = search_text + str(row)
        self.localizable.set(key, "")
        self.fill_table()
        self.select_row_key(key)

    def select_row(self, row: int):
        self.text_editor_table.selectRow(row)

    def select_row_key(self, key: str):
        for i in range(self.text_editor_table.rowCount()):
            if self.text_editor_table.item(i, 0).text() == key:
                self.select_row(i)
                break

    def save(self):
        if self.setup:
            self.mod.localizable = self.localizable

    def get_current_rows(self) -> list[int]:
        return [
            i
            for i in range(self.text_editor_table.rowCount())
            if self.text_editor_table.isRowHidden(i) is False
        ]

    def get_row_by_key_current(self, key: str) -> int:
        current_rows = self.get_current_rows()
        for relative_index in range(len(current_rows)):
            row = current_rows[relative_index]
            if self.text_editor_table.item(row, 0).text() == key:
                return relative_index
        return -1

    def flash_around_rows(self, *rows_current: int):
        if sum(rows_current) == len(rows_current) * -1:
            return

        current_rows = self.get_current_rows()
        max_range = 20
        min_row = min(rows_current)
        max_row = max(rows_current)
        min_row = max(min_row - max_range, 0)
        max_row = min(max_row + max_range, len(current_rows) - 1)
        valid_rows: list[int] = []
        for i in range(min_row, max_row):
            element = self.get_text_item(current_rows[i])
            if isinstance(element, TextRenderBox):
                element.start_flash()
                valid_rows.append(current_rows[i])

        all_rows = range(self.text_editor_table.rowCount())
        for i in all_rows:
            if i in valid_rows:
                continue
            element = self.get_text_item(i)
            if isinstance(element, TextRenderBox):
                element.stop_flash()

    def tick(self):
        pos = self.text_editor_table.mapFromGlobal(QtGui.QCursor.pos())
        if not self.text_editor_table.rect().contains(pos):
            return
        row_mouse = self.text_editor_table.rowAt(pos.y())
        element_mouse = self.get_text_item(row_mouse)
        mouse_key = None
        if isinstance(element_mouse, TextRenderBox):
            mouse_key = element_mouse.key

        selected = self.text_editor_table.selectedIndexes()
        row_select = -1
        if selected:
            row_select = selected[0].row()
        element_select = self.get_text_item(row_select)
        select_key = None
        if isinstance(element_select, TextRenderBox):
            select_key = element_select.key

        mouse_index = -1

        if mouse_key is not None:
            mouse_index = self.get_row_by_key_current(mouse_key)

        select_index = -1

        if select_key is not None:
            select_index = self.get_row_by_key_current(select_key)

        self.flash_around_rows(mouse_index, select_index)

    def on_mouse_move(self, event: QtGui.QMouseEvent):
        self.tick()
