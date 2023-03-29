import enum
from typing import Optional

from PyQt5 import QtCore, QtGui, QtWidgets

from bcml.core import game_data, io, locale_handler, mods
from bcml.ui.editor import gatya_item, localizable
from bcml.ui.utils import ui_dialog, ui_file_dialog, ui_thread


class Rows(enum.Enum):
    ITEM_ID = 0
    ITEM_NAME = 1
    PRICE = 2
    AMOUNT = 3
    EFFECTIVE_AMOUNT = 4
    DRAW_ITEM_AMOUNT = 5
    ITEM_CATEGORY = 6
    IMAGE = 7


class ShopEditor(QtWidgets.QWidget):
    def __init__(
        self,
        mod: mods.bc_mod.Mod,
        game_packs: game_data.pack.GamePacks,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ShopEditor, self).__init__(parent)
        self.mod = mod
        self.game_packs = game_packs
        self.setup = False

    def setup_ui(self):
        if self.setup:
            return
        self.setup = True
        self.locale_manager = locale_handler.LocalManager.from_config()
        layout = QtWidgets.QVBoxLayout(self)
        layout.setObjectName("item_shop_layout")
        self.setLayout(layout)

        self._item_shop_table = QtWidgets.QTableWidget(self)
        self._item_shop_table.setObjectName("item_shop_table")
        self._item_shop_table.setColumnCount(8)
        self._item_shop_table.setHorizontalHeaderLabels(
            [
                self.locale_manager.search_key("item_id"),
                self.locale_manager.search_key("item_name"),
                self.locale_manager.search_key("item_price"),
                self.locale_manager.search_key("item_amount"),
                self.locale_manager.search_key("item_effective_amount"),
                self.locale_manager.search_key("draw_item_amount"),
                self.locale_manager.search_key("shop_item_category"),
                self.locale_manager.search_key("item_image"),
            ]
        )
        self._item_shop_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        self._item_shop_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        # make the last column stretch to fill the table
        self._item_shop_table.horizontalHeader().setStretchLastSection(True)

        item_id_header = self._item_shop_table.horizontalHeaderItem(Rows.ITEM_ID.value)
        item_id_header.setToolTip(self.locale_manager.search_key("shop_item_id_tip"))

        price_header = self._item_shop_table.horizontalHeaderItem(Rows.PRICE.value)
        price_header.setToolTip(self.locale_manager.search_key("item_price_tip"))
        amount_header = self._item_shop_table.horizontalHeaderItem(Rows.AMOUNT.value)
        amount_header.setToolTip(self.locale_manager.search_key("item_amount_tip"))

        effective_amount_header = self._item_shop_table.horizontalHeaderItem(
            Rows.EFFECTIVE_AMOUNT.value
        )
        effective_amount_header.setToolTip(
            self.locale_manager.search_key("item_effective_amount_tip")
        )

        image_header = self._item_shop_table.horizontalHeaderItem(Rows.IMAGE.value)
        image_header.setToolTip(self.locale_manager.search_key("item_image_tip"))

        display_current_amount_header = self._item_shop_table.horizontalHeaderItem(
            Rows.DRAW_ITEM_AMOUNT.value
        )
        display_current_amount_header.setToolTip(
            self.locale_manager.search_key("draw_item_amount_tip")
        )

        item_category_header = self._item_shop_table.horizontalHeaderItem(
            Rows.ITEM_CATEGORY.value
        )
        item_category_header.setToolTip(
            self.locale_manager.search_key("shop_item_category_tip")
        )

        layout.addWidget(self._item_shop_table)

        self.add_row_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("add_shop_item"), self
        )
        self.add_row_button.clicked.connect(self.add_row)  # type: ignore
        layout.addWidget(self.add_row_button)

        self.reset_button = QtWidgets.QPushButton(
            self.locale_manager.search_key("reset_to_original"), self
        )
        self.reset_button.clicked.connect(self.reset)  # type: ignore
        layout.addWidget(self.reset_button)

        self._item_shop_table.setContextMenuPolicy(
            QtCore.Qt.ContextMenuPolicy.CustomContextMenu
        )
        self._item_shop_table.customContextMenuRequested.connect(self.show_context_menu)  # type: ignore

        self._item_shop_table.setDragEnabled(True)
        self._item_shop_table.setDragDropMode(
            QtWidgets.QAbstractItemView.DragDropMode.InternalMove
        )

        # disallow selection of multiple rows
        self._item_shop_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._item_shop_table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )

        self._item_shop_table.dropEvent = self.dropEvent

        self._item_shop_table.itemChanged.connect(self.item_changed)  # type: ignore
        self._item_shop_table.doubleClicked.connect(self.item_selected)  # type: ignore

        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.setup_data, self.fill_table
        )

    def dropEvent(self, event: QtGui.QDropEvent) -> None:  # type: ignore
        source = event.source()
        if source == self._item_shop_table:
            dest_row = self._item_shop_table.rowAt(event.pos().y())
            source_row = self._item_shop_table.currentRow()
            if dest_row == -1:
                return
            if source_row == -1:
                return
            if dest_row == source_row:
                return
            item = self.item_shop.get_item(source_row)
            if item is None:
                return
            back_wards = dest_row < source_row
            if back_wards:
                self.item_shop.insert_item(dest_row, item)
                self.item_shop.remove_item(source_row + 1)
            else:
                self.item_shop.insert_item(dest_row + 1, item)
                self.item_shop.remove_item(source_row)

            self.clear_table()
            self.fill_table()
            self._item_shop_table.selectRow(dest_row)
        event.ignore()

    def clear_table(self):
        self._item_shop_table.clearContents()
        self._item_shop_table.setRowCount(0)

    def show_context_menu(self, pos: QtCore.QPoint):
        menu = QtWidgets.QMenu()
        column = self._item_shop_table.columnAt(pos.x())
        replace_image_action = None

        if column == Rows.IMAGE.value:
            replace_image_action = menu.addAction(
                self.locale_manager.search_key("replace_image")
            )
        remove_action = menu.addAction(
            self.locale_manager.search_key("remove_shop_item")
        )
        action = menu.exec_(self._item_shop_table.mapToGlobal(pos))  #
        if column == Rows.IMAGE.value and action == replace_image_action:
            self.replace_image()
        if action == remove_action:
            self.remove_row()

    def add_row(self):
        row = self._item_shop_table.rowCount()

        gaty_item = self.gatya_items.get_item(0)
        if gaty_item is None:
            return
        self.item_shop.add_item(
            game_data.cat_base.item_shop.Item(
                shop_id=row,
                gatya_item_id=0,
                count=0,
                price=0,
                draw_item_value=True,
                category_name="shop_category1",
                rect_id=0,
            )
        )
        self._item_shop_table.clearContents()
        self.fill_table()

    def remove_row(self):
        self.msg_box = ui_dialog.Dialog().yes_no_box(
            QtWidgets.QMessageBox.Icon.Warning,
            self.locale_manager.search_key("remove_shop_item"),
            self.locale_manager.search_key("remove_shop_item_confirm"),
            self.locale_manager.search_key("remove_shop_item_confirm_title"),
            QtWidgets.QMessageBox.StandardButton.No,
            self.remove_confirm,
        )

    def remove_confirm(self):
        row = self._item_shop_table.currentRow()
        if row == -1:
            return
        self.item_shop.remove_item(row)
        self._item_shop_table.clearContents()
        self.fill_table()

    def replace_image(self):
        default_location = io.apk.Apk.get_default_apk_folder()
        file = ui_file_dialog.FileDialog(self).select_file(
            self.locale_manager.search_key("image_select_title"),
            default_location.to_str(),
            self.locale_manager.search_key("image_select_filter"),
        )
        if not file:
            return
        row = self._item_shop_table.currentRow()
        if row == -1:
            return
        item = self.item_shop.get_item(row)
        if item is None:
            return
        path = io.path.Path(file)
        img = io.bc_image.BCImage(path.read())
        self.fill_table()

    def save(self):
        if not self.setup:
            return
        self.mod.cat_base.item_shop = self.item_shop

    def setup_data(self):
        item_shop = game_data.cat_base.item_shop.ItemShop.from_game_data(
            self.game_packs
        )
        gatya_items = game_data.cat_base.gatya_item.GatyaItems.from_game_data(
            self.game_packs
        )
        self.item_shop = item_shop
        self.gatya_items = gatya_items
        self.locals = game_data.pack.Localizable.from_game_data(self.game_packs)

        self.item_shop.import_item_shop(self.mod.cat_base.item_shop, self.game_packs)
        self.gatya_items.import_items(self.mod.cat_base.gatya_items, self.game_packs)
        self.locals.import_localizable(self.mod.localizable, self.game_packs)
        self.item_shop.tex.split_cuts()

    def fill_table(self):
        self._item_shop_table.clearContents()
        self._item_shop_table.setRowCount(len(self.item_shop.items))
        for item_index, shop_item in self.item_shop.items.items():
            amount = QtWidgets.QTableWidgetItem(str(shop_item.count))
            price = QtWidgets.QTableWidgetItem(str(shop_item.price))
            item = self.gatya_items.get_item(shop_item.gatya_item_id)
            if item is None:
                continue
            item_id_o = QtWidgets.QTableWidgetItem(str(item.id))
            item_id_o.setFlags(item_id_o.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)  # type: ignore
            name_o = QtWidgets.QTableWidgetItem(item.gatya_item_name_item.name)
            name_o.setFlags(name_o.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)  # type: ignore

            name_o.setToolTip(item.gatya_item_name_item.get_trimmed_description())

            image_o = QtWidgets.QTableWidgetItem()
            image_o.setFlags(image_o.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)  # type: ignore
            img = QtGui.QImage()
            image = self.item_shop.tex.get_image(shop_item.rect_id)
            if image is None:
                continue
            img.loadFromData(image.to_data().to_bytes())
            pixmap = QtGui.QPixmap.fromImage(img)
            image_o.setIcon(QtGui.QIcon(pixmap))

            quantity = item.gatya_item_buy_item.quantity
            effective_amount = shop_item.count * quantity
            effective_amount_o = QtWidgets.QTableWidgetItem(str(effective_amount))
            effective_amount_o.setFlags(
                effective_amount_o.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable  # type: ignore
            )

            display_current_amount = QtWidgets.QTableWidgetItem()
            display_current_amount.setCheckState(
                QtCore.Qt.CheckState.Checked
                if shop_item.draw_item_value
                else QtCore.Qt.CheckState.Unchecked
            )
            display_current_amount.setFlags(
                display_current_amount.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable  # type: ignore
            )

            item_category_str = self.locals.get(shop_item.category_name)
            if item_category_str is None:
                item_category_str = (
                    shop_item.category_name
                    + f" {self.locale_manager.search_key('localize_fail')}"
                )

            item_category = QtWidgets.QTableWidgetItem(item_category_str)
            item_category.setFlags(
                item_category.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable  # type: ignore
            )
            item_category.setToolTip(shop_item.category_name)

            self._item_shop_table.setItem(item_index, Rows.ITEM_ID.value, item_id_o)
            self._item_shop_table.setItem(item_index, Rows.ITEM_NAME.value, name_o)
            self._item_shop_table.setItem(item_index, Rows.PRICE.value, price)
            self._item_shop_table.setItem(item_index, Rows.AMOUNT.value, amount)
            self._item_shop_table.setItem(
                item_index, Rows.EFFECTIVE_AMOUNT.value, effective_amount_o
            )
            self._item_shop_table.setItem(item_index, Rows.IMAGE.value, image_o)
            self._item_shop_table.setItem(
                item_index, Rows.DRAW_ITEM_AMOUNT.value, display_current_amount
            )
            self._item_shop_table.setItem(
                item_index, Rows.ITEM_CATEGORY.value, item_category
            )

        self._item_shop_table.setIconSize(QtCore.QSize(128, 128))

    def get_selected_item(self) -> Optional[game_data.cat_base.gatya_item.GatyaItem]:
        row = self._item_shop_table.currentRow()
        if row == -1:
            return None
        item_id = int(self._item_shop_table.item(row, 0).text())
        return self.gatya_items.get_item(item_id)

    def item_selected(self):
        selected_column = self._item_shop_table.currentColumn()
        if selected_column == Rows.ITEM_ID.value:
            gt_item = self.get_selected_item()
            if gt_item is None:
                return
            self.gatya_item_selector = gatya_item.GatyaItemSelector(
                gt_item, self.gatya_items, self.gitem_selected
            )
            self.gatya_item_selector.show()

        elif selected_column == Rows.ITEM_CATEGORY.value:
            selected_row = self._item_shop_table.currentRow()
            if selected_row == -1:
                return
            item = self.item_shop.get_item(selected_row)
            if item is None:
                return
            self.local_selector = localizable.LocalizableSelector(
                item.category_name, self.locals, True, self.category_selected
            )
            self.local_selector.show()

    def item_changed(self, item: QtWidgets.QTableWidgetItem):
        row = item.row()
        column = item.column()
        if column == Rows.ITEM_ID.value:
            return
        gitem = self.item_shop.get_item(row)
        change_effective_amount = False
        if gitem is None:
            return
        if column == Rows.PRICE.value:
            gitem.price = int(item.text())
            change_effective_amount = True
        elif column == Rows.AMOUNT.value:
            gitem.count = int(item.text())
            change_effective_amount = True
        elif column == Rows.DRAW_ITEM_AMOUNT.value:
            gitem.draw_item_value = item.checkState() == QtCore.Qt.CheckState.Checked
        if change_effective_amount:
            gaty_item = self.gatya_items.get_item(gitem.gatya_item_id)
            if gaty_item is None:
                return

            quantity = gaty_item.gatya_item_buy_item.quantity
            effective_amount = gitem.count * quantity
            try:
                self._item_shop_table.item(row, Rows.EFFECTIVE_AMOUNT.value).setText(
                    str(effective_amount)
                )
            except AttributeError:
                pass

    def gitem_selected(self, item_id: int):
        item = self.gatya_items.get_item(item_id)
        if item is None:
            return
        row = self._item_shop_table.currentRow()
        if row == -1:
            return
        self._item_shop_table.item(row, Rows.ITEM_ID.value).setText(str(item.id))
        self._item_shop_table.item(row, Rows.ITEM_NAME.value).setText(
            item.gatya_item_name_item.name
        )
        self._item_shop_table.item(row, Rows.ITEM_NAME.value).setToolTip(
            item.gatya_item_name_item.get_trimmed_description()
        )
        quantity = item.gatya_item_buy_item.quantity
        effective_amount = (
            int(self._item_shop_table.item(row, Rows.AMOUNT.value).text()) * quantity
        )
        self._item_shop_table.item(row, Rows.EFFECTIVE_AMOUNT.value).setText(
            str(effective_amount)
        )

        item_s = self.item_shop.get_item(row)
        if item_s is None:
            return
        item_s.gatya_item_id = item.id

    def category_selected(self, category: str):
        row = self._item_shop_table.currentRow()
        if row == -1:
            return
        text = self.locals.get(category)
        if text is None:
            return
        self._item_shop_table.item(row, Rows.ITEM_CATEGORY.value).setText(text)
        item = self.item_shop.get_item(row)
        if item is None:
            return
        item.category_name = category

    def reset(self):
        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.setup_data, self.fill_table
        )
