from typing import Optional
from PyQt5 import QtWidgets, QtCore, QtGui
from bcml.core import mods, game_data
from bcml.ui import ui_thread, gatya_item


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
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setObjectName("item_shop_layout")
        self.setLayout(layout)

        self._item_shop_table = QtWidgets.QTableWidget(self)
        self._item_shop_table.setObjectName("item_shop_table")
        self._item_shop_table.setColumnCount(5)
        self._item_shop_table.setHorizontalHeaderLabels(
            [
                self.tr("Item ID"),
                self.tr("Item Name"),
                self.tr("Price"),
                self.tr("Amount"),
                self.tr("Image"),
            ]
        )
        self._item_shop_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self._item_shop_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        layout.addWidget(self._item_shop_table)
        self.setup_data()
        self.fill_table()
        self._thread = ui_thread.ThreadWorker.run_in_thread_on_finished(
            self.setup_data, self.fill_table
        )

    def setup_data(self):
        item_shop = game_data.cat_base.item_shop.ItemShop.from_game_data(
            self.game_packs
        )
        gatya_items = game_data.cat_base.gatya_item.GatyaItems.from_game_data(
            self.game_packs
        )
        if item_shop is None or gatya_items is None:
            raise RuntimeError("Failed to load item shop data")
        self.item_shop = item_shop
        self.gatya_items = gatya_items

    def fill_table(self):
        self._item_shop_table.setRowCount(len(self.item_shop.items))
        for item_index, shop_item in self.item_shop.items.items():
            amount = QtWidgets.QTableWidgetItem(str(shop_item.count))
            amount.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled  # type: ignore
                | QtCore.Qt.ItemFlag.ItemIsSelectable
                | QtCore.Qt.ItemFlag.ItemIsEditable
            )
            price = QtWidgets.QTableWidgetItem(str(shop_item.price))
            price.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled  # type: ignore
                | QtCore.Qt.ItemFlag.ItemIsSelectable
                | QtCore.Qt.ItemFlag.ItemIsEditable
            )
            item = self.gatya_items.get_item(shop_item.gatya_item_id)
            if item is None:
                continue
            item_id_o = QtWidgets.QTableWidgetItem(str(item.id))
            item_id_o.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled  # type: ignore
                | QtCore.Qt.ItemFlag.ItemIsSelectable
            )
            name_o = QtWidgets.QTableWidgetItem(item.gatya_item_name_item.name)
            name_o.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled  # type: ignore
                | QtCore.Qt.ItemFlag.ItemIsSelectable
            )

            image_o = QtWidgets.QTableWidgetItem()
            image_o.setFlags(
                QtCore.Qt.ItemFlag.ItemIsEnabled  # type: ignore
                | QtCore.Qt.ItemFlag.ItemIsSelectable
            )
            img = QtGui.QImage()
            image = shop_item.cut.get_image(self.item_shop.imgcut.image)
            img.loadFromData(image.to_data().to_bytes())
            pixmap = QtGui.QPixmap.fromImage(img)
            image_o.setIcon(QtGui.QIcon(pixmap))

            self._item_shop_table.setItem(item_index, 0, item_id_o)
            self._item_shop_table.setItem(item_index, 1, name_o)
            self._item_shop_table.setItem(item_index, 2, price)
            self._item_shop_table.setItem(item_index, 3, amount)
            self._item_shop_table.setItem(item_index, 4, image_o)

        self._item_shop_table.setIconSize(QtCore.QSize(100, 100))

        self._item_shop_table.itemChanged.connect(self.item_changed)  # type: ignore
        self._item_shop_table.doubleClicked.connect(self.item_selected)  # type: ignore

    def get_selected_item(self) -> Optional[game_data.cat_base.gatya_item.GatyaItem]:
        row = self._item_shop_table.currentRow()
        if row == -1:
            return None
        item_id = int(self._item_shop_table.item(row, 0).text())
        return self.gatya_items.get_item(item_id)

    def item_selected(self):
        selected_column = self._item_shop_table.currentColumn()
        if selected_column != 0:
            return
        gt_item = self.get_selected_item()
        if gt_item is None:
            return
        self.gatya_item_selector = gatya_item.GatyaItemSelector(
            gt_item, self.gatya_items, self.gitem_selected
        )
        self.gatya_item_selector.show()

    def item_changed(self, item: QtWidgets.QTableWidgetItem):
        row = item.row()
        column = item.column()
        if column == 0:
            return
        gitem = self.item_shop.get_item(row)
        if gitem is None:
            return
        if column == 2:
            gitem.price = int(item.text())
        elif column == 3:
            gitem.count = int(item.text())

    def gitem_selected(self, item_id: int):
        item = self.gatya_items.get_item(item_id)
        if item is None:
            return
        row = self._item_shop_table.currentRow()
        if row == -1:
            return
        self._item_shop_table.item(row, 0).setText(str(item.id))
        self._item_shop_table.item(row, 1).setText(item.gatya_item_name_item.name)

        item_s = self.item_shop.get_item(row)
        if item_s is None:
            return
        item_s.gatya_item_id = item.id

    def save(self):
        self.mod.cat_base.item_shop = self.item_shop
