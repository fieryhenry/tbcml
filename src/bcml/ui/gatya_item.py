from typing import Callable
from PyQt5 import QtWidgets, QtCore, QtGui
from bcml.core import game_data


class GatyaItemSelector(QtWidgets.QDialog):
    def __init__(
        self,
        current_item: game_data.cat_base.gatya_item.GatyaItem,
        gatya_items: game_data.cat_base.gatya_item.GatyaItems,
        on_select: Callable[[int], None],
    ):
        super(GatyaItemSelector, self).__init__()
        self.current_item = current_item
        self.gatya_items = gatya_items
        self.on_select = on_select
        self.setup_ui()

    def setup_ui(self):
        self.resize(600, 500)
        self.setWindowTitle("Item Selector")
        layout = QtWidgets.QVBoxLayout(self)
        layout.setObjectName("gatya_item_selector_layout")
        self.setLayout(layout)

        self._gatya_item_table = QtWidgets.QTableWidget(self)
        self._gatya_item_table.setObjectName("gatya_item_table")
        self._gatya_item_table.setColumnCount(3)
        self._gatya_item_table.setHorizontalHeaderLabels(
            [self.tr("Item ID"), self.tr("Item Name"), self.tr("Image")]
        )
        self._gatya_item_table.verticalHeader().setVisible(False)

        self._gatya_item_table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self._gatya_item_table.verticalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        layout.addWidget(self._gatya_item_table)

        self._gatya_item_table.horizontalHeader().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

        test_image = QtGui.QImage()
        test_image.loadFromData(self.current_item.image.to_data().to_bytes())
        pixmap = QtGui.QPixmap.fromImage(test_image)
        pixmap = pixmap.scaledToHeight(64)
        self._gatya_item_table.setIconSize(pixmap.size())

        self._gatya_item_table.setRowCount(len(self.gatya_items.items))
        for i, (item_id, item) in enumerate(self.gatya_items.items.items()):
            item_id = QtWidgets.QTableWidgetItem(str(item.id))
            item_id.setFlags(QtCore.Qt.ItemFlag.ItemIsEnabled)

            self._gatya_item_table.setItem(i, 0, item_id)

            name = item.gatya_item_name_item.name
            if name == "＠":
                name = self.tr("Unknown")

            item_name = QtWidgets.QTableWidgetItem(name)
            item_name.setFlags(QtCore.Qt.ItemFlag.ItemIsEnabled)
            self._gatya_item_table.setItem(i, 1, item_name)

            item_image = QtWidgets.QTableWidgetItem()
            item_image.setFlags(QtCore.Qt.ItemFlag.ItemIsEnabled)
            img = QtGui.QImage()
            img.loadFromData(item.image.to_data().to_bytes())
            pixmap = QtGui.QPixmap.fromImage(img)
            item_image.setIcon(QtGui.QIcon(pixmap))
            self._gatya_item_table.setItem(i, 2, item_image)

            item_name.setToolTip(item.gatya_item_name_item.get_trimmed_description())

        self._gatya_item_table.itemDoubleClicked.connect(self._on_item_double_clicked)  # type: ignore

    def _on_item_double_clicked(self, item: QtWidgets.QTableWidgetItem):
        item_id = int(self._gatya_item_table.item(item.row(), 0).text())
        self.on_select(item_id)
        self.close()
