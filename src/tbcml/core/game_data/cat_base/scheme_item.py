import enum
from typing import Any, Optional
from tbcml import core


class SchemeType(enum.Enum):
    URL_SCHEME = 0
    BROWSER_EVENT = 1
    APP_INSTALL = 2


class DropCategory(enum.Enum):
    ITEM = 0
    CHARACTER = 1
    OTHER = 2


class Item:
    def __init__(self, drop_category: DropCategory, id: int, value: int):
        self.drop_category = drop_category
        self.id = id
        self.value = value

    def apply_dict(self, dict_data: dict[str, Any]):
        self.drop_category = DropCategory(
            dict_data.get("drop_category", self.drop_category.value)
        )
        self.id = dict_data.get("id", self.id)
        self.value = dict_data.get("value", self.value)

    @staticmethod
    def create_empty() -> "Item":
        return Item(DropCategory.ITEM, 0, 0)


class SchemeItem:
    def __init__(self, id: int, type: SchemeType, items: list[Item]):
        self.id = id
        self.type = type
        self.items = items

    def apply_dict(self, dict_data: dict[str, Any]):
        self.id = dict_data.get("id", self.id)
        self.type = SchemeType(dict_data.get("type", self.type.value))
        items = dict_data.get("items")
        if items is not None:
            current_items_dict = {i: i for i in range(len(self.items))}
            modded_items = core.ModEditDictHandler(items, current_items_dict).get_dict(
                convert_int=True
            )
            for item_id, modded_item in modded_items:
                try:
                    item = self.items[int(item_id)]
                except IndexError:
                    item = Item.create_empty()
                    self.items.append(item)
                item.apply_dict(modded_item)

    @staticmethod
    def create_empty(id: int) -> "SchemeItem":
        return SchemeItem(id, SchemeType.URL_SCHEME, [])


class SchemeItems(core.EditableClass):
    def __init__(self, items: dict[int, SchemeItem]):
        self.data = items
        super().__init__(items)

    @staticmethod
    def get_file_name():
        return "schemeItemData.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "SchemeItems":
        if game_data.scheme_items is not None:
            return game_data.scheme_items
        tsv_data = game_data.find_file(SchemeItems.get_file_name())
        if tsv_data is None:
            return SchemeItems.create_empty()
        items: dict[int, SchemeItem] = {}
        csv = core.CSV(tsv_data.dec_data, delimeter="\t")
        for line in csv.lines[1:]:
            id = int(line[0])
            type = SchemeType(int(line[1]))
            items[id] = SchemeItem(id, type, [])
            for i in range(2, len(line), 3):
                category = DropCategory(int(line[i]))
                items[id].items.append(
                    Item(category, int(line[i + 1]), int(line[i + 2]))
                )
        scheme_items = SchemeItems(items)
        game_data.scheme_items = scheme_items
        return scheme_items

    def to_game_data(self, game_data: "core.GamePacks"):
        tsv_data = game_data.find_file(SchemeItems.get_file_name())
        if tsv_data is None:
            return
        csv = core.CSV(tsv_data.dec_data, delimeter="\t")
        remaining = self.data.copy()
        for i, line in enumerate(csv.lines[1:]):
            item = self.data.get(int(line[0]))
            if item is None:
                continue

            line[1] = str(item.type.value)
            for item_index, it in enumerate(item.items):
                line_data: list[str] = []
                line_data.append(str(it.drop_category.value))
                line_data.append(str(it.id))
                line_data.append(str(it.value))
                try:
                    line[item_index * 3 + 2] = line_data[0]
                    line[item_index * 3 + 3] = line_data[1]
                    line[item_index * 3 + 4] = line_data[2]
                except IndexError:
                    line.extend(line_data)

            csv.lines[i + 1] = line
            del remaining[item.id]

        for item in remaining.values():
            line: list[str] = []
            line.append(str(item.id))
            line.append(str(item.type.value))
            for item_index, item in enumerate(item.items):
                line.append(str(item.drop_category.value))
                line.append(str(item.id))
                line.append(str(item.value))
            csv.lines.append(line)

        game_data.set_file(SchemeItems.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "SchemeItems":
        return SchemeItems({})

    def get_item(self, id: int) -> Optional[SchemeItem]:
        return self.data.get(id)

    def set_item(self, item: SchemeItem, id: int):
        item.id = id
        self.data[item.id] = item
