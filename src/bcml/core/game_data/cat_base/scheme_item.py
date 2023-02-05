import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


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

    def serialize(self) -> dict[str, Any]:
        return {
            "drop_category": self.drop_category.value,
            "id": self.id,
            "value": self.value,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Item":
        return Item(
            DropCategory(data["drop_category"]),
            data["id"],
            data["value"],
        )


class SchemeItem:
    def __init__(self, id: int, type: SchemeType, items: list[Item]):
        self.id = id
        self.type = type
        self.items = items

    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "items": [i.serialize() for i in self.items],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "SchemeItem":
        return SchemeItem(
            data["id"],
            SchemeType(data["type"]),
            [Item.deserialize(i) for i in data["items"]],
        )


class SchemeItems:
    def __init__(self, items: dict[int, SchemeItem]):
        self.items = items

    def serialize(self) -> dict[str, Any]:
        return {
            "items": {str(k): v.serialize() for k, v in self.items.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "SchemeItems":
        return SchemeItems(
            {int(k): SchemeItem.deserialize(v) for k, v in data["items"].items()},
        )

    @staticmethod
    def get_file_name():
        return "schemeItemData.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "SchemeItems":
        tsv_data = game_data.find_file(SchemeItems.get_file_name())
        if tsv_data is None:
            return SchemeItems.create_empty()
        items: dict[int, SchemeItem] = {}
        csv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        for line in csv.lines[1:]:
            id = line[0].to_int()
            type = SchemeType(line[1].to_int())
            items[id] = SchemeItem(id, type, [])
            for i in range(2, len(line), 3):
                category = DropCategory(line[i].to_int())
                items[id].items.append(
                    Item(category, line[i + 1].to_int(), line[i + 2].to_int())
                )
        return SchemeItems(items)

    def to_game_data(self, game_data: "pack.GamePacks"):
        tsv_data = game_data.find_file(SchemeItems.get_file_name())
        if tsv_data is None:
            return
        csv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        remaining = self.items.copy()
        for i, line in enumerate(csv.lines[1:]):
            item = self.items.get(line[0].to_int())
            if item is None:
                continue

            line[1].set(item.type.value)
            for item_index, it in enumerate(item.items):
                line_data: list[Any] = []
                line_data.append(it.drop_category.value)
                line_data.append(it.id)
                line_data.append(it.value)
                try:
                    line[item_index * 3 + 2] = line_data[0]
                    line[item_index * 3 + 3] = line_data[1]
                    line[item_index * 3 + 4] = line_data[2]
                except IndexError:
                    line.extend(line_data)

            csv.set_line(i + 1, line)
            del remaining[item.id]

        for item in remaining.values():
            line: list[Any] = []
            line.append(item.id)
            line.append(item.type.value)
            for item_index, item in enumerate(item.items):
                line.append(item.drop_category.value)
                line.append(item.id)
                line.append(item.value)
            csv.lines.append(line)

        game_data.set_file(SchemeItems.get_file_name(), csv.to_data())

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("catbase").add("scheme_items.json")

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip_file.add_file(SchemeItems.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "SchemeItems":
        json_data = zip.get_file(SchemeItems.get_json_file_path())
        if json_data is None:
            return SchemeItems.create_empty()
        json = io.json_file.JsonFile.from_data(json_data)
        return SchemeItems.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "SchemeItems":
        return SchemeItems({})

    def get_item(self, id: int) -> Optional[SchemeItem]:
        return self.items.get(id)

    def set_item(self, item: SchemeItem, id: int):
        item.id = id
        self.items[item.id] = item

    def import_scheme_items(self, other: "SchemeItems"):
        self.items.update(other.items)
