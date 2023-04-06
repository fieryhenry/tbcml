import enum
from typing import Any
from bcml.core.game_data import pack
from bcml.core import io


class DropType(enum.Enum):
    ITEM_PACK = 0
    GREAT_FORTUNE = 1


class DropItem:
    def __init__(self, item_id: int, probability: int):
        self.item_id = item_id
        self.probability = probability

    def get_percentage(self) -> float:
        return self.probability / 100

    def serialize(self) -> dict[str, int]:
        return {
            "item_id": self.item_id,
            "probability": self.probability,
        }

    @staticmethod
    def deserialize(data: dict[str, int]) -> "DropItem":
        return DropItem(data["item_id"], data["probability"])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DropItem):
            return False
        return self.item_id == other.item_id and self.probability == other.probability

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class ItemPack:
    def __init__(
        self, type: DropType, user_rank: int, unknown: int, items: dict[int, DropItem]
    ):
        self.type = type
        self.user_rank = user_rank
        self.unknown = unknown
        self.items = items

    def serialize(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "user_rank": self.user_rank,
            "unknown": self.unknown,
            "items": {k: v.serialize() for k, v in self.items.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ItemPack":
        return ItemPack(
            DropType(data["type"]),
            data["user_rank"],
            data["unknown"],
            {k: DropItem.deserialize(v) for k, v in data["items"].items()},
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ItemPack):
            return False
        return (
            self.type == other.type
            and self.user_rank == other.user_rank
            and self.unknown == other.unknown
            and self.items == other.items
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class ItemPacks:
    def __init__(self, packs: dict[int, ItemPack]):
        self.packs = packs

    @staticmethod
    def get_file_name() -> str:
        return "Adreward_table.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "ItemPacks":
        file = game_data.find_file(ItemPacks.get_file_name())
        if file is None:
            return ItemPacks.create_empty()
        csv = io.bc_csv.CSV(file.dec_data)
        packs: dict[int, ItemPack] = {}
        for i, line in enumerate(csv.lines[1:]):
            type = DropType(line[0].to_int())
            user_rank = line[1].to_int()
            unknown = line[2].to_int()
            items: dict[int, DropItem] = {}
            for j in range(3, len(line)):
                item_id = line[j].to_int()
                items[j - 3] = DropItem(item_id, 0)
            packs[i] = ItemPack(type, user_rank, unknown, items)
        return ItemPacks(packs)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(self.get_file_name())
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        remaining_item_packs = self.packs.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                pack = self.packs[i]
            except KeyError:
                continue
            line[0].set(pack.type.value)
            line[1].set(pack.user_rank)
            line[2].set(pack.unknown)
            for j in range(3, len(line)):
                try:
                    item = pack.items[j - 3]
                except KeyError:
                    continue
                line[j].set(item.item_id)
            csv.set_line(i + 1, line)
            del remaining_item_packs[i]

        for i, pack in remaining_item_packs.items():
            line = [pack.type.value, pack.user_rank, pack.unknown]
            for j in range(3, len(line)):
                try:
                    item = pack.items[j - 3]
                except KeyError:
                    continue
                line.append(item.item_id)
            csv.add_line(line)
        game_data.set_file(self.get_file_name(), csv.to_data())

    def serialize(self) -> dict[str, Any]:
        return {
            "packs": {k: v.serialize() for k, v in self.packs.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ItemPacks":
        return ItemPacks({k: ItemPack.deserialize(v) for k, v in data["packs"].items()})

    @staticmethod
    def get_zip_folder() -> "io.path.Path":
        return io.path.Path("gamototo").add("ototo")

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        return ItemPacks.get_zip_folder().add("item_packs.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_object(self.serialize())
        zip.add_file(self.get_zip_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "ItemPacks":
        file = zip.get_file(ItemPacks.get_zip_json_file_path())
        if file is None:
            return ItemPacks.create_empty()
        json = io.json_file.JsonFile.from_data(file)
        return ItemPacks.deserialize(json.json)

    @staticmethod
    def create_empty() -> "ItemPacks":
        return ItemPacks({})

    def set_item_pack(self, pack: ItemPack):
        self.packs[pack.user_rank] = pack

    def import_item_packs(self, item_packs: "ItemPacks", game_data: "pack.GamePacks"):
        """_summary_

        Args:
            item_packs (ItemPacks): _description_
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_item_packs = ItemPacks.from_game_data(game_data)
        all_keys = set(self.packs.keys())
        all_keys.update(item_packs.packs.keys())
        all_keys.update(gd_item_packs.packs.keys())
        for rank in all_keys:
            other_pack = item_packs.packs.get(rank)
            gd_pack = gd_item_packs.packs.get(rank)
            if other_pack is None:
                continue
            if gd_pack is not None:
                if other_pack != gd_pack:
                    self.packs[rank] = other_pack
            else:
                self.packs[rank] = other_pack
