import enum
from typing import Any
from tbcml import core


class DropType(enum.Enum):
    ITEM_PACK = 0
    GREAT_FORTUNE = 1


class DropItem:
    def __init__(self, item_id: int, probability: int):
        self.item_id = item_id
        self.probability = probability

    def get_percentage(self) -> float:
        return self.probability / 100

    def apply_dict(self, dict_data: dict[str, Any]):
        self.item_id = dict_data.get("item_id", self.item_id)
        self.probability = dict_data.get("probability", self.probability)

    @staticmethod
    def create_empty(item_id: int) -> "DropItem":
        return DropItem(
            item_id,
            0,
        )


class ItemPack:
    def __init__(
        self, type: DropType, user_rank: int, unknown: int, items: dict[int, DropItem]
    ):
        self.type = type
        self.user_rank = user_rank
        self.unknown = unknown
        self.items = items

    def apply_dict(self, dict_data: dict[str, Any]):
        self.type = DropType(dict_data.get("type", self.type.value))
        self.user_rank = dict_data.get("user_rank", self.user_rank)
        self.unknown = dict_data.get("unknown", self.unknown)
        items = dict_data.get("items")
        if items is not None:
            current_items = self.items.copy()
            modded_items = core.ModEditDictHandler(items, current_items).get_dict(
                convert_int=True
            )
            for item_id, modded_item in modded_items:
                item = self.items.get(item_id)
                if item is None:
                    item = DropItem.create_empty(item_id)
                    self.items[item_id] = item
                item.apply_dict(modded_item)

    @staticmethod
    def create_empty() -> "ItemPack":
        return ItemPack(
            DropType.ITEM_PACK,
            0,
            0,
            {},
        )


class ItemPacks:
    def __init__(self, packs: dict[int, ItemPack]):
        self.packs = packs

    @staticmethod
    def get_file_name() -> str:
        return "Adreward_table.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "ItemPacks":
        file = game_data.find_file(ItemPacks.get_file_name())
        if file is None:
            return ItemPacks.create_empty()
        csv = core.CSV(file.dec_data)
        packs: dict[int, ItemPack] = {}
        for i, line in enumerate(csv.lines[1:]):
            type = DropType(int(line[0]))
            user_rank = int(line[1])
            unknown = int(line[2])
            items: dict[int, DropItem] = {}
            for j in range(3, len(line)):
                item_id = int(line[j])
                items[j - 3] = DropItem(item_id, 0)
            packs[i] = ItemPack(type, user_rank, unknown, items)
        return ItemPacks(packs)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(self.get_file_name())
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        remaining_item_packs = self.packs.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                pack = self.packs[i]
            except KeyError:
                continue
            line[0] = str(pack.type.value)
            line[1] = str(pack.user_rank)
            line[2] = str(pack.unknown)
            for j in range(3, len(line)):
                try:
                    item = pack.items[j - 3]
                except KeyError:
                    continue
                line[j] = str(item.item_id)
            csv.lines[i + 1] = line
            del remaining_item_packs[i]

        for i, pack in remaining_item_packs.items():
            line = [
                str(pack.type.value),
                str(pack.user_rank),
                str(pack.unknown),
            ]
            for j in range(3, len(line)):
                try:
                    item = pack.items[j - 3]
                except KeyError:
                    continue
                line.append(str(item.item_id))
            csv.lines.append(line)
        game_data.set_file(self.get_file_name(), csv.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        packs = dict_data.get("item_packs")
        if packs is not None:
            current_packs = self.packs.copy()
            modded_packs = core.ModEditDictHandler(packs, current_packs).get_dict(
                convert_int=True
            )
            for pack_id, modded_pack in modded_packs:
                pack = self.packs.get(pack_id)
                if pack is None:
                    pack = ItemPack.create_empty()
                    self.packs[pack_id] = pack
                pack.apply_dict(modded_pack)

    @staticmethod
    def create_empty() -> "ItemPacks":
        return ItemPacks({})

    def set_item_pack(self, pack: ItemPack):
        self.packs[pack.user_rank] = pack

    @staticmethod
    def apply_mod_to_game_data(mod: "core.Mod", game_data: "core.GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (core.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        item_packs_data = mod.mod_edits.get("item_packs")
        if item_packs_data is None:
            return
        item_packs = ItemPacks.from_game_data(game_data)
        item_packs.apply_dict(mod.mod_edits)
        item_packs.to_game_data(game_data)
