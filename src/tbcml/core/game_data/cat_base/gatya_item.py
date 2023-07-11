from typing import Any, Optional
from tbcml import core
import enum


class ItemBuyCategory(enum.Enum):
    NONE = 0
    EventTicket = 1
    Ability = 2
    BattleItem = 3
    Matatabi = 4
    CatsEye = 5
    Nekovitan = 6
    MaterialStone = 7
    TicketSet2 = 8
    EndlessItems = 9
    TicketSet3 = 10
    Medals = 11


class GatyaItemBuyItem:
    def __init__(
        self,
        item_id: int,
        rarity: Optional[int] = None,
        storage: Optional[bool] = None,
        sell_price: Optional[int] = None,
        stage_drop_item_id: Optional[int] = None,
        quantity: Optional[int] = None,
        server_id: Optional[int] = None,
        category: Optional[ItemBuyCategory] = None,
        index_in_category: Optional[int] = None,
        src_item_id: Optional[int] = None,
        main_menu_type: Optional[int] = None,
        gatya_ticket_id: Optional[int] = None,
        comment: Optional[str] = None,
    ):
        self.item_id = item_id
        self.rarity = rarity
        self.storage = storage
        self.sell_price = sell_price
        self.stage_drop_item_id = stage_drop_item_id
        self.quantity = quantity
        self.server_id = server_id
        self.category = category
        self.index_in_category = index_in_category
        self.src_item_id = src_item_id
        self.main_menu_type = main_menu_type
        self.gatya_ticket_id = gatya_ticket_id
        self.comment = comment

    def set_id(self, item_id: int) -> None:
        self.item_id = item_id

    def apply_dict(self, dict_data: dict[str, Any]):
        self.item_id = dict_data.get("item_id", self.item_id)
        self.rarity = dict_data.get("rarity", self.rarity)
        self.storage = dict_data.get("storage", self.storage)
        self.sell_price = dict_data.get("sell_price", self.sell_price)
        self.stage_drop_item_id = dict_data.get(
            "stage_drop_item_id", self.stage_drop_item_id
        )
        self.quantity = dict_data.get("quantity", self.quantity)
        self.server_id = dict_data.get("server_id", self.server_id)
        category = dict_data.get("category")
        if category is not None:
            self.category = ItemBuyCategory(category)
        self.index_in_category = dict_data.get(
            "index_in_category", self.index_in_category
        )
        self.src_item_id = dict_data.get("src_item_id", self.src_item_id)
        self.main_menu_type = dict_data.get("main_menu_type", self.main_menu_type)
        self.gatya_ticket_id = dict_data.get("gatya_ticket_id", self.gatya_ticket_id)
        self.comment = dict_data.get("comment", self.comment)

    @staticmethod
    def create_empty(item_id: int) -> "GatyaItemBuyItem":
        return GatyaItemBuyItem(
            item_id,
        )


class GatyaItemBuy:
    def __init__(
        self,
        gatya_item_buys: dict[int, GatyaItemBuyItem],
    ):
        self.gatya_item_buys = gatya_item_buys

    @staticmethod
    def get_file_name() -> str:
        return "Gatyaitembuy.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "GatyaItemBuy":
        csv_data = game_data.find_file(GatyaItemBuy.get_file_name())
        if csv_data is None:
            return GatyaItemBuy.create_empty()

        csv = core.CSV(csv_data.dec_data)
        gatya_item_buys: dict[int, GatyaItemBuyItem] = {}
        for i, line in enumerate(csv.lines[1:]):
            comment = ""
            if len(line) > 11:
                comment = line[11]
            gatya_item_buys[i] = GatyaItemBuyItem(
                i,
                int(line[0]),
                bool(int(line[1])),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
                ItemBuyCategory(int(line[6])),
                int(line[7]),
                int(line[8]),
                int(line[9]),
                int(line[10]),
                comment,
            )

        return GatyaItemBuy(gatya_item_buys)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        csv_data = game_data.find_file(GatyaItemBuy.get_file_name())
        if csv_data is None:
            return None

        csv = core.CSV(csv_data.dec_data)
        remaining_items = self.gatya_item_buys.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                item = self.gatya_item_buys[i]
            except KeyError:
                continue
            if item.rarity is not None:
                line[0] = str(item.rarity)
            if item.storage is not None:
                line[1] = str(int(item.storage))
            if item.sell_price is not None:
                line[2] = str(item.sell_price)
            if item.stage_drop_item_id is not None:
                line[3] = str(item.stage_drop_item_id)
            if item.quantity is not None:
                line[4] = str(item.quantity)
            if item.server_id is not None:
                line[5] = str(item.server_id)
            if item.category is not None:
                line[6] = str(item.category.value)
            if item.index_in_category is not None:
                line[7] = str(item.index_in_category)
            if item.src_item_id is not None:
                line[8] = str(item.src_item_id)
            if item.main_menu_type is not None:
                line[9] = str(item.main_menu_type)
            if item.gatya_ticket_id is not None:
                line[10] = str(item.gatya_ticket_id)
            if item.comment is not None:
                line[11] = item.comment
            remaining_items.pop(i)
            csv.lines[i + 1] = line

        for i, item in remaining_items.items():
            new_line: list[str] = [
                str(item.rarity or 0),
                str(int(item.storage or False)),
                str(item.sell_price or 0),
                str(item.stage_drop_item_id or 0),
                str(item.quantity or 0),
                str(item.server_id or 0),
                str(item.category.value) if item.category is not None else "0",
                str(item.index_in_category or 0),
                str(item.src_item_id or 0),
                str(item.main_menu_type or 0),
                str(item.gatya_ticket_id or 0),
                item.comment or "",
            ]
            csv.lines.append(new_line)

        game_data.set_file(GatyaItemBuy.get_file_name(), csv.to_data())

    def get_item(self, item_id: int) -> Optional[GatyaItemBuyItem]:
        return self.gatya_item_buys.get(item_id)

    def set_item(self, item_id: int, item: GatyaItemBuyItem) -> None:
        item.item_id = item_id
        self.gatya_item_buys[item_id] = item

    @staticmethod
    def create_empty() -> "GatyaItemBuy":
        return GatyaItemBuy({})

    def apply_dict(self, dict_data: dict[str, Any]):
        gatya_item_buys = dict_data.get("gatya_item_buys")
        if gatya_item_buys is not None:
            current_gatya_item_buys = self.gatya_item_buys
            modded_gatya_item_buys = core.ModEditDictHandler(
                gatya_item_buys, current_gatya_item_buys
            ).get_dict(convert_int=True)
            for item_id, modded_item in modded_gatya_item_buys.items():
                item = current_gatya_item_buys.get(item_id)
                if item is None:
                    item = GatyaItemBuyItem.create_empty(item_id)
                item.apply_dict(modded_item)
                self.set_item(item_id, item)


class GatyaItemNameItem:
    def __init__(self, id: int, name: str, description: list[str]):
        self.id = id
        self.name = name
        self.description = description

    def get_trimmed_description(self) -> str:
        desc = ""
        for line in self.description:
            if line == "＠":
                break
            desc += f"{line}\n"
        return desc.strip()

    def set_id(self, id: int) -> None:
        self.id = id

    def apply_dict(self, dict_data: dict[str, Any]):
        self.name = dict_data.get("name", self.name)
        self.description = dict_data.get("description", self.description)

    @staticmethod
    def create_empty(id: int) -> "GatyaItemNameItem":
        return GatyaItemNameItem(id, "", [])


class GatyaItemName:
    def __init__(self, gatya_item_names: dict[int, GatyaItemNameItem]):
        self.gatya_item_names = gatya_item_names

    @staticmethod
    def get_file_name() -> str:
        return "GatyaitemName.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "GatyaItemName":
        csv_data = game_data.find_file(GatyaItemName.get_file_name())
        if csv_data is None:
            return GatyaItemName.create_empty()

        csv = core.CSV(
            csv_data.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
        )
        gatya_item_names: dict[int, GatyaItemNameItem] = {}
        for i, line in enumerate(csv.lines):
            name = line[0]
            description = line[1:]
            gatya_item_names[i] = GatyaItemNameItem(i, name, description)

        return GatyaItemName(gatya_item_names)

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        csv_data = game_data.find_file(GatyaItemName.get_file_name())
        if csv_data is None:
            return None

        csv = core.CSV(
            csv_data.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
        )
        for item in self.gatya_item_names.values():
            line: list[str] = []
            line.append(item.name)
            line.extend(item.description)
            csv.lines[item.id] = line

        game_data.set_file(GatyaItemName.get_file_name(), csv.to_data())

    def get_item(self, id: int) -> Optional[GatyaItemNameItem]:
        return self.gatya_item_names.get(id)

    def set_item(self, id: int, item: GatyaItemNameItem) -> None:
        item.id = id
        self.gatya_item_names[id] = item

    @staticmethod
    def create_empty() -> "GatyaItemName":
        return GatyaItemName({})

    def apply_dict(self, dict_data: dict[str, Any]):
        gatya_item_names = dict_data.get("gatya_item_names")
        if gatya_item_names is not None:
            current_gatya_item_names = self.gatya_item_names
            modded_gatya_item_names = core.ModEditDictHandler(
                gatya_item_names, current_gatya_item_names
            ).get_dict(convert_int=True)
            for item_id, modded_item in modded_gatya_item_names.items():
                item = current_gatya_item_names.get(item_id)
                if item is None:
                    item = GatyaItemNameItem.create_empty(item_id)
                item.apply_dict(modded_item)
                self.set_item(item_id, item)


class GatyaItem:
    def __init__(
        self,
        id: int,
        gatya_item_buy_item: Optional[GatyaItemBuyItem] = None,
        gatya_item_name_item: Optional[GatyaItemNameItem] = None,
        image: Optional["core.BCImage"] = None,
        silhouette: Optional["core.BCImage"] = None,
    ):
        self.id = id
        self.gatya_item_buy_item = gatya_item_buy_item
        self.gatya_item_name_item = gatya_item_name_item
        self.image = image
        self.silhouette = silhouette

    @staticmethod
    def get_image_name(id: int, silhouette: bool) -> str:
        id_str = core.PaddedInt(id, 2).to_str()
        return f"gatyaitemD_{id_str}_{'z' if silhouette else 'f'}.png"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        id: int,
        gatya_item_buy: GatyaItemBuyItem,
        gatya_item_name: GatyaItemNameItem,
    ) -> "GatyaItem":
        image = game_data.find_file(GatyaItem.get_image_name(id, False))

        silhouette = game_data.find_file(GatyaItem.get_image_name(id, True))

        return GatyaItem(
            id,
            gatya_item_buy,
            gatya_item_name,
            core.BCImage(image.dec_data if image is not None else None),
            core.BCImage(silhouette.dec_data if silhouette is not None else None),
        )

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        if self.image is not None:
            game_data.set_file(
                GatyaItem.get_image_name(self.id, False),
                self.image.to_data(),
            )
        if self.silhouette is not None:
            game_data.set_file(
                GatyaItem.get_image_name(self.id, True),
                self.silhouette.to_data(),
            )

    def get_gatya_item_buy_item(self) -> GatyaItemBuyItem:
        if self.gatya_item_buy_item is None:
            self.gatya_item_buy_item = GatyaItemBuyItem.create_empty(self.id)
        return self.gatya_item_buy_item

    def get_gatya_item_name_item(self) -> GatyaItemNameItem:
        if self.gatya_item_name_item is None:
            self.gatya_item_name_item = GatyaItemNameItem.create_empty(self.id)
        return self.gatya_item_name_item

    def set_id(self, id: int) -> None:
        self.id = id
        if self.gatya_item_buy_item is not None:
            self.gatya_item_buy_item.set_id(id)
        if self.gatya_item_name_item is not None:
            self.gatya_item_name_item.set_id(id)

    @staticmethod
    def create_empty(id: int) -> "GatyaItem":
        return GatyaItem(id)

    def apply_dict(self, dict_data: dict[str, Any]):
        gatya_item_buy_item = dict_data.get("gatya_item_buy_item")
        if gatya_item_buy_item is not None:
            self.get_gatya_item_buy_item().apply_dict(gatya_item_buy_item)
        gatya_item_name_item = dict_data.get("gatya_item_name_item")
        if gatya_item_name_item is not None:
            self.get_gatya_item_name_item().apply_dict(gatya_item_name_item)


class GatyaItems(core.EditableClass):
    def __init__(self, items: dict[int, GatyaItem]):
        self.data = items
        super().__init__(self.data)

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "GatyaItems":
        if game_data.gatya_items is not None:
            return game_data.gatya_items
        gatya_item_buy = GatyaItemBuy.from_game_data(game_data)
        gatya_item_name = GatyaItemName.from_game_data(game_data)

        items: dict[int, GatyaItem] = {}
        for i in range(len(gatya_item_buy.gatya_item_buys)):
            item_buy = gatya_item_buy.get_item(i)
            if item_buy is None:
                continue
            item_name = gatya_item_name.get_item(i)
            if item_name is None:
                continue
            item = GatyaItem.from_game_data(
                game_data,
                i,
                item_buy,
                item_name,
            )

            items[i] = item

        gatya_items = GatyaItems(items)
        game_data.gatya_items = gatya_items
        return gatya_items

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        gatya_item_buy = GatyaItemBuy({})
        gatya_item_name = GatyaItemName({})
        for item in self.data.values():
            item.to_game_data(game_data)
            if item.gatya_item_buy_item is not None:
                gatya_item_buy.set_item(item.id, item.gatya_item_buy_item)
            if item.gatya_item_name_item is not None:
                gatya_item_name.set_item(item.id, item.gatya_item_name_item)

        gatya_item_buy.to_game_data(game_data)
        gatya_item_name.to_game_data(game_data)

    def get_item(self, id: int) -> Optional[GatyaItem]:
        return self.data.get(id)

    def set_item(self, id: int, item: GatyaItem) -> None:
        item.set_id(id)
        self.data[id] = item

    @staticmethod
    def create_empty() -> "GatyaItems":
        return GatyaItems({})

    def get_item_stage_drop_id(self, id: int) -> Optional[int]:
        item = self.get_item(id)
        if item is None:
            return None
        if item.gatya_item_buy_item is None:
            return None
        return item.gatya_item_buy_item.stage_drop_item_id
