from typing import Optional
from tbcml.core.game_data import pack
from tbcml.core import io
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
        rarity: int,
        storage: bool,
        sell_price: int,
        stage_drop_item_id: int,
        quantity: int,
        server_id: int,
        category: ItemBuyCategory,
        index_in_category: int,
        src_item_id: int,
        main_menu_type: int,
        gatya_ticket_id: int,
        comment: str,
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
    def from_game_data(game_data: "pack.GamePacks") -> "GatyaItemBuy":
        csv_data = game_data.find_file(GatyaItemBuy.get_file_name())
        if csv_data is None:
            return GatyaItemBuy.create_empty()

        csv = io.bc_csv.CSV(csv_data.dec_data)
        gatya_item_buys: dict[int, GatyaItemBuyItem] = {}
        for i, line in enumerate(csv.lines[1:]):
            comment = ""
            if len(line) > 11:
                comment = line[11]
            gatya_item_buys[i] = GatyaItemBuyItem(
                i,
                int(line[0]),
                bool(line[1]),
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

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        csv_data = game_data.find_file(GatyaItemBuy.get_file_name())
        if csv_data is None:
            return None

        csv = io.bc_csv.CSV(csv_data.dec_data)
        for item in self.gatya_item_buys.values():
            line: list[str] = []
            line.append(str(item.rarity))
            line.append("1" if item.storage else "0")
            line.append(str(item.sell_price))
            line.append(str(item.stage_drop_item_id))
            line.append(str(item.quantity))
            line.append(str(item.server_id))
            line.append(str(item.category.value))
            line.append(str(item.index_in_category))
            line.append(str(item.src_item_id))
            line.append(str(item.main_menu_type))
            line.append(str(item.gatya_ticket_id))
            line.append(item.comment)
            csv.lines[item.item_id + 1] = line

        game_data.set_file(GatyaItemBuy.get_file_name(), csv.to_data())

    def get_item(self, item_id: int) -> Optional[GatyaItemBuyItem]:
        return self.gatya_item_buys.get(item_id)

    def set_item(self, item_id: int, item: GatyaItemBuyItem) -> None:
        item.item_id = item_id
        self.gatya_item_buys[item_id] = item

    @staticmethod
    def create_empty() -> "GatyaItemBuy":
        return GatyaItemBuy({})


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


class GatyaItemName:
    def __init__(self, gatya_item_names: dict[int, GatyaItemNameItem]):
        self.gatya_item_names = gatya_item_names

    @staticmethod
    def get_file_name() -> str:
        return "GatyaitemName.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "GatyaItemName":
        csv_data = game_data.find_file(GatyaItemName.get_file_name())
        if csv_data is None:
            return GatyaItemName.create_empty()

        csv = io.bc_csv.CSV(
            csv_data.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
        )
        gatya_item_names: dict[int, GatyaItemNameItem] = {}
        for i, line in enumerate(csv.lines):
            name = line[0]
            description = line[1:]
            gatya_item_names[i] = GatyaItemNameItem(i, name, description)

        return GatyaItemName(gatya_item_names)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        csv_data = game_data.find_file(GatyaItemName.get_file_name())
        if csv_data is None:
            return None

        csv = io.bc_csv.CSV(
            csv_data.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
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


class GatyaItem:
    def __init__(
        self,
        id: int,
        gatya_item_buy_item: GatyaItemBuyItem,
        gatya_item_name_item: GatyaItemNameItem,
        image: "io.bc_image.BCImage",
        silhouette: "io.bc_image.BCImage",
    ):
        self.id = id
        self.gatya_item_buy_item = gatya_item_buy_item
        self.gatya_item_name_item = gatya_item_name_item
        self.image = image
        self.silhouette = silhouette

    @staticmethod
    def get_image_name(id: int, silhouette: bool) -> str:
        id_str = io.data.PaddedInt(id, 2).to_str()
        return f"gatyaitemD_{id_str}_{'z' if silhouette else 'f'}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
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
            io.bc_image.BCImage(image.dec_data if image is not None else None),
            io.bc_image.BCImage(
                silhouette.dec_data if silhouette is not None else None
            ),
        )

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        game_data.set_file(
            GatyaItem.get_image_name(self.id, False),
            self.image.to_data(),
        )
        game_data.set_file(
            GatyaItem.get_image_name(self.id, True),
            self.silhouette.to_data(),
        )

    def set_id(self, id: int) -> None:
        self.id = id
        self.gatya_item_buy_item.set_id(id)
        self.gatya_item_name_item.set_id(id)


class GatyaItems:
    def __init__(self, items: dict[int, GatyaItem]):
        self.items = items

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "GatyaItems":
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

        return GatyaItems(items)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        gatya_item_buy = GatyaItemBuy({})
        gatya_item_name = GatyaItemName({})
        for item in self.items.values():
            item.to_game_data(game_data)
            gatya_item_buy.set_item(item.id, item.gatya_item_buy_item)
            gatya_item_name.set_item(item.id, item.gatya_item_name_item)

        gatya_item_buy.to_game_data(game_data)
        gatya_item_name.to_game_data(game_data)

    def get_item(self, id: int) -> Optional[GatyaItem]:
        return self.items.get(id)

    def set_item(self, id: int, item: GatyaItem) -> None:
        item.set_id(id)
        self.items[id] = item

    @staticmethod
    def create_empty() -> "GatyaItems":
        return GatyaItems({})

    def get_item_stage_drop_id(self, id: int) -> Optional[int]:
        item = self.get_item(id)
        if item is None:
            return None
        return item.gatya_item_buy_item.stage_drop_item_id
