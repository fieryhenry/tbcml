from typing import Any, Optional
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

    def serialize(self) -> dict[str, Any]:
        return {
            "rarity": self.rarity,
            "storage": self.storage,
            "sell_price": self.sell_price,
            "stage_drop_item_id": self.stage_drop_item_id,
            "quantity": self.quantity,
            "server_id": self.server_id,
            "category": self.category.value,
            "index_in_category": self.index_in_category,
            "src_item_id": self.src_item_id,
            "main_menu_type": self.main_menu_type,
            "gatya_ticket_id": self.gatya_ticket_id,
            "comment": self.comment,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], item_id: int) -> "GatyaItemBuyItem":
        return GatyaItemBuyItem(
            item_id,
            data["rarity"],
            data["storage"],
            data["sell_price"],
            data["stage_drop_item_id"],
            data["quantity"],
            data["server_id"],
            ItemBuyCategory(data["category"]),
            data["index_in_category"],
            data["src_item_id"],
            data["main_menu_type"],
            data["gatya_ticket_id"],
            data["comment"],
        )

    def set_id(self, item_id: int) -> None:
        self.item_id = item_id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GatyaItemBuyItem):
            return False
        return (
            self.rarity == other.rarity
            and self.storage == other.storage
            and self.sell_price == other.sell_price
            and self.stage_drop_item_id == other.stage_drop_item_id
            and self.quantity == other.quantity
            and self.server_id == other.server_id
            and self.category == other.category
            and self.index_in_category == other.index_in_category
            and self.src_item_id == other.src_item_id
            and self.main_menu_type == other.main_menu_type
            and self.gatya_ticket_id == other.gatya_ticket_id
            and self.comment == other.comment
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class GatyaItemBuy:
    def __init__(
        self,
        gatya_item_buys: dict[int, GatyaItemBuyItem],
    ):
        self.gatya_item_buys = gatya_item_buys

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_item_buys": {
                k: v.serialize() for k, v in self.gatya_item_buys.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaItemBuy":
        return GatyaItemBuy(
            {
                k: GatyaItemBuyItem.deserialize(v, k)
                for k, v in data["gatya_item_buys"].items()
            }
        )

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
                comment = line[11].to_str()
            gatya_item_buys[i] = GatyaItemBuyItem(
                i,
                line[0].to_int(),
                line[1].to_bool(),
                line[2].to_int(),
                line[3].to_int(),
                line[4].to_int(),
                line[5].to_int(),
                ItemBuyCategory(line[6].to_int()),
                line[7].to_int(),
                line[8].to_int(),
                line[9].to_int(),
                line[10].to_int(),
                comment,
            )

        return GatyaItemBuy(gatya_item_buys)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        csv_data = game_data.find_file(GatyaItemBuy.get_file_name())
        if csv_data is None:
            return None

        csv = io.bc_csv.CSV(csv_data.dec_data)
        for item in self.gatya_item_buys.values():
            line: list[Any] = []
            line.append(item.rarity)
            line.append(item.storage)
            line.append(item.sell_price)
            line.append(item.stage_drop_item_id)
            line.append(item.quantity)
            line.append(item.server_id)
            line.append(item.category.value)
            line.append(item.index_in_category)
            line.append(item.src_item_id)
            line.append(item.main_menu_type)
            line.append(item.gatya_ticket_id)
            line.append(item.comment)
            csv.set_line(item.item_id + 1, line)

        game_data.set_file(GatyaItemBuy.get_file_name(), csv.to_data())

    def get_item(self, item_id: int) -> Optional[GatyaItemBuyItem]:
        return self.gatya_item_buys.get(item_id)

    def set_item(self, item_id: int, item: GatyaItemBuyItem) -> None:
        item.item_id = item_id
        self.gatya_item_buys[item_id] = item

    @staticmethod
    def create_empty() -> "GatyaItemBuy":
        return GatyaItemBuy({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GatyaItemBuy):
            return False
        return self.gatya_item_buys == other.gatya_item_buys

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


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

    def serialize(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], id: int) -> "GatyaItemNameItem":
        return GatyaItemNameItem(
            id,
            data["name"],
            data["description"],
        )

    def set_id(self, id: int) -> None:
        self.id = id

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GatyaItemNameItem):
            return False
        return (
            self.id == other.id
            and self.name == other.name
            and self.description == other.description
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class GatyaItemName:
    def __init__(self, gatya_item_names: dict[int, GatyaItemNameItem]):
        self.gatya_item_names = gatya_item_names

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_item_names": {
                k: v.serialize() for k, v in self.gatya_item_names.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaItemName":
        return GatyaItemName(
            {
                k: GatyaItemNameItem.deserialize(v, k)
                for k, v in data["gatya_item_names"].items()
            }
        )

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
            name = line[0].to_str()
            description = io.data.Data.data_list_string_list(line[1:])
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
            line: list[Any] = []
            line.append(item.name)
            line.extend(item.description)
            csv.set_line(item.id, line)

        game_data.set_file(GatyaItemName.get_file_name(), csv.to_data())

    def get_item(self, id: int) -> Optional[GatyaItemNameItem]:
        return self.gatya_item_names.get(id)

    def set_item(self, id: int, item: GatyaItemNameItem) -> None:
        item.id = id
        self.gatya_item_names[id] = item

    @staticmethod
    def create_empty() -> "GatyaItemName":
        return GatyaItemName({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GatyaItemName):
            return False
        return self.gatya_item_names == other.gatya_item_names

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


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

    def serialize(self) -> dict[str, Any]:
        return {
            "gatya_item_buy_item": self.gatya_item_buy_item.serialize(),
            "gatya_item_name_item": self.gatya_item_name_item.serialize(),
            "image": self.image.serialize(),
            "silhouette": self.silhouette.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], id: int) -> "GatyaItem":
        return GatyaItem(
            id,
            GatyaItemBuyItem.deserialize(data["gatya_item_buy_item"], id),
            GatyaItemNameItem.deserialize(data["gatya_item_name_item"], id),
            io.bc_image.BCImage.deserialize(data["image"]),
            io.bc_image.BCImage.deserialize(data["silhouette"]),
        )

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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GatyaItem):
            return False
        return (
            self.id == other.id
            and self.gatya_item_buy_item == other.gatya_item_buy_item
            and self.gatya_item_name_item == other.gatya_item_name_item
            and self.image == other.image
            and self.silhouette == other.silhouette
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class GatyaItems:
    def __init__(self, items: dict[int, GatyaItem]):
        self.items = items

    def serialize(self) -> dict[str, Any]:
        return {
            "items": {k: v.serialize() for k, v in self.items.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "GatyaItems":
        return GatyaItems(
            {k: GatyaItem.deserialize(v, k) for k, v in data["items"].items()}
        )

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
    def get_items_json_file_name() -> "io.path.Path":
        return io.path.Path("catbase").add("gatya_items.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        items_json = io.json_file.JsonFile.from_object(self.serialize())
        zip.add_file(GatyaItems.get_items_json_file_name(), items_json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "GatyaItems":
        items_json = zip.get_file(GatyaItems.get_items_json_file_name())
        if items_json is None:
            return GatyaItems.create_empty()
        return GatyaItems.deserialize(io.json_file.JsonFile(items_json).get_json())

    @staticmethod
    def create_empty() -> "GatyaItems":
        return GatyaItems({})

    def import_items(self, other: "GatyaItems", game_data: "pack.GamePacks"):
        """_summary_

        Args:
            other (GatyaItems): _description_
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_items = GatyaItems.from_game_data(game_data)
        all_keys = set(gd_items.items.keys())
        all_keys.update(other.items.keys())
        all_keys.update(self.items.keys())
        for id in all_keys:
            gd_item = gd_items.get_item(id)
            other_item = other.get_item(id)
            if other_item is None:
                continue
            if gd_item is not None:
                if other_item != gd_item:
                    self.set_item(id, other_item)
            else:
                self.set_item(id, other_item)

    def get_item_stage_drop_id(self, id: int) -> Optional[int]:
        item = self.get_item(id)
        if item is None:
            return None
        return item.gatya_item_buy_item.stage_drop_item_id
