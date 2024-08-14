from __future__ import annotations

import enum

import tbcml
from marshmallow_dataclass import dataclass

from tbcml.io.csv_fields import (
    BoolCSVField,
    IntCSVField,
    IntListCSVField,
    StringCSVField,
    StrListCSVField,
)


class GatyaItemCategory(enum.Enum):
    NONE = 0
    TICKET_SET_1 = 1
    ABILITY = 2
    BATTLE_ITEM = 3
    MATATABI = 4
    CATSEYE = 5
    CATAMIN = 6
    OTOTO_MATERIAL = 7
    TICKET_SET_2 = 8
    ENDLESS_ITEMS = 9
    TICKET_SET_3 = 10
    MEDALS = 11


@dataclass
class Matatabi:
    seed: bool | None = None
    group: int | None = None
    sort: int | None = None
    require: int | None = None
    text_id: str | None = None
    growup: list[int] | None = None

    def __post_init__(self):
        self._csv__seed = BoolCSVField(col_index=1)
        self._csv__group = IntCSVField(col_index=2)
        self._csv__sort = IntCSVField(col_index=3)
        self._csv__require = IntCSVField(col_index=4)
        self._csv__text_id = StringCSVField(col_index=5)
        self._csv__growup = IntListCSVField(col_index=6)

    def find_index(self, item_id: int, csv: tbcml.CSV):
        for i, row in enumerate(csv.lines):
            if row and row[0] == str(item_id):
                return i
        return None

    def read_csv(self, item_id: int, csv: tbcml.CSV):
        index = self.find_index(item_id, csv)
        if index is None:
            return

        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, item_id: int, csv: tbcml.CSV):
        index = self.find_index(item_id, csv)
        if index is None:
            index = len(csv.lines)
            csv.index = index
            csv.set_str(str(item_id), 0)
        else:
            csv.index = index

        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def get_csv(self, game_data: tbcml.GamePacks):
        filename = "Matatabi.tsv"
        return filename, game_data.get_csv(filename, delimeter="\t")

    def read_game_data(self, item_id: int, game_data: tbcml.GamePacks):
        _, csv = self.get_csv(game_data)
        if csv is None:
            return

        self.read_csv(item_id, csv)

    def apply_game_data(self, item_id: int, game_data: tbcml.GamePacks):
        filename, csv = self.get_csv(game_data)
        if csv is None:
            return

        self.apply_csv(item_id, csv)

        game_data.set_csv(filename, csv)


@dataclass
class GatyaItemBuy:
    rarity: int | None = None
    storage: bool | None = None
    sell_price: int | None = None
    stage_item_id: int | None = None
    quantity: int | None = None
    server_id: int | None = None
    category: int | None = None
    category_index: int | None = None
    src_item_id: int | None = None
    main_menu_type: int | None = None
    gatya_ticket_id: int | None = None
    comment: str | None = None

    def __post_init__(self):
        self._csv__rarity = IntCSVField(col_index=0)
        self._csv__storage = BoolCSVField(col_index=1)
        self._csv__sell_price = IntCSVField(col_index=2)
        self._csv__stage_item_id = IntCSVField(col_index=3)
        self._csv__quantity = IntCSVField(col_index=4)
        self._csv__server_id = IntCSVField(col_index=5)
        self._csv__category = IntCSVField(col_index=6)
        self._csv__category_index = IntCSVField(col_index=7)
        self._csv__src_item_id = IntCSVField(col_index=8)
        self._csv__main_menu_type = IntCSVField(col_index=9)
        self._csv__gatya_ticket_id = IntCSVField(col_index=10)
        self._csv__comment = StringCSVField(col_index=11)

    def get_category(self) -> GatyaItemCategory:
        return GatyaItemCategory(self.category)

    def set_category(self, category: GatyaItemCategory):
        self.category = category.value

    def apply_csv(self, item_id: int, csv: tbcml.CSV):
        csv.index = item_id + 1
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, item_id: int, csv: tbcml.CSV):
        csv.index = item_id + 1
        tbcml.Modification.read_csv_fields(self, csv)

    @staticmethod
    def get_csv(game_data: tbcml.GamePacks):
        filename = "Gatyaitembuy.csv"
        return filename, game_data.get_csv(filename)

    def apply_game_data(self, item_id: int, game_data: tbcml.GamePacks):
        file_name, csv = self.get_csv(game_data)
        if csv is None:
            return

        self.apply_csv(item_id, csv)
        game_data.set_csv(file_name, csv)

    def read_game_data(self, item_id: int, game_data: tbcml.GamePacks):
        _, csv = self.get_csv(game_data)
        if csv is None:
            return

        self.read_csv(item_id, csv)

    @staticmethod
    def get_all(game_data: tbcml.GamePacks) -> list[GatyaItemBuy]:
        _, csv = GatyaItemBuy.get_csv(game_data)
        if csv is None:
            return []
        total_items = len(csv.lines) - 1

        items: list[GatyaItemBuy] = []

        for i in range(total_items):
            item = GatyaItemBuy()
            item.read_csv(i, csv)
            items.append(item)

        return items


@dataclass
class GatyaItem(tbcml.Modification):
    item_id: int
    name: str | None = None
    description: list[str] | None = None
    img: tbcml.BCImage | None = None
    img_black: tbcml.BCImage | None = None
    itembuy: GatyaItemBuy | None = None
    matatabi: Matatabi | None = None

    def __post_init__(self):
        self._csv__name = StringCSVField(col_index=0)
        self._csv__description = StrListCSVField(col_index=1, blank="＠")

    def get_name_desc_csv(self, game_data: tbcml.GamePacks):
        filename = "GatyaitemName.csv"
        return filename, game_data.get_csv(
            filename, country_code=game_data.country_code, remove_empty=False
        )

    def read_name_desc(self, game_data: tbcml.GamePacks):
        _, csv = self.get_name_desc_csv(game_data)
        if csv is None:
            return

        csv.index = self.item_id

        tbcml.Modification.read_csv_fields(self, csv)

    def apply_name_desc(self, game_data: tbcml.GamePacks):
        filename, csv = self.get_name_desc_csv(game_data)
        if csv is None:
            return

        csv.index = self.item_id

        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)
        game_data.set_csv(filename, csv)

    def get_img_file(self, game_data: tbcml.GamePacks, is_black: bool):
        code = "f" if not is_black else "z"
        filename = f"gatyaitemD_{str(self.item_id).zfill(2)}_{code}.png"
        return filename, game_data.get_img(filename)

    def read_img(self, game_data: tbcml.GamePacks):
        _, img = self.get_img_file(game_data, False)
        if img is not None:
            self.img = img

        _, img_black = self.get_img_file(game_data, True)
        if img_black is not None:
            self.img_black = img_black

    def apply_img(self, game_data: tbcml.GamePacks):
        filename, _ = self.get_img_file(game_data, False)
        if self.img is not None:
            game_data.set_img(filename, self.img)

        filename_black, _ = self.get_img_file(game_data, True)
        if self.img_black is not None:
            game_data.set_img(filename_black, self.img_black)

    def apply_game_data(self, game_data: tbcml.GamePacks):
        self.apply_name_desc(game_data)
        self.apply_img(game_data)

        if self.matatabi is not None:
            self.matatabi.apply_game_data(self.item_id, game_data)

        if self.itembuy is not None:
            self.itembuy.apply_game_data(self.item_id, game_data)

    def read_game_data(self, game_data: tbcml.GamePacks):
        self.read_name_desc(game_data)
        self.read_img(game_data)

        self.matatabi = Matatabi()
        self.itembuy = GatyaItemBuy()

        self.matatabi.read_game_data(self.item_id, game_data)
        self.itembuy.read_game_data(self.item_id, game_data)

    def read(self, game_data: tbcml.GamePacks):
        self.read_game_data(game_data)

    def apply(self, game_data: tbcml.GamePacks):
        self.apply_game_data(game_data)

    def pre_to_json(self) -> None:
        if self.img is not None:
            self.img.save_b64()
        if self.img_black is not None:
            self.img_black.save_b64()

    def become_evolve_item(
        self,
        seed: bool,
        group: int,
        sort: int,
        category_index: int | None = None,
        game_data: tbcml.GamePacks | None = None,
        require: int | None = None,
        text_id: str | None = None,
        growup: list[int] | None = None,
    ):
        if seed:
            if require is None or text_id is None or growup is None:
                raise ValueError(
                    "For a seed, require, text_id, and growup are required"
                )
        else:
            if require is not None or text_id is not None or growup is not None:
                raise ValueError(
                    "For a non-seed, require, text_id and growup should be None"
                )
        self.matatabi = Matatabi(seed, group, sort, require, text_id, growup)
        if self.itembuy is None:
            return

        self.itembuy.set_category(GatyaItemCategory.MATATABI)
        if category_index is None:
            if game_data is None:
                raise ValueError("category_index or game_data must be specified")
            all_items = GatyaItemBuy.get_all(game_data)
            category_index = 0
            for item in all_items:
                if item.get_category() == GatyaItemCategory.MATATABI:
                    category_index += 1

        self.itembuy.category_index = category_index
