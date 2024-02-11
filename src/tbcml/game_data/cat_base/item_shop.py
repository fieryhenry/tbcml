import copy
from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml

from tbcml.io.csv_fields import (
    IntCSVField,
    StringCSVField,
    BoolCSVField,
)


@dataclass
class ShopItem:
    shop_id: Optional[int] = None
    gatya_item_id: Optional[int] = None
    count: Optional[int] = None
    cost: Optional[int] = None
    draw_item_value: Optional[bool] = None
    category_name: Optional[str] = None
    imgcut_rect_id: Optional[int] = None

    def __post_init__(self):
        self.csv__shop_id = IntCSVField(col_index=0)
        self.csv__gatya_item_id = IntCSVField(col_index=1)
        self.csv__count = IntCSVField(col_index=2)
        self.csv__cost = IntCSVField(col_index=3)
        self.csv__draw_item_value = BoolCSVField(col_index=4)
        self.csv__category_name = StringCSVField(col_index=5)
        self.csv__imgcut_rect_id = IntCSVField(col_index=6)

    def find_index(self, csv: "tbcml.CSV") -> Optional[int]:
        if self.shop_id is None:
            return None
        for i in range(len(csv.lines[1:])):
            csv.index = i + 1
            if csv.get_str(0) == str(self.shop_id):
                return csv.index
        return None

    def read_csv(self, csv: "tbcml.CSV", index: int) -> bool:
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)
        return True

    def apply_csv(self, csv: "tbcml.CSV"):
        index = self.find_index(csv) or len(csv.lines)
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def copy(self) -> "ShopItem":
        return copy.deepcopy(self)


@dataclass
class ItemShop(tbcml.Modification):
    items: Optional[dict[int, "ShopItem"]] = None
    texture: Optional["tbcml.Texture"] = None
    total_items: Optional[int] = None
    modification_type: tbcml.ModificationType = tbcml.ModificationType.SHOP

    def get_texture(self) -> "tbcml.Texture":
        if self.texture is None:
            self.texture = tbcml.Texture()
        return self.texture

    def __post_init__(self):
        ItemShop.Schema()

    def get_item(self, id: int) -> Optional[ShopItem]:
        if self.items is None:
            return None
        return self.items.get(id)

    @staticmethod
    def get_data_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = "itemShopData.tsv"
        csv = game_data.get_csv(file_name, "\t")

        return file_name, csv

    def read_texture(self, game_data: "tbcml.GamePacks"):
        sprite_name = f"item000_{game_data.localizable.get_lang()}.png"
        imgcut_name = f"item000_{game_data.localizable.get_lang()}.imgcut"
        imgcut_csv = game_data.get_csv(imgcut_name)
        if imgcut_csv is None:
            return

        texture = tbcml.Texture()
        texture.read_csv(imgcut_csv, imgcut_name)
        texture.read_img(game_data, sprite_name)

        self.texture = texture

    def apply_texture(self, game_data: "tbcml.GamePacks"):
        if self.texture is None:
            return
        texture_csv = tbcml.CSV()
        self.texture.apply_csv(
            texture_csv,
            game_data,
            f"item000_{game_data.localizable.get_lang()}.png",
        )
        game_data.set_csv(self.texture.imgcut_name, texture_csv)

    def read_data(self, game_data: "tbcml.GamePacks"):
        _, csv = self.get_data_csv(game_data)
        if csv is None:
            return

        self.items = {}
        for i in range(len(csv.lines[1:])):
            item = ShopItem()
            item.read_csv(csv, i + 1)
            if item.shop_id is not None:
                self.items[item.shop_id] = item

    def apply_data(self, game_data: "tbcml.GamePacks"):
        file_name, csv = self.get_data_csv(game_data)
        if csv is None or self.items is None:
            return

        for item in self.items.values():
            item.apply_csv(csv)

        if self.total_items is not None:
            new_lines: list[list[str]] = [csv.lines[0]]
            for i in range(len(csv.lines[1:])):
                index = i + 1
                csv.index = index
                if csv.get_int(0, default=-1) in range(self.total_items):
                    new_lines.append(csv.lines[index])

            csv.lines = new_lines

        game_data.set_csv(file_name, csv)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_data(game_data)
        self.read_texture(game_data)

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_data(game_data)
        self.apply_texture(game_data)

    def pre_to_json(self):
        if self.texture is not None:
            self.texture.save_b64()

    def get_custom_html(self) -> str: ...

    def set_item(self, item: "ShopItem", shop_id: Optional[int] = None):
        if shop_id is not None:
            item.shop_id = shop_id

        shop_id = item.shop_id
        if shop_id is None:
            return

        if self.items is None:
            self.items = {}

        self.items[shop_id] = item

    def add_item(self, item: "ShopItem"):
        if self.items is None:
            raise ValueError("You must read data first!")
        id = len(self.items)
        item.shop_id = id
        self.items[id] = item

    def get_item_img(self, item: "ShopItem") -> Optional["tbcml.BCImage"]:
        if item.imgcut_rect_id is None:
            return None
        img = self.get_texture().get_cut(item.imgcut_rect_id)
        if img is None:
            return None
        return img

    def set_item_img(self, item: "ShopItem", img: "tbcml.BCImage") -> bool:
        if item.imgcut_rect_id is None:
            return False
        self.get_texture().set_cut(item.imgcut_rect_id, img)
        return True
