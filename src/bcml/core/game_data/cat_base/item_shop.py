from typing import Any, Optional
from bcml.core.game_data import pack, bc_anim
from bcml.core import io


class Item:
    def __init__(
        self,
        shop_id: int,
        gatya_item_id: int,
        count: int,
        price: int,
        draw_item_value: bool,
        category_name: str,
        imgcut_id: int,
        cut: "bc_anim.Cut",
    ):
        self.shop_id = shop_id
        self.gatya_item_id = gatya_item_id
        self.count = count
        self.price = price
        self.draw_item_value = draw_item_value
        self.category_name = category_name
        self.imgcut_id = imgcut_id
        self.cut = cut

    def serialize(self) -> dict[str, Any]:
        return {
            "shop_id": self.shop_id,
            "gatya_item_id": self.gatya_item_id,
            "count": self.count,
            "price": self.price,
            "draw_item_value": self.draw_item_value,
            "category_name": self.category_name,
            "imgcut_id": self.imgcut_id,
            "cut": self.cut.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Item":
        return Item(
            data["shop_id"],
            data["gatya_item_id"],
            data["count"],
            data["price"],
            data["draw_item_value"],
            data["category_name"],
            data["imgcut_id"],
            bc_anim.Cut.deserialize(data["cut"]),
        )


class ItemShop:
    def __init__(self, items: dict[int, Item], imgcut: "bc_anim.Imgcut"):
        self.items = items
        self.imgcut = imgcut

    def serialize(self) -> dict[str, Any]:
        return {
            "items": {str(k): v.serialize() for k, v in self.items.items()},
            "imgcut": self.imgcut.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ItemShop":
        imgcut = bc_anim.Imgcut.deserialize(data["imgcut"])
        return ItemShop(
            {int(k): Item.deserialize(v) for k, v in data["items"].items()},
            imgcut,
        )

    @staticmethod
    def get_file_name() -> str:
        return "itemShopData.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["ItemShop"]:
        tsv_data = game_data.find_file(ItemShop.get_file_name())
        png_data = game_data.find_file(f"item000_{game_data.country_code.get_language()}.png")
        imgcut_data = game_data.find_file(f"item000_{game_data.country_code.get_language()}.imgcut")
        if tsv_data is None or png_data is None or imgcut_data is None:
            return None
        img = io.bc_image.BCImage(png_data.dec_data)
        imgcut = bc_anim.Imgcut.from_data(imgcut_data.dec_data, img)
        tsv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        items = {}
        for line in tsv.lines[1:]:
            items[line[0].to_int()] = Item(
                line[0].to_int(),
                line[1].to_int(),
                line[2].to_int(),
                line[3].to_int(),
                line[4].to_bool(),
                line[5].to_str(),
                line[6].to_int(),
                imgcut.cuts[line[6].to_int()],
            )
        return ItemShop(items, imgcut)

    def to_game_data(self, game_data: "pack.GamePacks"):
        tsv_data = game_data.find_file(ItemShop.get_file_name())
        if tsv_data is None:
            return None
        tsv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        remaning_items = self.items.copy()
        for i, line in enumerate(tsv.lines[1:]):
            try:
                item = self.items[line[0].to_int()]
            except KeyError:
                continue
            line[1].set(item.gatya_item_id)
            line[2].set(item.count)
            line[3].set(item.price)
            line[4].set(item.draw_item_value)
            line[5].set(item.category_name)
            line[6].set(item.imgcut_id)
            del remaning_items[line[0].to_int()]
            tsv.set_line(i + 1, line)

        for item in remaning_items.values():
            line: list[Any] = []
            line.append(item.shop_id)
            line.append(item.gatya_item_id)
            line.append(item.count)
            line.append(item.price)
            line.append(item.draw_item_value)
            line.append(item.category_name)
            line.append(item.imgcut_id)
            tsv.add_line(line)
        
        game_data.set_file(ItemShop.get_file_name(), tsv.to_data())
        if not self.imgcut.is_empty():
            self.imgcut.reconstruct_image()
            csv_data, png_data = self.imgcut.to_data()
            game_data.set_file(f"item000_{game_data.country_code.get_language()}.png", png_data)
            game_data.set_file(f"item000_{game_data.country_code.get_language()}.imgcut", csv_data)
        

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("catbase").add("item_shop.json")

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip_file.add_file(ItemShop.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["ItemShop"]:
        json_data = zip.get_file(ItemShop.get_json_file_path())
        if json_data is None:
            return None
        json = io.json_file.JsonFile.from_data(json_data)
        return ItemShop.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "ItemShop":
        return ItemShop({}, bc_anim.Imgcut.create_empty())

    def get_item(self, shop_index: int) -> Optional[Item]:
        return self.items.get(shop_index)
    
    def set_item(self, shop_index: int, item: Item):
        item.shop_id = shop_index
        self.items[shop_index] = item
    
    def import_item_shop(self, other: "ItemShop"):
        self.items.update(other.items)
        if not other.imgcut.is_empty():
            self.imgcut = other.imgcut