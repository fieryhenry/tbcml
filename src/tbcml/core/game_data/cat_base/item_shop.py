from typing import Any, Optional
from tbcml import core


class Item:
    """Represents an item in the Item Shop."""

    def __init__(
        self,
        shop_id: int,
        gatya_item_id: int,
        count: int,
        price: int,
        draw_item_value: bool,
        category_name: str,
        rect_id: int,
    ):
        """Initialize a new Item.

        Args:
            shop_id (int): The index of the item in the shop.
            gatya_item_id (int): The ID of the item to sell.
            count (int): The number of items to sell.
            price (int): The price of the item in catfood.
            draw_item_value (bool): Whether to draw the player's current item count of the item.
            category_name (str): The name of the category the item belongs to. e.g "Battle Items", "XP"
            rect (int): The index in the texture of the item's icon.
        """
        self.shop_id = shop_id
        self.gatya_item_id = gatya_item_id
        self.count = count
        self.price = price
        self.draw_item_value = draw_item_value
        self.category_name = category_name
        self.rect_id = rect_id

    def apply_dict(self, dict_data: dict[str, Any]):
        gatya_item_id = dict_data.get("gatya_item_id")
        if gatya_item_id is not None:
            self.gatya_item_id = core.ModEditValueHandler(
                gatya_item_id, self.gatya_item_id
            ).get_value()
        count = dict_data.get("count")
        if count is not None:
            self.count = core.ModEditValueHandler(count, self.count).get_value()
        price = dict_data.get("price")
        if price is not None:
            self.price = core.ModEditValueHandler(price, self.price).get_value()
        draw_item_value = dict_data.get("draw_item_value")
        if draw_item_value is not None:
            self.draw_item_value = bool(draw_item_value)
        category_name = dict_data.get("category_name")
        if category_name is not None:
            self.category_name = str(category_name)
        rect_id = dict_data.get("rect_id")
        if rect_id is not None:
            self.rect_id = core.ModEditValueHandler(rect_id, self.rect_id).get_value()

    @staticmethod
    def create_empty() -> "Item":
        return Item(0, 0, 0, 0, False, "", 0)


class ItemShop(core.EditableClass):
    """Represents the Item Shop."""

    def __init__(self, items: dict[int, Item], tex: "core.Texture"):
        """Initialize a new ItemShop.

        Args:
            items (dict[int, Item]): The items in the shop.
            tex (core.Texture): The texture containing the icons for the items.
        """
        self.data = items
        self.tex = tex
        super().__init__(self.data)

    @staticmethod
    def get_file_name() -> str:
        """Get the name of the file containing the ItemShop data.

        Returns:
            str: The name of the file containing the ItemShop data.
        """
        return "itemShopData.tsv"

    @staticmethod
    def get_imgname(lang: str) -> str:
        """Get the name of the file containing the ItemShop icons.

        Args:
            lang (str): The language of the icons.

        Returns:
            str: The name of the file containing the ItemShop icons.
        """
        return f"item000_{lang}.png"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "ItemShop":
        """Get the ItemShop from the game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            ItemShop: The ItemShop.
        """
        if game_data.item_shop is not None:
            return game_data.item_shop
        tsv_data = game_data.find_file(ItemShop.get_file_name())
        png_name = f"item000_{game_data.localizable.get_lang()}.png"
        imgcut_name = f"item000_{game_data.localizable.get_lang()}.imgcut"
        tex = core.Texture.load(png_name, imgcut_name, game_data)
        if tsv_data is None:
            return ItemShop.create_empty()
        tsv = core.CSV(tsv_data.dec_data, delimeter="\t")
        items = {}
        for line in tsv.lines[1:]:
            items[int(line[0])] = Item(
                int(line[0]),
                int(line[1]),
                int(line[2]),
                int(line[3]),
                bool(int(line[4])),
                line[5],
                int(line[6]),
            )
        item_shop = ItemShop(items, tex)
        game_data.item_shop = item_shop
        return item_shop

    def get_texture(self) -> "core.Texture":
        """Get the Imgcut of the ItemShop.

        Returns:
            bc_anim.Imgcut: The Imgcut of the ItemShop.
        """
        return self.tex

    def to_game_data(self, game_data: "core.GamePacks"):
        """Write the ItemShop to the game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        tsv_data = game_data.find_file(ItemShop.get_file_name())
        if tsv_data is None:
            return
        tsv = core.CSV(tsv_data.dec_data, delimeter="\t")
        remaning_items = self.data.copy()
        for i, line in enumerate(tsv.lines[1:]):
            try:
                item = self.data[int(line[0])]
            except KeyError:
                continue
            line[1] = str(item.gatya_item_id)
            line[2] = str(item.count)
            line[3] = str(item.price)
            line[4] = "1" if item.draw_item_value else "0"
            line[5] = str(item.category_name)
            line[6] = str(item.rect_id)
            del remaning_items[int(line[0])]
            tsv.lines[i + 1] = line

        for item in remaning_items.values():
            line: list[str] = []
            line.append(str(item.shop_id))
            line.append(str(item.gatya_item_id))
            line.append(str(item.count))
            line.append(str(item.price))
            line.append("1" if item.draw_item_value else "0")
            line.append(str(item.category_name))
            line.append(str(item.rect_id))
            tsv.lines.append(line)

        game_data.set_file(ItemShop.get_file_name(), tsv.to_data())
        tex = self.get_texture()
        if not tex.is_empty():
            tex.save(game_data)

    @staticmethod
    def create_empty() -> "ItemShop":
        """Create an empty ItemShop.

        Returns:
            ItemShop: The empty ItemShop.
        """
        return ItemShop({}, core.Texture.create_empty())

    def get_item(self, shop_index: int) -> Optional[Item]:
        """Get an item from the ItemShop.

        Args:
            shop_index (int): The index of the item in the ItemShop.

        Returns:
            Optional[Item]: The item.
        """
        return self.data.get(shop_index)

    def set_item(self, shop_index: int, item: Item):
        """Set an item in the ItemShop.

        Args:
            shop_index (int): The index of the item in the ItemShop.
            item (Item): The item.
        """
        item.shop_id = shop_index
        self.data[shop_index] = item

    def add_item(self, item: Item):
        """Add an item to the ItemShop.

        Args:
            item (Item): The item to add.
        """
        self.set_item(item.shop_id, item)

    def remove_item(self, shop_index: int):
        """Remove an item from the ItemShop.

        Args:
            shop_index (int): The index of the item in the ItemShop.
        """
        self.data.pop(shop_index)
        self.shift_items(shop_index + 1, -1)

    def shift_items(self, start_index: int, shift: int):
        """Move all items after a certain index.

        Args:
            start_index (int): The index to start shifting from.
            shift (int): The amount to shift by.
        """
        for item in self.data.values():
            if item.shop_id >= start_index:
                item.shop_id += shift
        self.data = {item.shop_id: item for item in self.data.values()}

    def insert_item(self, shop_index: int, item: Item):
        """Insert an item into the ItemShop.

        Args:
            shop_index (int): The index to insert the item at.
            item (Item): The item to insert.
        """
        self.shift_items(shop_index, 1)
        self.set_item(shop_index, item)

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        """Apply a dictionary to the ItemShop.

        Args:
            dict_data (dict[str, Any]): The dictionary to apply.
        """
        data = dict_data.get(mod_edit_key)
        if data is None:
            return
        super().apply_dict(data, "items", convert_int=convert_int)
        tex = data.get("tex")

        if tex is not None:
            self.tex.apply_dict(tex)
