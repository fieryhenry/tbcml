from tbcml.core import ItemShop
from tbcml.core.game_data.cat_base.item_shop import Item

from .catfood import CatFoodItem

class CustomShop(ItemShop):
    def __init__(self, game_data):
        self.game_data = game_data

    def initialize(self):
        shop = ItemShop.from_game_data(self.game_data)

        item = CatFoodItem(self.game_data)

        shop.add_item(item)
        
        return shop