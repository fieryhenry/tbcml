from tbcml.core import GamePacks, Localizable


from tbcml.core.game_data.cat_base.item_shop import Item

class CatFoodItem(Item):
    def __init__(self, game_data: GamePacks):
        self.id = 0
        self.count = 25
        self.price = 1
        self.gachya_item_id = 22
        self.category_name = "catfood"
        self.game_data = game_data
        self.localizable = self.__get_localizable()

        super().__init__(shop_id=self.id, gatya_item_id=self.gachya_item_id, count=self.count, price=self.price, draw_item_value=True, category_name=self.category_name, rect_id=0)

    def __get_localizable(self):
        
        localizable = Localizable.from_game_data(self.game_data)
        localizable.set("catfood", "Cat Food")
        
        return localizable

