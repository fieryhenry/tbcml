import tbcml


class CustomLocalizable(tbcml.Localizable):
    def __init__(self):
        super().__init__()
        self.set_string("catfood", "Cat Food")


class CatFoodItem(tbcml.ShopItem):
    def __init__(self):
        super().__init__()
        self.count = 500
        self.cost = 1
        self.gatya_item_id = 22
        self.draw_item_value = True
        self.category_name = "catfood"
        self.imgcut_rect_id = 0  # haven't made my own sprite, so using speed ups sprite


class CustomShop(tbcml.ItemShop):
    def __init__(self, game_packs: tbcml.GamePacks):
        super().__init__()
        self.read_data(game_packs)  # add_item needs to know total items, so read data

        catfood_item = CatFoodItem()

        self.add_item(
            catfood_item
        )  # adds to end of shop, use self.set_item(catfood_item, id) to overwrite existing item


loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()

apk = loader.get_apk()

mod = tbcml.Mod(
    "Custom ItemShop", "fieryhenry", "Adds catfood as a custom item shop item"
)

mod.add_modification(CustomShop(loader.get_game_packs()))
mod.add_modification(CustomLocalizable())

apk.set_app_name("Custom Shop")
apk.set_package_name("jp.co.ponos.battlecats.customshop")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
