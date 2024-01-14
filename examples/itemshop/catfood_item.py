from tbcml import core


class CustomLocalizable(core.Localizable):
    def __init__(self):
        super().__init__()
        self.set_string("catfood", "Cat Food")


class CatFoodItem(core.ShopItem):
    def __init__(self):
        super().__init__()

        self.shop_id.set(0)

        self.count.set(500)
        self.cost.set(1)
        self.gatya_item_id.set(22)
        self.draw_item_value.set(True)
        self.category_name.set("catfood")


class CustomShop(core.ItemShop):
    def __init__(self):
        super().__init__()

        self.set_item(CatFoodItem())


loader = core.ModLoader("en", "12.3.0")
loader.initialize()

apk = loader.get_apk()

mod = core.Mod(
    "Custom ItemShop", "fieryhenry", "Adds catfood as a custom item shop item"
)

mod.add_modification(CustomShop())
mod.add_modification(CustomLocalizable())

apk.set_app_name("Custom Shop")
apk.set_package_name("jp.co.ponos.battlecats.customshop")

loader.apply(mod)
