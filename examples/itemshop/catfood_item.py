import tbcml


class CustomLocalizable(tbcml.Localizable):
    def __init__(self):
        super().__init__()
        self.set_string("catfood", "Cat Food")


class CatFoodItem(tbcml.ShopItem):
    def __init__(self):
        super().__init__(
            count=500,
            cost=1,
            gatya_item_id=22,
            draw_item_value=True,
            category_name="catfood",
            imgcut_rect_id=0,  # use same image as speed up
        )


class CustomShop(tbcml.ItemShop):
    def __init__(self, game_packs: tbcml.GamePacks):
        super().__init__(
            total_items=4
        )  # change total number of shop items, leave as None to not remove any items
        self.read_data(game_packs)

        self.set_item(CatFoodItem(), 2)  # set 3rd item to catfood


loader = tbcml.ModLoader("en", "13.1.1")
loader.initialize()

apk = loader.get_apk()

mod = tbcml.Mod(
    "Custom ItemShop", "fieryhenry", "Adds catfood as a custom item shop item"
)

mod.add_modification(CustomShop(loader.get_game_packs()))
mod.add_modification(CustomLocalizable())

apk.set_app_name("Custom Shop")
apk.set_package_name("jp.co.ponos.battlecats.itemshop")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
