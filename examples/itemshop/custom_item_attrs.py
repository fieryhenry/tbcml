from tbcml import core

cc = core.CountryCode.from_code("en")

gv = core.GameVersion.from_string_latest("12.3.0", cc)

apk = core.Apk(gv, cc)
apk.download()
apk.extract()
apk.download_server_files()

game_data = core.GamePacks.from_apk(apk)

item_shop = core.ItemShop.from_game_data(game_data)

first_item = item_shop.get_item(0)
if first_item is None:
    raise ValueError("Item 0 not found")
first_item.count = 5000
first_item.price = 1
first_item.gatya_item_id = 22
first_item.category_name = "catfood"

localizable = core.Localizable.from_game_data(game_data)
localizable.set("catfood", "Cat Food")

mod = core.Mod(
    "itemshop_mod", "fieryhenry", "adds custom items", core.Mod.create_mod_id(), "1.0.0"
)

mod_edit = core.ModEdit(["item_shop"], item_shop.to_dict())
mod.add_mod_edit(mod_edit)

mod_edit = core.ModEdit(["localizable"], localizable.to_dict())
mod.add_mod_edit(mod_edit)

apk.set_app_name("12.3.0")
apk.set_package_name("jp.co.ponos.battlecatste")

apk.load_mods([mod], game_data)

game_data.extract(core.Path("dec_modded"))
