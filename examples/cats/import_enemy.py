from tbcml import core

cc = core.CountryCode.from_code("en")

gv = core.GameVersion.from_string_latest("12.3.0", cc)

apk = core.Apk(gv, cc)
apk.download()
apk.extract()
apk.download_server_files()

game_data = core.GamePacks.from_apk(apk)

cat_id = 0

cats = core.Cats.from_game_data(game_data, [cat_id])  # avoid loading all cats
cat = cats.get_cat(cat_id)
if cat is None:
    raise ValueError("Cat 0 not found")

first_form = cat.get_form(core.CatFormType.FIRST)  # can also do cat.get_form(0)
if first_form is None:
    raise ValueError("Cat 0 first form not found")

enemies = core.Enemies.from_game_data(game_data)
enemy = enemies.get_enemy(0)
if enemy is None:
    raise ValueError("Doge not found")
enemy_model = enemy.get_anim().model

cat_model = first_form.get_anim().model

first_form.import_enemy(enemy)

mod = core.Mod(
    "enemy_as_cat",
    "fieryhenry",
    "changes basic cat to doge",
    core.Mod.create_mod_id(),
    "1.0.0",
)

mod_edit = core.ModEdit(["cats", cat_id], cat.to_dict())
mod.add_mod_edit(mod_edit)

apk.set_app_name("12.3.0")
apk.set_package_name("jp.co.ponos.battlecatsie")

apk.load_mods([mod], game_data)
