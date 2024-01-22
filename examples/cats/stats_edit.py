import tbcml


class NewForm(tbcml.CatForm):
    def __init__(self, cat_id: int, game_data: tbcml.GamePacks):
        super().__init__(form_type=tbcml.CatFormType.FIRST)
        self.read_stats(
            cat_id, game_data
        )  # not needed if you are just writing stats, not reading anything

        stats = self.get_stats()
        stats.hp = 5000
        stats.cost = 0
        stats.attack_1_damage = 8000
        stats.speed = 100
        stats.attack_interval = 0
        stats.area_attack = True


class NewCat(tbcml.Cat):
    def __init__(self, game_data: tbcml.GamePacks):
        super().__init__(cat_id=0)

        self.set_form(NewForm(self.cat_id, game_data))


loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()


mod = tbcml.Mod(
    "Modded Cat Stats Example",
    "fieryhenry",
    "Changes basic cat stats",
)

mod.add_modification(NewCat(loader.get_game_packs()))

apk = loader.get_apk()

apk.set_app_name("Modded Cat")
apk.set_package_name("jp.co.ponos.battlecatsen.moddedcat")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)
