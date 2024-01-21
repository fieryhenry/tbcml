import tbcml


class CustomStage(tbcml.Stage):
    def __init__(self):
        super().__init__()
        self.stage_csv_data.stage_info.base_health.set(10000)


class CustomMap(tbcml.Map):
    def __init__(self):
        super().__init__(map_index=0, map_type=tbcml.MapType.EMPIRE_OF_CATS)

        self.stages.append(CustomStage())


loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()

mod = tbcml.Mod(
    "Custom Map",
    authors="fieryhenry",
    description="Modifies korea to have 10k base health",
)

mod.add_modification(CustomMap())

apk = loader.get_apk()


apk.set_package_name("jp.co.ponos.battlecats.korea")
apk.set_app_name("Battle Cats (Korea)")

loader.apply(mod)

game_packs = loader.get_game_packs()

# loader.initialize_adb()
# loader.install_adb(run_game=True)
