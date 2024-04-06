import tbcml


class CustomStage(tbcml.Stage):
    def __init__(
        self,
        parent_map: tbcml.Map,
        stage_index: int,
    ):
        super().__init__(name="Epic Stage", base_health=10000, parent_map=parent_map)
        # text name is only used for the Post to SNS feature i'm pretty sure, actual stage names are all stored as images annoyingly
        self.sync(stage_index)  # used to sync data with the original stage

        self.get_story_map_name_img().flip_x()
        self.get_in_battle_img().flip_y()


class CustomMap(tbcml.Map):
    def __init__(self, game_data: tbcml.GamePacks):
        super().__init__(map_index=0, map_type=tbcml.MapType.EMPIRE_OF_CATS)
        self.read(game_data)

        self.set_stage(0, CustomStage(parent_map=self, stage_index=0))


loader = tbcml.ModLoader("en", "12.3.0")
loader.initialize()

mod = tbcml.Mod(
    "Custom Map",
    authors="fieryhenry",
    short_description="Modifies korea to have 10k base health",
)

mod.add_modification(CustomMap(loader.get_game_packs()))

apk = loader.get_apk()


apk.set_package_name("jp.co.ponos.battlecats.korea")
apk.set_app_name("Battle Cats (Korea)")

loader.apply(mod)

game_packs = loader.get_game_packs()

# loader.initialize_adb()
# loader.install_adb(run_game=True)
