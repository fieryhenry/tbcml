import tbcml


class CustomStage(tbcml.Stage):
    def __init__(
        self,
        parent_map: tbcml.Map,
        stage_index: int,
    ):
        super().__init__(
            name="Epic Stage",
            base_health=1200000,
            parent_map=parent_map,  # used to sync data
            width=4000,
            max_enemy_count=1000,
            max_production_frames=0,
            min_production_frames=0,
        )
        # text name is only used for the Post to SNS feature i'm pretty sure, actual stage names are all stored as images annoyingly
        self.sync(stage_index)  # used to sync data with the original stage
        self.get_story_map_name_img().flip_x_coords()
        self.get_in_battle_img().flip_y_coords()

        for enemy in self.stage_csv_data.get_stage_enemy_data():
            enemy.spawn_base_percent = 100
            enemy.start_frame = 0
            enemy.max_enemy_count = -1
            enemy.min_spawn_interval = 0
            enemy.max_spawn_interval = 0
            enemy.enemy_id = 18  # assassin bear
            enemy.magnification = 100

        info = tbcml.StageOptionInfo(
            star_id=0, rarity_restriction_bit_mask=0b001001, deploy_limit=2000
        )
        info2 = tbcml.StageOptionInfo(star_id=1, rarity_restriction_bit_mask=0b000011)
        self.get_stage_option_info().append(info)
        self.get_stage_option_info().append(info2)


class CustomMap(tbcml.Map):
    def __init__(self, game_data: tbcml.GamePacks):
        super().__init__(map_index=0, map_type=tbcml.MapType.CHALLENGE)
        self.read(game_data)

        stage_id = 0
        self.set_stage(stage_id, CustomStage(parent_map=self, stage_index=stage_id))
        self.get_map_name_img().flip_x_coords()


loader = tbcml.ModLoader("en", "13.1.1")
loader.initialize_apk()

mod = tbcml.Mod()

mod.add_modification(CustomMap(loader.get_game_packs()))
