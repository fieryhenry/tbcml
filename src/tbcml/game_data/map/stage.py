from __future__ import annotations

import copy
from dataclasses import field

from marshmallow_dataclass import dataclass

import tbcml
from tbcml.io.csv_fields import BoolCSVField, IntCSVField, StringCSVField


@dataclass
class StageOptionInfo:
    star_id: int | None = None
    rarity_restriction_bit_mask: int | None = None
    """Bits to restrict the rarity allowed. Least significant bit is normal:
    legend,uber,super,rare,special,normal
    e.g
    0b001001 = allow super and normal 
    """
    deploy_limit: int | None = None
    slot_formation_limit: int | None = None
    deploy_cost_limit_lower: int | None = None
    deploy_cost_limit_upper: int | None = None
    group_id: int | None = None

    def __post_init__(self):
        self._csv__star_id = IntCSVField(col_index=1)
        self._csv__rarity_restriction_bit_mask = IntCSVField(col_index=3)
        self._csv__deploy_limit = IntCSVField(col_index=4)
        self._csv__slot_formation_limit = IntCSVField(col_index=5)
        self._csv__deploy_cost_limit_lower = IntCSVField(col_index=6)
        self._csv__deploy_cost_limit_upper = IntCSVField(col_index=7)
        self._csv__group_id = IntCSVField(col_index=8)

    @staticmethod
    def find_indexes(
        map_id: int,
        map_type: tbcml.MapType,
        csv: tbcml.CSV,
    ) -> list[int] | None:
        abs_map_id = map_type.get_map_abs_index(map_id)
        if abs_map_id is None:
            return None
        indexes: list[int] = []
        for i in range(1, len(csv.lines)):
            csv.index = i
            if csv.get_int(0) == map_id:
                indexes.append(i)
        if not indexes:
            return None
        return indexes

    def apply_csv(
        self,
        csv: tbcml.CSV,
        index: int,
    ):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False, length=9)

    def read_csv(
        self,
        csv: tbcml.CSV,
        index: int,
    ):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class NonStoryStageInfo:
    castle_type: int | None = None
    no_continues: bool | None = None
    extra_stage_probability: int | None = None
    extra_stage_map_id: int | None = None
    extra_stage_stage_index: int | None = None
    unknown: int | None = None

    def __post_init__(self):
        self._csv__castle_type = IntCSVField(col_index=0, row_index=0)
        self._csv__no_continues = BoolCSVField(col_index=1, row_index=0)
        self._csv__extra_stage_probability = IntCSVField(col_index=2, row_index=0)
        self._csv__extra_stage_map_id = IntCSVField(col_index=3, row_index=0)
        self._csv__extra_stage_stage_index = IntCSVField(col_index=4, row_index=0)
        self._csv__unknown = IntCSVField(col_index=5, row_index=0)

    def apply_csv(self, csv: tbcml.CSV):
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, csv: tbcml.CSV):
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class StageInfo:
    width: int | None = None
    base_health: int | None = None
    min_production_frames: int | None = None
    max_production_frames: int | None = None
    background_id: int | None = None
    max_enemy_count: int | None = None
    castle_enemy_id: int | None = None
    trial_mode_duration_mins: int | None = None
    unknown_1: int | None = None
    unknown_2: int | None = None

    def __post_init__(self):
        self._csv__width = IntCSVField(col_index=0)
        self._csv__base_health = IntCSVField(col_index=1)
        self._csv__min_production_frames = IntCSVField(col_index=2)
        self._csv__max_production_frames = IntCSVField(col_index=3)
        self._csv__background_id = IntCSVField(col_index=4)
        self._csv__max_enemy_count = IntCSVField(col_index=5)
        self._csv__castle_enemy_id = IntCSVField(col_index=6)
        self._csv__trial_mode_duration_mins = IntCSVField(col_index=7)
        self._csv__unknown_1 = IntCSVField(col_index=8)
        self._csv__unknown_2 = IntCSVField(col_index=9)

    def apply_csv(self, index: int, csv: tbcml.CSV):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, index: int, csv: tbcml.CSV):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class StageEnemyData:
    enemy_id: int | None = None
    max_enemy_count: int | None = None
    start_frame: int | None = None
    min_spawn_interval: int | None = None
    max_spawn_interval: int | None = None
    spawn_base_percent: int | None = None
    min_z: int | None = None
    max_z: int | None = None
    boss_flag: bool | None = None
    magnification: int | None = None
    trial_score: int | None = None
    unknown_1: int | None = None
    unknown_2: int | None = None
    unknown_3: int | None = None

    def __post_init__(self):
        self._csv__enemy_id = IntCSVField(col_index=0)
        self._csv__max_enemy_count = IntCSVField(col_index=1)
        self._csv__start_frame = IntCSVField(col_index=2)
        self._csv__min_spawn_interval = IntCSVField(col_index=3)
        self._csv__max_spawn_interval = IntCSVField(col_index=4)
        self._csv__spawn_base_percent = IntCSVField(col_index=5)
        self._csv__min_z = IntCSVField(col_index=6)
        self._csv__max_z = IntCSVField(col_index=7)
        self._csv__boss_flag = BoolCSVField(col_index=8)
        self._csv__magnification = IntCSVField(col_index=9)
        self._csv__trial_score = IntCSVField(col_index=10)
        self._csv__unknown_1 = IntCSVField(col_index=11)
        self._csv__unknown_2 = IntCSVField(col_index=12)
        self._csv__unknown_3 = IntCSVField(col_index=13)

    def apply_csv(self, index: int, csv: tbcml.CSV):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, index: int, csv: tbcml.CSV):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def copy(self) -> "StageEnemyData":
        return copy.deepcopy(self)


@dataclass
class StageCSV:
    non_story_stage_info: NonStoryStageInfo | None = None
    stage_info: StageInfo | None = None
    stage_enemy_data: list[StageEnemyData] | None = None

    def get_stage_info(self) -> StageInfo:
        if self.stage_info is None:
            self.stage_info = StageInfo()
        return self.stage_info

    def get_stage_enemy_data(self) -> list[StageEnemyData]:
        if self.stage_enemy_data is None:
            self.stage_enemy_data = []
        return self.stage_enemy_data

    def apply_csv(self, csv: tbcml.CSV):
        index = 0
        if len(csv.lines[0]) < 7:
            if self.non_story_stage_info is None:
                self.non_story_stage_info = NonStoryStageInfo()
            self.non_story_stage_info.apply_csv(csv)
            index += 1

        if self.stage_info is None:
            stage_info = StageInfo()
        else:
            stage_info = self.stage_info

        stage_info.apply_csv(index, csv)
        index += 1

        for i, sed in enumerate(self.stage_enemy_data or []):
            sed.apply_csv(i + index, csv)

    def read_csv(self, csv: tbcml.CSV):
        index = 0
        if len(csv.lines[0]) < 7:
            self.non_story_stage_info = NonStoryStageInfo()
            self.non_story_stage_info.read_csv(csv)
            index += 1

        self.stage_info = StageInfo()
        self.stage_info.read_csv(index, csv)
        index += 1

        self.stage_enemy_data = []
        for i in range(index, len(csv.lines)):
            sed = StageEnemyData()
            sed.read_csv(i, csv)
            self.stage_enemy_data.append(sed)


@dataclass
class DropItem:
    probability_score: int
    item_id: int
    amount: int
    is_timed_score: bool

    def get_drop_item_type(self):
        if self.item_id >= 10000:
            return 2
        if self.item_id >= 1000:
            return 1
        return 0


@dataclass
class MapStageDataStage:
    energy: int | None = None
    xp: int | None = None
    main_music_id: int | None = None
    boss_music_hp_percentage: int | None = None
    boss_music_id: int | None = None
    drop_items: list[DropItem] | None = None
    drop_reward_type: int | None = None

    def __post_init__(self):
        self._csv__energy = IntCSVField(col_index=0)
        self._csv__xp = IntCSVField(col_index=1)
        self._csv__main_music_id = IntCSVField(col_index=2)
        self._csv__boss_music_hp_percentage = IntCSVField(col_index=3)
        self._csv__boss_music_id = IntCSVField(col_index=4)
        self._csv__drop_reward_type = IntCSVField(col_index=8)

    def read_csv(self, index: int, csv: tbcml.CSV, score_reward_stage_id: int):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

        self.drop_items = []

        drop_item_prob = IntCSVField(col_index=5)
        drop_item_id = IntCSVField(col_index=6)
        drop_item_amount = IntCSVField(col_index=7)

        drop_item_prob.read_from_csv(csv, -1)
        drop_item_id.read_from_csv(csv, -1)
        drop_item_amount.read_from_csv(csv, -1)

        drop_item = DropItem(
            drop_item_prob.get(),
            drop_item_id.get(),
            drop_item_amount.get(),
            is_timed_score=False,
        )
        self.drop_items.append(drop_item)

        if self.drop_reward_type is None:
            return

        is_timed = (
            csv.get_int(15) == 1 and score_reward_stage_id != -1
        ) and self.drop_reward_type > -3

        start_index = 9
        if is_timed:
            start_index = 16

        index = start_index
        while True:
            if csv.get_int(index, -1) == -1:
                break
            drop_item_prob.col_index = index
            drop_item_id.col_index = index + 1
            drop_item_amount.col_index = index + 2

            drop_item_prob.read_from_csv(csv, -1)
            drop_item_id.read_from_csv(csv, -1)
            drop_item_amount.read_from_csv(csv, -1)

            drop_item = DropItem(
                drop_item_prob.get(),
                drop_item_id.get(),
                drop_item_amount.get(),
                is_timed_score=is_timed,
            )

            self.drop_items.append(drop_item)
            index += 3

    def apply_csv(
        self,
        index: int,
        csv: tbcml.CSV,
        score_reward_stage_id: int,
        warn: bool = True,
    ):
        csv.index = index

        is_timed = (
            self.drop_items
            and len(self.drop_items) >= 2
            and self.drop_items[1].is_timed_score
        )
        if is_timed:
            if score_reward_stage_id == -1 and warn:
                print(
                    "WARNING: map score_reward_stage_id == -1, timed scores may not appear!"
                )

        tbcml.Modification.apply_csv_fields(
            self, csv, remove_others=bool(self.drop_items)
        )

        if not self.drop_items:
            csv.set_str(-1, 5)
            return

        drop_item_prob = IntCSVField(col_index=5)
        drop_item_id = IntCSVField(col_index=6)
        drop_item_amount = IntCSVField(col_index=7)

        drop_item = self.drop_items[0]

        drop_item_prob.set(drop_item.probability_score)
        drop_item_id.set(drop_item.item_id)
        drop_item_amount.set(drop_item.amount)

        drop_item_prob.write_to_csv(csv)
        drop_item_id.write_to_csv(csv)
        drop_item_amount.write_to_csv(csv)

        if self.drop_reward_type is None:
            csv.set_str(-1, 8)
            return

        start_index = 9
        if is_timed:
            csv.set_str(1, 15)
            for i in range(9, 15):
                csv.set_str(-2, i)
            start_index = 16

        index = start_index

        for item in self.drop_items[1:]:
            drop_item_prob.col_index = index
            drop_item_id.col_index = index + 1
            drop_item_amount.col_index = index + 2

            drop_item_prob.set(item.probability_score)
            drop_item_id.set(item.item_id)
            drop_item_amount.set(item.amount)

            drop_item_prob.write_to_csv(csv)
            drop_item_id.write_to_csv(csv)
            drop_item_amount.write_to_csv(csv)

            index += 3

        csv.set_str(-1, index)


@dataclass
class Stage:
    stage_csv_data: StageCSV = field(default_factory=StageCSV)
    map_stage_data_stage: MapStageDataStage | None = None
    parent_map: tbcml.Map | None = None

    name: str | None = None
    name_img: tbcml.BCImage | None = None
    story_map_name_img: tbcml.BCImage | None = None

    stage_option_info: list[StageOptionInfo] | None = None

    width: int | None = None
    base_health: int | None = None
    min_production_frames: int | None = None
    max_production_frames: int | None = None
    background_id: int | None = None
    max_enemy_count: int | None = None
    castle_enemy_id: int | None = None
    trial_mode_duration_mins: int | None = None
    unknown_1: int | None = None
    unknown_2: int | None = None

    class Meta:
        fields = [
            "stage_csv_data",
            "name",
            "name_img",
            "story_map_name_img",
            "stage_option_info",
        ]

    def get_stage_option_info(self) -> list[StageOptionInfo]:
        if self.stage_option_info is None:
            self.stage_option_info = []
        return self.stage_option_info

    def read_map_stage_data_csv(
        self,
        index: int,
        csv: tbcml.CSV,
        score_reward_stage_id: int,
    ):
        self.map_stage_data_stage = MapStageDataStage()
        self.map_stage_data_stage.read_csv(index, csv, score_reward_stage_id)

    def apply_map_stage_data_csv(
        self,
        index: int,
        csv: tbcml.CSV,
        score_reward_stage_id: int,
    ):
        if self.map_stage_data_stage is None:
            return
        self.map_stage_data_stage.apply_csv(index, csv, score_reward_stage_id)

    def get_original_stage(self, index: int):
        if self.parent_map is None:
            return None
        original_stage = self.parent_map.get_stage(index)
        if original_stage is None:
            return None
        return original_stage

    def sync(self, index: int):
        original_stage = self.get_original_stage(index)
        if original_stage is None:
            return

        original_stage = copy.deepcopy(original_stage)

        tbcml.Modification.sync(self, original_stage)
        self.update_stage_info_vars()

    def get_in_battle_img(self) -> tbcml.BCImage:
        if self.name_img is None:
            self.name_img = tbcml.BCImage.from_size(256, 64)
        return self.name_img

    def get_story_map_name_img(self) -> tbcml.BCImage:
        if self.story_map_name_img is None:
            self.story_map_name_img = tbcml.BCImage.from_size(224, 45)
        return self.story_map_name_img

    def __post_init__(self):
        self.stage_csv_copy = copy.deepcopy(self.stage_csv_data)
        self.apply_stage_info_vars()

    def apply_stage_info_vars(self):
        if self.stage_csv_data.stage_info is None:
            self.stage_csv_data.stage_info = StageInfo()
        self.stage_csv_data.stage_info.width = self.width
        self.stage_csv_data.stage_info.base_health = self.base_health
        self.stage_csv_data.stage_info.min_production_frames = (
            self.min_production_frames
        )
        self.stage_csv_data.stage_info.max_production_frames = (
            self.max_production_frames
        )
        self.stage_csv_data.stage_info.background_id = self.background_id
        self.stage_csv_data.stage_info.max_enemy_count = self.max_enemy_count
        self.stage_csv_data.stage_info.castle_enemy_id = self.castle_enemy_id
        self.stage_csv_data.stage_info.trial_mode_duration_mins = (
            self.trial_mode_duration_mins
        )
        self.stage_csv_data.stage_info.unknown_1 = self.unknown_1
        self.stage_csv_data.stage_info.unknown_2 = self.unknown_2

    def update_stage_info_vars(self):
        if self.stage_csv_data.stage_info is None:
            return
        self.width = self.stage_csv_data.stage_info.width
        self.base_health = self.stage_csv_data.stage_info.base_health
        self.min_production_frames = (
            self.stage_csv_data.stage_info.min_production_frames
        )
        self.max_production_frames = (
            self.stage_csv_data.stage_info.max_production_frames
        )
        self.background_id = self.stage_csv_data.stage_info.background_id
        self.max_enemy_count = self.stage_csv_data.stage_info.max_enemy_count
        self.castle_enemy_id = self.stage_csv_data.stage_info.castle_enemy_id
        self.trial_mode_duration_mins = (
            self.stage_csv_data.stage_info.trial_mode_duration_mins
        )
        self.unknown_1 = self.stage_csv_data.stage_info.unknown_1
        self.unknown_2 = self.stage_csv_data.stage_info.unknown_2

    def get_map_type(self) -> tbcml.MapType | None:
        if self.parent_map is None:
            return None
        return self.parent_map.map_type

    def get_map_index(self) -> int | None:
        if self.parent_map is None:
            return None
        return self.parent_map.map_index

    def get_stage_csv(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType,
        map_index: int | None,
    ) -> tuple[str | None, tbcml.CSV | None]:
        file_name = map_type.get_stage_csv_file_name(stage_index, map_index)
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(file_name)

    def get_stage_name_img(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType,
        map_index: int | None,
    ):
        file_name = map_type.get_stage_name_img_file_name(
            map_index, stage_index, game_data.get_lang()
        )
        if file_name is None:
            return None, None
        return file_name, game_data.get_img(file_name)

    @staticmethod
    def convert_main_story_stage_id(id: int) -> int | None:
        if id in [46, 47]:
            return id
        new_id = 45 - id
        if new_id < 0:
            return None
        return new_id

    def apply_stage_name_csv(
        self,
        csv: tbcml.CSV,
        map_type: tbcml.MapType,
        map_index: int,
        stage_index: int,
    ):
        if self.name is None:
            return
        col_index = stage_index
        row_index = map_index
        if map_type.is_main_story():
            row_index = Stage.convert_main_story_stage_id(stage_index)
            if row_index is None:
                return
            col_index = 0

        csv_name = StringCSVField(col_index=col_index, row_index=row_index)
        csv_name.set(self.name)
        csv_name.write_to_csv(csv)

    def apply_stage_name_img(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType,
        map_index: int | None,
    ):
        if self.name_img is None:
            return
        file_name = map_type.get_stage_name_img_file_name(
            map_index, stage_index, game_data.get_lang()
        )
        if file_name is None:
            return
        game_data.set_img(file_name, self.name_img)

    def read_stage_name_csv(
        self,
        csv: tbcml.CSV,
        map_type: tbcml.MapType,
        map_index: int,
        stage_index: int,
    ):
        col_index = stage_index
        row_index = map_index
        if map_type.is_main_story():
            row_index = Stage.convert_main_story_stage_id(stage_index)
            if row_index is None:
                return
            col_index = 0

        csv_name = StringCSVField(col_index=col_index, row_index=row_index)
        csv_name.read_from_csv(csv)
        self.name = csv_name.value

    def read_stage_name_img(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType | None = None,
        map_index: int | None = None,
    ):
        if map_type is None:
            map_type = self.get_map_type()
        if map_index is None:
            map_index = self.get_map_index()

        if map_type is None:
            raise ValueError("map_type cannot be None!")
        _, img = self.get_stage_name_img(game_data, stage_index, map_type, map_index)
        if img is None:
            return
        self.name_img = img

    def apply(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType | None = None,
        map_index: int | None = None,
    ):
        if map_type is None:
            map_type = self.get_map_type()
        if map_index is None:
            map_index = self.get_map_index()

        if map_type is None:
            raise ValueError("map_type cannot be None!")

        self.apply_stage_csv(game_data, stage_index, map_type, map_index)
        self.apply_stage_name_img(game_data, stage_index, map_type, map_index)

    def read(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType | None = None,
        map_index: int | None = None,
    ) -> bool:
        if map_type is None:
            map_type = self.get_map_type()
        if map_index is None:
            map_index = self.get_map_index()

        if map_type is None:
            raise ValueError("map_type cannot be None!")

        success = self.read_stage_csv(game_data, stage_index, map_type, map_index)
        self.read_stage_name_img(game_data, stage_index, map_type, map_index)
        return success

    def apply_stage_csv(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType,
        map_index: int | None = None,
    ):
        self.apply_stage_info_vars()
        file_name, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None or file_name is None:
            return
        self.stage_csv_data.apply_csv(csv)

        return game_data.set_csv(file_name, csv)

    def read_stage_csv(
        self,
        game_data: tbcml.GamePacks,
        stage_index: int,
        map_type: tbcml.MapType,
        map_index: int | None = None,
    ) -> bool:
        _, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None:
            return False
        self.stage_csv_data.read_csv(csv)
        self.update_stage_info_vars()
        return True

    def pre_to_json(self):
        self.apply_stage_info_vars()
        if self.name_img is not None:
            self.name_img.save_b64()
        if self.story_map_name_img is not None:
            self.story_map_name_img.save_b64()

    def post_from_json(self):
        self.stage_csv_data = self.stage_csv_copy
        self.update_stage_info_vars()
