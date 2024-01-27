import copy
from dataclasses import field
from typing import Optional

from marshmallow_dataclass import dataclass

import tbcml
from tbcml.io.csv_fields import BoolCSVField, IntCSVField, StringCSVField


@dataclass
class NonStoryStageInfo:
    castle_type: Optional[int] = None
    no_continues: Optional[bool] = None
    extra_stage_probability: Optional[int] = None
    extra_stage_map_id: Optional[int] = None
    extra_stage_stage_index: Optional[int] = None
    unknown: Optional[int] = None

    def __post_init__(self):
        self.csv__castle_type = IntCSVField(col_index=0, row_index=0)
        self.csv__no_continues = BoolCSVField(col_index=1, row_index=0)
        self.csv__extra_stage_probability = IntCSVField(col_index=2, row_index=0)
        self.csv__extra_stage_map_id = IntCSVField(col_index=3, row_index=0)
        self.csv__extra_stage_stage_index = IntCSVField(col_index=4, row_index=0)
        self.csv__unknown = IntCSVField(col_index=5, row_index=0)

    def apply_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class StageInfo:
    width: Optional[int] = None
    base_health: Optional[int] = None
    min_production_frames: Optional[int] = None
    max_production_frames: Optional[int] = None
    background_id: Optional[int] = None
    max_enemy_count: Optional[int] = None
    castle_enemy_id: Optional[int] = None
    trial_mode_limit: Optional[int] = None
    unknown_1: Optional[int] = None
    unknown_2: Optional[int] = None

    def __post_init__(self):
        self.csv__width = IntCSVField(col_index=0)
        self.csv__base_health = IntCSVField(col_index=1)
        self.csv__min_production_frames = IntCSVField(col_index=2)
        self.csv__max_production_frames = IntCSVField(col_index=3)
        self.csv__background_id = IntCSVField(col_index=4)
        self.csv__max_enemy_count = IntCSVField(col_index=5)
        self.csv__castle_enemy_id = IntCSVField(col_index=6)
        self.csv__trial_mode_limit = IntCSVField(col_index=7)
        self.csv__unknown_1 = IntCSVField(col_index=8)
        self.csv__unknown_2 = IntCSVField(col_index=9)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class StageEnemyData:
    enemy_id: Optional[int] = None
    max_enemy_count: Optional[int] = None
    start_frame: Optional[int] = None
    min_spawn_interval: Optional[int] = None
    max_spawn_interval: Optional[int] = None
    spawn_base_percent: Optional[int] = None
    min_z: Optional[int] = None
    max_z: Optional[int] = None
    boss_flag: Optional[bool] = None
    magnification: Optional[int] = None
    trial_score: Optional[int] = None
    unknown_1: Optional[int] = None
    unknown_2: Optional[int] = None
    unknown_3: Optional[int] = None

    def __post_init__(self):
        self.csv__enemy_id = IntCSVField(col_index=0)
        self.csv__max_enemy_count = IntCSVField(col_index=1)
        self.csv__start_frame = IntCSVField(col_index=2)
        self.csv__min_spawn_interval = IntCSVField(col_index=3)
        self.csv__max_spawn_interval = IntCSVField(col_index=4)
        self.csv__spawn_base_percent = IntCSVField(col_index=5)
        self.csv__min_z = IntCSVField(col_index=6)
        self.csv__max_z = IntCSVField(col_index=7)
        self.csv__boss_flag = BoolCSVField(col_index=8)
        self.csv__magnification = IntCSVField(col_index=9)
        self.csv__trial_score = IntCSVField(col_index=10)
        self.csv__unknown_1 = IntCSVField(col_index=11)
        self.csv__unknown_2 = IntCSVField(col_index=12)
        self.csv__unknown_3 = IntCSVField(col_index=13)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class StageCSV:
    non_story_stage_info: Optional[NonStoryStageInfo] = None
    stage_info: StageInfo = field(default_factory=StageInfo)
    stage_enemy_data: list[StageEnemyData] = field(default_factory=list)

    def apply_csv(self, csv: "tbcml.CSV"):
        index = 0
        if self.non_story_stage_info is not None:
            self.non_story_stage_info.apply_csv(csv)
            index += 1

        self.stage_info.apply_csv(index, csv)
        index += 1

        for i, sed in enumerate(self.stage_enemy_data):
            sed.apply_csv(i + index, csv)

    def read_csv(self, csv: "tbcml.CSV"):
        index = 0
        if len(csv.lines[0]) < 7:
            self.non_story_stage_info = NonStoryStageInfo()
            self.non_story_stage_info.read_csv(csv)
            index += 1

        self.stage_info.read_csv(index, csv)
        index += 1

        self.stage_enemy_data = []
        for i in range(index, len(csv.lines)):
            sed = StageEnemyData()
            sed.read_csv(i, csv)
            self.stage_enemy_data.append(sed)


@dataclass
class Stage:
    stage_csv_data: StageCSV = field(default_factory=StageCSV)
    parent_map: Optional["tbcml.Map"] = None

    name: Optional[str] = None
    in_battle_name_img: Optional["tbcml.BCImage"] = None

    base_health: Optional[int] = None
    min_production_frames: Optional[int] = None
    max_production_frames: Optional[int] = None
    background_id: Optional[int] = None
    max_enemy_count: Optional[int] = None
    castle_enemy_id: Optional[int] = None
    trial_mode_limit: Optional[int] = None
    unknown_1: Optional[int] = None
    unknown_2: Optional[int] = None

    class Meta:
        fields = ["stage_csv_data", "name", "in_battle_name_img"]

    def get_in_battle_img(self) -> "tbcml.BCImage":
        if self.in_battle_name_img is None:
            self.in_battle_name_img = tbcml.BCImage.from_size(256, 64)
        return self.in_battle_name_img

    def __post_init__(self):
        self.stage_csv_copy = copy.deepcopy(self.stage_csv_data)
        self.apply_stage_info_vars()

    def apply_stage_info_vars(self):
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
        self.stage_csv_data.stage_info.trial_mode_limit = self.trial_mode_limit
        self.stage_csv_data.stage_info.unknown_1 = self.unknown_1
        self.stage_csv_data.stage_info.unknown_2 = self.unknown_2

    def update_stage_info_vars(self):
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
        self.trial_mode_limit = self.stage_csv_data.stage_info.trial_mode_limit
        self.unknown_1 = self.stage_csv_data.stage_info.unknown_1
        self.unknown_2 = self.stage_csv_data.stage_info.unknown_2

    def get_map_type(self) -> Optional["tbcml.MapType"]:
        if self.parent_map is None:
            return None
        return self.parent_map.map_type

    def get_map_index(self) -> Optional[int]:
        if self.parent_map is None:
            return None
        return self.parent_map.map_index

    def get_stage_csv(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "tbcml.MapType",
        map_index: Optional[int],
    ) -> tuple[Optional[str], Optional["tbcml.CSV"]]:
        file_name = map_type.get_stage_csv_file_name(stage_index, map_index)
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(file_name)

    def get_stage_name_img(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "tbcml.MapType",
        map_index: Optional[int],
    ):
        file_name = map_type.get_stage_name_img_file_name(
            map_index, stage_index, game_data.get_lang()
        )
        if file_name is None:
            return None, None
        return file_name, game_data.get_img(file_name)

    @staticmethod
    def convert_main_story_stage_id(id: int) -> int:
        if id in [46, 47]:
            return id
        return 45 - id

    def apply_stage_name_csv(
        self,
        csv: "tbcml.CSV",
        map_type: "tbcml.MapType",
        map_index: int,
        stage_index: int,
    ):
        if self.name is None:
            return
        col_index = stage_index
        row_index = map_index
        if map_type.is_main_story():
            row_index = Stage.convert_main_story_stage_id(stage_index)
            col_index = 0

        csv_name = StringCSVField(col_index=col_index, row_index=row_index)
        csv_name.set(self.name)
        csv_name.write_to_csv(csv)

    def apply_stage_name_img(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "tbcml.MapType",
        map_index: Optional[int],
    ):
        if self.in_battle_name_img is None:
            return
        file_name = map_type.get_stage_name_img_file_name(
            map_index, stage_index, game_data.get_lang()
        )
        if file_name is None:
            return
        game_data.set_img(file_name, self.in_battle_name_img)

    def read_stage_name_csv(
        self,
        csv: "tbcml.CSV",
        map_type: "tbcml.MapType",
        map_index: int,
        stage_index: int,
    ):
        col_index = stage_index
        row_index = map_index
        if map_type.is_main_story():
            row_index = Stage.convert_main_story_stage_id(stage_index)
            col_index = 0

        csv_name = StringCSVField(col_index=col_index, row_index=row_index)
        csv_name.read_from_csv(csv)
        self.name = csv_name.value

    def read_stage_name_img(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: Optional["tbcml.MapType"] = None,
        map_index: Optional[int] = None,
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
        self.in_battle_name_img = img

    def apply(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: Optional["tbcml.MapType"] = None,
        map_index: Optional[int] = None,
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
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: Optional["tbcml.MapType"] = None,
        map_index: Optional[int] = None,
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
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "tbcml.MapType",
        map_index: Optional[int] = None,
    ):
        self.apply_stage_info_vars()
        file_name, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None or file_name is None:
            return
        self.stage_csv_data.apply_csv(csv)

        return game_data.set_csv(file_name, csv)

    def read_stage_csv(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "tbcml.MapType",
        map_index: Optional[int] = None,
    ) -> bool:
        _, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None:
            return False
        self.stage_csv_data.read_csv(csv)
        self.update_stage_info_vars()
        return True

    def pre_to_json(self):
        self.apply_stage_info_vars()
        if self.in_battle_name_img is not None:
            self.in_battle_name_img.save_b64()

    def post_from_json(self):
        self.stage_csv_data = self.stage_csv_copy
        self.update_stage_info_vars()
