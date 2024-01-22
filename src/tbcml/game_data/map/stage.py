from dataclasses import field
import enum
from typing import Optional
import tbcml

from marshmallow_dataclass import dataclass

from tbcml.io.csv_fields import IntCSVField, BoolCSVField


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

    def get_stage_csv(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "MapType",
        map_index: Optional[int] = None,
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = map_type.get_stage_csv_file_name(stage_index, map_index)
        return file_name, game_data.get_csv(file_name)

    def apply(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "MapType",
        map_index: Optional[int] = None,
    ):
        self.apply_stage_csv(game_data, stage_index, map_type, map_index)

    def apply_stage_csv(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "MapType",
        map_index: Optional[int] = None,
    ):
        file_name, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None:
            return
        self.stage_csv_data.apply_csv(csv)

        return game_data.set_csv(file_name, csv)

    def read_stage_csv(
        self,
        game_data: "tbcml.GamePacks",
        stage_index: int,
        map_type: "MapType",
        map_index: Optional[int] = None,
    ) -> bool:
        _, csv = self.get_stage_csv(game_data, stage_index, map_type, map_index)
        if csv is None:
            return False
        self.stage_csv_data.read_csv(csv)
        return True


class MapType(enum.Enum):
    EMPIRE_OF_CATS = enum.auto()
    INTO_THE_FUTURE = enum.auto()
    CATS_OF_THE_COSMOS = enum.auto()
    STORIES_OF_LEGEND = enum.auto()
    REGULAR_EVENT = enum.auto()
    COLLAB = enum.auto()
    EXTRA = enum.auto()
    DOJO_RANKING = enum.auto()
    DOJO_CATCLAW = enum.auto()
    TOWER = enum.auto()
    CHALLENGE = enum.auto()
    UNCANNY_LEGEND = enum.auto()
    DRINK = enum.auto()
    OUTBREAKS = enum.auto()
    GAUNTLET = enum.auto()
    ENGIMA = enum.auto()
    COLLAB_GAUNTLET = enum.auto()
    BEHEMOTH = enum.auto()
    AKU = enum.auto()
    LABYRINTH = enum.auto()
    ZERO_LEGENDS = enum.auto()

    def get_stage_csv_file_name(
        self,
        stage_index: int,
        map_index: Optional[int] = None,
    ) -> str:
        stage_index_pad_2 = str(stage_index).zfill(2)
        if self == MapType.EMPIRE_OF_CATS:
            return f"stage{stage_index_pad_2}.csv"

        if map_index is None:
            raise ValueError("Map index must be provided for this map type")

        map_index_pad_3 = str(map_index).zfill(3)
        if self == MapType.INTO_THE_FUTURE:
            map_str = str(map_index + 4).zfill(2)
            return f"stageItF{map_str}_{stage_index_pad_2}.csv"
        if self == MapType.CATS_OF_THE_COSMOS:
            map_str = str(map_index + 7).zfill(2)
            return f"stageSpace{map_str}_{stage_index_pad_2}.csv"

        map_type_str = None
        if self == MapType.AKU:
            map_type_str = "DM"
        if self == MapType.EXTRA:
            map_type_str = "EX"
        if self == MapType.LABYRINTH:
            map_type_str = "L"
        if self == MapType.GAUNTLET:
            map_type_str = "RA"
        if self == MapType.DRINK:
            map_type_str = "RB"
        if self == MapType.COLLAB:
            map_type_str = "RC"
        if self == MapType.COLLAB_GAUNTLET:
            map_type_str = "RCA"
        if self == MapType.ENGIMA:
            map_type_str = "RH"
        if self == MapType.CHALLENGE:
            map_type_str = "RM"
        if self == MapType.STORIES_OF_LEGEND:
            map_type_str = "RN"
        if self == MapType.UNCANNY_LEGEND:
            map_type_str = "RNA"
        if self == MapType.ZERO_LEGENDS:
            map_type_str = "RND"
        if self == MapType.BEHEMOTH:
            map_type_str = "RQ"
        if self == MapType.DOJO_RANKING:
            map_type_str = "RR"
        if self == MapType.REGULAR_EVENT:
            map_type_str = "RS"
        if self == MapType.DOJO_CATCLAW:
            map_type_str = "RT"
        if self == MapType.TOWER:
            map_type_str = "RV"
        if self == MapType.OUTBREAKS:
            map_type_str = "Z"

        if map_type_str is None:
            raise ValueError(f"Map type {self} not implemented")

        return f"stage{map_type_str}{map_index_pad_3}_{stage_index_pad_2}.csv"


@dataclass
class Map(tbcml.Modification):
    map_index: int
    map_type: MapType
    stages: list[Stage] = field(default_factory=list)
    modification_type: tbcml.ModificationType = tbcml.ModificationType.MAP

    def __post_init__(self):
        Map.Schema()

    def get_stage(self, index: int) -> Optional[Stage]:
        if index < 0 or index >= len(self.stages):
            return None
        return self.stages[index]

    def apply_stages(self, game_data: "tbcml.GamePacks"):
        for i, stage in enumerate(self.stages):
            stage.apply_stage_csv(game_data, i, self.map_type, self.map_index)

    def read_stages(self, game_data: "tbcml.GamePacks"):
        i = 0
        self.stages = []
        while True:
            stage = Stage()
            success = stage.read_stage_csv(game_data, i, self.map_type, self.map_index)
            if not success:
                break
            self.stages.append(stage)
            i += 1

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_stages(game_data)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_stages(game_data)
