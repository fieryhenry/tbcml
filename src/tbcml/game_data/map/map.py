import enum
from dataclasses import field
from typing import Optional

from marshmallow_dataclass import dataclass

import tbcml


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
    LEGEND_QUEST = enum.auto()

    def is_main_story(self) -> bool:
        return self in [
            MapType.EMPIRE_OF_CATS,
            MapType.INTO_THE_FUTURE,
            MapType.CATS_OF_THE_COSMOS,
        ]

    def get_stage_name_csv_file_name(self, lang: str) -> Optional[str]:
        if self == MapType.EMPIRE_OF_CATS:
            return f"StageName0_{lang}.csv"
        if self == MapType.INTO_THE_FUTURE:
            return f"StageName1_{lang}.csv"
        if self == MapType.CATS_OF_THE_COSMOS:
            return f"StageName2_{lang}.csv"

        map_type_str = None
        if self == MapType.AKU:
            map_type_str = "DM"
        elif self == MapType.LABYRINTH:
            map_type_str = "L"
        elif self == MapType.GAUNTLET:
            map_type_str = "RA"
        elif self == MapType.DRINK:
            map_type_str = "RB"
        elif self == MapType.COLLAB:
            map_type_str = "RC"
        elif self == MapType.COLLAB_GAUNTLET:
            map_type_str = "RCA"
        elif self == MapType.LEGEND_QUEST:
            map_type_str = "RD"
        elif self == MapType.EXTRA:
            map_type_str = "RE"
        elif self == MapType.ENGIMA:
            map_type_str = "RH"
        elif self == MapType.CHALLENGE:
            map_type_str = "RM"
        elif self == MapType.STORIES_OF_LEGEND:
            map_type_str = "RN"
        elif self == MapType.UNCANNY_LEGEND:
            map_type_str = "RNA"
        elif self == MapType.ZERO_LEGENDS:
            map_type_str = "RND"
        elif self == MapType.BEHEMOTH:
            map_type_str = "RQ"
        elif self == MapType.DOJO_RANKING:
            map_type_str = "RR"
        elif self == MapType.REGULAR_EVENT:
            map_type_str = "RS"
        elif self == MapType.DOJO_CATCLAW:
            map_type_str = "RT"
        elif self == MapType.TOWER:
            map_type_str = "RV"

        if map_type_str is None:
            return None

        return f"StageName_{map_type_str}_{lang}.csv"

    def get_stage_csv_file_name(
        self,
        stage_index: int,
        map_index: Optional[int] = None,
    ) -> Optional[str]:
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
        elif self == MapType.EXTRA:
            map_type_str = "EX"
        elif self == MapType.LABYRINTH:
            map_type_str = "L"
        elif self == MapType.GAUNTLET:
            map_type_str = "RA"
        elif self == MapType.DRINK:
            map_type_str = "RB"
        elif self == MapType.COLLAB:
            map_type_str = "RC"
        elif self == MapType.COLLAB_GAUNTLET:
            map_type_str = "RCA"
        elif self == MapType.ENGIMA:
            map_type_str = "RH"
        elif self == MapType.CHALLENGE:
            map_type_str = "RM"
        elif self == MapType.STORIES_OF_LEGEND:
            map_type_str = "RN"
        elif self == MapType.UNCANNY_LEGEND:
            map_type_str = "RNA"
        elif self == MapType.ZERO_LEGENDS:
            map_type_str = "RND"
        elif self == MapType.BEHEMOTH:
            map_type_str = "RQ"
        elif self == MapType.DOJO_RANKING:
            map_type_str = "RR"
        elif self == MapType.REGULAR_EVENT:
            map_type_str = "RS"
        elif self == MapType.DOJO_CATCLAW:
            map_type_str = "RT"
        elif self == MapType.TOWER:
            map_type_str = "RV"
        elif self == MapType.OUTBREAKS:
            map_type_str = "Z"

        if map_type_str is None:
            return None

        return f"stage{map_type_str}{map_index_pad_3}_{stage_index_pad_2}.csv"

    def get_map_img_code(self) -> Optional[str]:
        if self == MapType.EMPIRE_OF_CATS:
            return "ec"
        if self == MapType.INTO_THE_FUTURE:
            return "wc"
        if self == MapType.CATS_OF_THE_COSMOS:
            return "sc"

        if self == MapType.AKU:
            return "dm"
        if self == MapType.LABYRINTH:
            return "l"
        if self == MapType.GAUNTLET:
            return "a"
        if self == MapType.DRINK:
            return "b"
        if self == MapType.COLLAB:
            return "c"
        if self == MapType.COLLAB_GAUNTLET:
            return "ca"
        if self == MapType.LEGEND_QUEST:
            return "d"
        if self == MapType.EXTRA:
            return "ex"
        if self == MapType.ENGIMA:
            return "h"
        if self == MapType.CHALLENGE:
            return "m"
        if self == MapType.STORIES_OF_LEGEND:
            return "n"
        if self == MapType.UNCANNY_LEGEND:
            return "na"
        if self == MapType.ZERO_LEGENDS:
            return "nd"
        if self == MapType.BEHEMOTH:
            return "q"
        if self == MapType.DOJO_RANKING:
            return "r"
        if self == MapType.REGULAR_EVENT:
            return "s"
        if self == MapType.DOJO_CATCLAW:
            return "t"
        if self == MapType.TOWER:
            return "v"

        return None

    def get_stage_name_img_file_name(
        self,
        map_index: Optional[int],
        stage_index: int,
        lang: str,
    ) -> Optional[str]:
        img_code = self.get_map_img_code()
        if img_code is None:
            return None
        if self.is_main_story():
            stage_index = tbcml.Stage.convert_main_story_stage_id(stage_index)
            stage_index_str = str(stage_index).zfill(3)
            return f"{img_code}{stage_index_str}_n_{lang}.png"

        if map_index is None:
            raise ValueError("Map index cannot be None!")

        map_index_str = str(map_index).zfill(3)
        stage_index_str = str(stage_index).zfill(2)
        return f"mapsn{map_index_str}_{stage_index_str}_{img_code}_{lang}.png"


@dataclass
class Map(tbcml.Modification):
    map_index: int
    map_type: MapType
    stages: list["tbcml.Stage"] = field(default_factory=list)
    modification_type: tbcml.ModificationType = tbcml.ModificationType.MAP

    def __post_init__(self):
        Map.Schema()

    def set_stage(self, index: int, stage: "tbcml.Stage"):
        self.stages[index] = stage

    def get_stage_name_csv(
        self,
        game_data: "tbcml.GamePacks",
    ) -> tuple[Optional[str], Optional["tbcml.CSV"]]:
        file_name = self.map_type.get_stage_name_csv_file_name(game_data.get_lang())
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(
            file_name, country_code=game_data.country_code
        )

    def apply_stage_name_csv(self, game_data: "tbcml.GamePacks"):
        if not self.stages:
            return
        file_name, csv = self.get_stage_name_csv(game_data)
        if file_name is None or csv is None:
            return

        for i, stage in enumerate(self.stages):
            stage.apply_stage_name_csv(csv, self.map_type, self.map_index, i)

        return game_data.set_csv(file_name, csv)

    def read_stage_name_csv(
        self, game_data: "tbcml.GamePacks", create_new_stages: bool = True
    ):
        _, csv = self.get_stage_name_csv(game_data)
        if csv is None:
            return

        row = self.map_index
        total_stages = len(csv.get_line(row))
        for i in range(total_stages):
            stage = self.get_stage(i)
            if stage is None:
                if create_new_stages:
                    stage = tbcml.Stage()
                    self.stages.append(stage)
                else:
                    continue
            stage.read_stage_name_csv(csv, self.map_type, self.map_index, i)

    def get_stage(self, index: int) -> Optional["tbcml.Stage"]:
        if index < 0 or index >= len(self.stages):
            return None
        return self.stages[index]

    def apply_stages(self, game_data: "tbcml.GamePacks"):
        for i, stage in enumerate(self.stages):
            stage.apply(game_data, i, self.map_type, self.map_index)

    def read_stages(self, game_data: "tbcml.GamePacks"):
        i = 0
        self.stages = []
        while True:
            stage = tbcml.Stage()
            success = stage.read(game_data, i, self.map_type, self.map_index)
            if not success:
                break
            self.stages.append(stage)
            i += 1

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_stages(game_data)
        self.apply_stage_name_csv(game_data)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_stages(game_data)
        self.read_stage_name_csv(game_data)

    def pre_to_json(self) -> None:
        for stage in self.stages:
            stage.pre_to_json()

    def post_from_json(self) -> None:
        for stage in self.stages:
            stage.post_from_json()
