import enum
from dataclasses import field
from typing import Optional

from marshmallow_dataclass import dataclass

import tbcml
from tbcml.io.csv_fields import IntCSVField


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

    def get_stage_name_map_code(self) -> Optional[str]:
        if self == MapType.AKU:
            return "DM"
        if self == MapType.LABYRINTH:
            return "L"
        if self == MapType.GAUNTLET:
            return "RA"
        if self == MapType.DRINK:
            return "RB"
        if self == MapType.COLLAB:
            return "RC"
        if self == MapType.COLLAB_GAUNTLET:
            return "RCA"
        if self == MapType.LEGEND_QUEST:
            return "RD"
        if self == MapType.EXTRA:
            return "RE"
        if self == MapType.ENGIMA:
            return "RH"
        if self == MapType.CHALLENGE:
            return "RM"
        if self == MapType.STORIES_OF_LEGEND:
            return "RN"
        if self == MapType.UNCANNY_LEGEND:
            return "RNA"
        if self == MapType.ZERO_LEGENDS:
            return "RND"
        if self == MapType.BEHEMOTH:
            return "RQ"
        if self == MapType.DOJO_RANKING:
            return "RR"
        if self == MapType.REGULAR_EVENT:
            return "RS"
        if self == MapType.DOJO_CATCLAW:
            return "RT"
        if self == MapType.TOWER:
            return "RV"
        return None

    def get_map_stage_data_map_code(self) -> Optional[str]:
        if self == MapType.AKU:
            return "DM"
        if self == MapType.LABYRINTH:
            return "L"
        if self == MapType.GAUNTLET:
            return "A"
        if self == MapType.DRINK:
            return "B"
        if self == MapType.COLLAB:
            return "C"
        if self == MapType.COLLAB_GAUNTLET:
            return "CA"
        if self == MapType.LEGEND_QUEST:
            return "D"
        if self == MapType.EXTRA:
            return "RE"
        if self == MapType.ENGIMA:
            return "H"
        if self == MapType.CHALLENGE:
            return "M"
        if self == MapType.STORIES_OF_LEGEND:
            return "N"
        if self == MapType.UNCANNY_LEGEND:
            return "NA"
        if self == MapType.ZERO_LEGENDS:
            return "ND"
        if self == MapType.BEHEMOTH:
            return "Q"
        if self == MapType.DOJO_RANKING:
            return "R"
        if self == MapType.REGULAR_EVENT:
            return "S"
        if self == MapType.DOJO_CATCLAW:
            return "T"
        if self == MapType.TOWER:
            return "V"
        return None

    def get_stage_name_csv_file_name(self, lang: str) -> Optional[str]:
        if self == MapType.EMPIRE_OF_CATS:
            return f"StageName0_{lang}.csv"
        if self == MapType.INTO_THE_FUTURE:
            return f"StageName1_{lang}.csv"
        if self == MapType.CATS_OF_THE_COSMOS:
            return f"StageName2_{lang}.csv"

        map_type_str = self.get_stage_name_map_code()
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
            ind = tbcml.Stage.convert_main_story_stage_id(stage_index)
            if ind is None:
                return None
            stage_index_str = str(ind).zfill(3)
            return f"{img_code}{stage_index_str}_n_{lang}.png"

        if map_index is None:
            raise ValueError("Map index cannot be None!")

        map_index_str = str(map_index).zfill(3)
        stage_index_str = str(stage_index).zfill(2)
        return f"mapsn{map_index_str}_{stage_index_str}_{img_code}_{lang}.png"

    def get_map_name_img_file_name(
        self,
        map_index: int,
        lang: str,
    ) -> Optional[str]:
        if self.is_main_story():
            return None
        img_code = self.get_map_img_code()
        if img_code is None:
            return None
        map_index_str = str(map_index).zfill(3)
        return f"mapname{map_index_str}_{img_code}_{lang}.png"

    def get_map_texture_imgcut_name(self, lang: str):
        name = self.get_map_texture_img_name(lang)
        if name is None:
            return None

        return name.replace(".png", ".imgcut")

    def get_map_texture_img_name(
        self,
        lang: str,
    ) -> Optional[str]:
        if self == MapType.EMPIRE_OF_CATS:
            return f"img019_{lang}.png"
        if self == MapType.INTO_THE_FUTURE:
            return f"img019_w.png"
        if self == MapType.CATS_OF_THE_COSMOS:
            return f"img019_space.png"
        return None

    def get_map_stage_data_csv_file_name(self, map_index: int) -> Optional[str]:
        map_type_str = self.get_map_stage_data_map_code()
        if map_type_str is None:
            return None

        map_index_str = str(map_index).zfill(3)

        return f"MapStageData{map_type_str}_{map_index_str}.csv"


@dataclass
class MapStageDataInfo:
    map_number: Optional[int] = None
    item_reward_stage_id: Optional[int] = None
    score_reward_stage_id: Optional[int] = None
    display_condition: Optional[int] = None
    play_condition: Optional[int] = None
    display_user_rank: Optional[int] = None
    map_pattern: Optional[int] = None

    def __post_init__(self):
        self.csv__map_number = IntCSVField(col_index=0, row_index=0)
        self.csv__item_reward_stage_id = IntCSVField(col_index=0, row_index=0)
        self.csv__score_reward_stage_id = IntCSVField(col_index=0, row_index=0)
        self.csv__display_condition = IntCSVField(col_index=0, row_index=0)
        self.csv__play_condition = IntCSVField(col_index=0, row_index=0)
        self.csv__display_user_rank = IntCSVField(col_index=0, row_index=0)
        self.csv__map_pattern = IntCSVField(col_index=0, row_index=1)

    def apply_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class Map(tbcml.Modification):
    map_index: int
    map_type: MapType
    stages: list["tbcml.Stage"] = field(default_factory=list)
    map_name_img: Optional["tbcml.BCImage"] = None
    map_stage_data_info: Optional[MapStageDataInfo] = None
    modification_type: tbcml.ModificationType = tbcml.ModificationType.MAP

    def __post_init__(self):
        Map.Schema()

    def get_map_stage_data_info(self) -> "MapStageDataInfo":
        if self.map_stage_data_info is None:
            self.map_stage_data_info = MapStageDataInfo()
        return self.map_stage_data_info

    def get_map_name_img(self) -> "tbcml.BCImage":
        if self.map_name_img is None:
            self.map_name_img = tbcml.BCImage.from_size(256, 64)
        return self.map_name_img

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

    def get_map_stage_data_csv(
        self,
        game_data: "tbcml.GamePacks",
    ) -> tuple[Optional[str], Optional["tbcml.CSV"]]:
        file_name = self.map_type.get_map_stage_data_csv_file_name(self.map_index)
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(file_name)

    def get_map_texture(
        self, game_data: "tbcml.GamePacks"
    ) -> Optional["tbcml.Texture"]:
        name = self.map_type.get_map_texture_img_name(game_data.get_lang())
        if name is None:
            return None
        texture_name = self.map_type.get_map_texture_imgcut_name(game_data.get_lang())
        if texture_name is None:
            return None

        texture = tbcml.Texture()
        texture.read_from_game_file_names(game_data, name, texture_name)
        return texture

    def get_map_name_png(
        self,
        game_data: "tbcml.GamePacks",
    ) -> Optional["tbcml.BCImage"]:
        if self.map_name_img is not None:
            return self.map_name_img
        name = self.map_type.get_map_name_img_file_name(
            self.map_index, game_data.get_lang()
        )
        if name is None:
            return None
        return game_data.get_img(name)

    def apply_stage_name_csv(self, game_data: "tbcml.GamePacks"):
        if not self.stages:
            return
        file_name, csv = self.get_stage_name_csv(game_data)
        if file_name is None or csv is None:
            return

        for i, stage in enumerate(self.stages):
            stage.apply_stage_name_csv(csv, self.map_type, self.map_index, i)

        return game_data.set_csv(file_name, csv)

    def apply_map_stage_data_csv(self, game_data: "tbcml.GamePacks"):
        if not self.stages:
            return
        file_name, csv = self.get_map_stage_data_csv(game_data)
        if file_name is None or csv is None:
            return

        map_stage_data_info = self.get_map_stage_data_info()
        map_stage_data_info.apply_csv(csv)

        for i, stage in enumerate(self.stages):
            stage.apply_map_stage_data_csv(
                i + 2, csv, self.get_map_stage_data_info().score_reward_stage_id or -1
            )

        return game_data.set_csv(file_name, csv)

    def apply_map_texture(self, game_data: "tbcml.GamePacks"):
        map_texture = self.get_map_texture(game_data)
        if map_texture is None:
            return
        for i, stage in enumerate(self.stages):
            if stage.story_map_name_img is None:
                continue
            rect_id = stage.convert_main_story_stage_id(i)
            if rect_id is None:
                continue
            map_texture.set_cut(rect_id, stage.story_map_name_img)
        return map_texture.apply(game_data)

    def apply_map_name_img(self, game_data: "tbcml.GamePacks"):
        if self.map_name_img is None:
            return
        map_name_img_name = self.map_type.get_map_name_img_file_name(
            self.map_index, game_data.get_lang()
        )
        if map_name_img_name is None:
            return
        return game_data.set_img(map_name_img_name, self.map_name_img)

    def read_stage_name_csv(
        self, game_data: "tbcml.GamePacks", create_new_stages: bool = True
    ):
        _, csv = self.get_stage_name_csv(game_data)
        if csv is None:
            return

        row = self.map_index
        total_stages = len(csv.get_line(row)) - 1
        for i in range(total_stages):
            stage = self.get_stage(i)
            if stage is None:
                if create_new_stages:
                    stage = tbcml.Stage()
                    self.stages.append(stage)
                else:
                    continue
            stage.read_stage_name_csv(csv, self.map_type, self.map_index, i)

    def read_map_stage_data_csv(self, game_data: "tbcml.GamePacks"):
        _, csv = self.get_map_stage_data_csv(game_data)
        if csv is None:
            return

        map_stage_data_info = self.get_map_stage_data_info()
        map_stage_data_info.read_csv(csv)

        for i, stage in enumerate(self.stages):
            stage.read_map_stage_data_csv(
                i + 2, csv, self.get_map_stage_data_info().score_reward_stage_id or -1
            )

    def read_map_texture(self, game_data: "tbcml.GamePacks"):
        if not self.stages:
            return
        map_texture = self.get_map_texture(game_data)
        if map_texture is None:
            return
        for i, stage in enumerate(self.stages):
            rect_id = stage.convert_main_story_stage_id(i)
            if rect_id is None:
                continue
            stage.story_map_name_img = map_texture.get_cut(rect_id)

    def read_map_name_img(self, game_data: "tbcml.GamePacks"):
        map_name_img = self.get_map_name_png(game_data)
        if map_name_img is None:
            return
        self.map_name_img = map_name_img

    def get_stage(self, index: int) -> Optional["tbcml.Stage"]:
        if index < 0 or index >= len(self.stages):
            return None
        return self.stages[index]

    def apply_stages(self, game_data: "tbcml.GamePacks"):
        for i, stage in enumerate(self.stages):
            stage.apply(game_data, i, self.map_type, self.map_index)

        self.apply_map_texture(game_data)

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

        self.read_map_texture(game_data)

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_stages(game_data)
        self.apply_stage_name_csv(game_data)
        self.apply_map_name_img(game_data)
        self.apply_map_stage_data_csv(game_data)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_stages(game_data)
        self.read_stage_name_csv(game_data)
        self.read_map_name_img(game_data)
        self.read_map_stage_data_csv(game_data)

    def pre_to_json(self) -> None:
        for stage in self.stages:
            stage.pre_to_json()
        if self.map_name_img is not None:
            self.map_name_img.save_b64()

    def post_from_json(self) -> None:
        for stage in self.stages:
            stage.post_from_json()
