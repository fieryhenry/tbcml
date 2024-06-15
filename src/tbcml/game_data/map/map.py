from __future__ import annotations

import enum
from dataclasses import field

from marshmallow_dataclass import dataclass

import tbcml
from tbcml.io.csv_fields import BoolCSVField, IntCSVField, StringCSVField


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

    def get_stage_name_map_code(self) -> str | None:
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

    def get_map_stage_data_map_code(self) -> str | None:
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

    def get_stage_name_csv_file_name(self, lang: str) -> str | None:
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
        map_index: int | None = None,
    ) -> str | None:
        stage_index_pad_2 = str(stage_index).zfill(2)
        if self == MapType.EMPIRE_OF_CATS:
            return f"stage{stage_index_pad_2}.csv"

        if map_index is None:
            raise ValueError("Map index must be provided for this map type")

        map_index_pad_3 = str(map_index).zfill(3)
        if self == MapType.INTO_THE_FUTURE:
            map_str = str(map_index + 4).zfill(2)
            return f"stageW{map_str}_{stage_index_pad_2}.csv"
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

    def get_map_abs_index(self, map_index: int) -> int | None:
        if self == MapType.STORIES_OF_LEGEND:
            return 0 + map_index
        if self == MapType.REGULAR_EVENT:
            return 1000 + map_index
        if self == MapType.COLLAB:
            return 2000 + map_index
        if self == MapType.EMPIRE_OF_CATS:
            return 3000 + map_index
        if self == MapType.INTO_THE_FUTURE:
            return 3003 + map_index
        if self == MapType.CATS_OF_THE_COSMOS:
            return 3006 + map_index
        if self == MapType.EXTRA:
            return 4000 + map_index
        if self == MapType.DOJO_CATCLAW:
            return 6000 + map_index
        if self == MapType.TOWER:
            return 7000 + map_index
        if self == MapType.DOJO_RANKING:
            return 11000 + map_index
        if self == MapType.CHALLENGE:
            return 12000 + map_index
        if self == MapType.UNCANNY_LEGEND:
            return 13000 + map_index
        if self == MapType.DRINK:
            return 14000 + map_index
        if self == MapType.LEGEND_QUEST:
            return 16000 + map_index
        if self == MapType.OUTBREAKS:
            if map_index < 3:
                return 20000 + map_index
            if map_index < 6:
                return 21000 + (map_index - 3)
            if map_index < 9:
                return 22000 + (map_index - 6)
        if self == MapType.GAUNTLET:
            return 24000 + map_index
        if self == MapType.ENGIMA:
            return 25000 + map_index
        if self == MapType.COLLAB_GAUNTLET:
            return 27000 + map_index
        if self == MapType.BEHEMOTH:
            return 31000 + map_index
        if self == MapType.ZERO_LEGENDS:
            return 34000 + map_index

        return None

    def get_map_img_code(self) -> str | None:
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
        map_index: int | None,
        stage_index: int,
        lang: str,
    ) -> str | None:
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
    ) -> str | None:
        if self.is_main_story():
            return None
        img_code = self.get_map_img_code()
        if img_code is None:
            return None
        map_index_str = str(map_index).zfill(3)
        return f"mapname{map_index_str}_{img_code}_{lang}.png"

    def get_map_texture_imgcut_name(self, map_index: int, lang: str):
        name = self.get_map_texture_img_name(map_index, lang)
        if name is None:
            return None

        return name.replace(".png", ".imgcut")

    def get_map_texture_img_name(
        self,
        map_index: int | None,
        lang: str,
    ) -> str | None:
        if self == MapType.EMPIRE_OF_CATS:
            return f"img019_{lang}.png"
        if self == MapType.INTO_THE_FUTURE:
            return f"img019_w.png"
        if self == MapType.CATS_OF_THE_COSMOS:
            return f"img019_space.png"

        img_code = self.get_map_img_code()
        if img_code is None:
            return None
        map_index_str = str(map_index).zfill(3)
        return f"mapsn{map_index_str}_{img_code}_{lang}.png"

    def get_map_stage_data_csv_file_name(self, map_index: int) -> str | None:
        map_type_str = self.get_map_stage_data_map_code()
        if map_type_str is None:
            return None

        map_index_str = str(map_index).zfill(3)

        return f"MapStageData{map_type_str}_{map_index_str}.csv"


@dataclass
class MapStageDataInfo:
    map_number: int | None = None
    item_reward_stage_id: int | None = None
    score_reward_stage_id: int | None = None
    display_condition: int | None = None
    play_condition: int | None = None
    display_user_rank: int | None = None
    map_pattern: int | None = None

    def __post_init__(self):
        self._csv__map_number = IntCSVField(col_index=0, row_index=0)
        self._csv__item_reward_stage_id = IntCSVField(col_index=1, row_index=0)
        self._csv__score_reward_stage_id = IntCSVField(col_index=2, row_index=0)
        self._csv__display_condition = IntCSVField(col_index=3, row_index=0)
        self._csv__play_condition = IntCSVField(col_index=4, row_index=0)
        self._csv__display_user_rank = IntCSVField(col_index=5, row_index=0)
        self._csv__map_pattern = IntCSVField(col_index=0, row_index=1)

    def apply_csv(self, csv: tbcml.CSV):
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, csv: tbcml.CSV):
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class MapOptionInfo:
    star_count: int | None = None
    star_multiplier_1: int | None = None
    star_multiplier_2: int | None = None
    star_multiplier_3: int | None = None
    star_multiplier_4: int | None = None
    guerrilla_set: int | None = None
    reset_type: int | None = None
    one_time_display: bool | None = None
    display_order: int | None = None
    interval: int | None = None
    challenge_flag: bool | None = None
    difficulty_mask: int | None = None
    hide_after_clear: bool | None = None
    map_name: str | None = None

    def __post_init__(self):
        self._csv__star_count = IntCSVField(col_index=1)
        self._csv__star_multiplier_1 = IntCSVField(col_index=2)
        self._csv__star_multiplier_2 = IntCSVField(col_index=3)
        self._csv__star_multiplier_3 = IntCSVField(col_index=4)
        self._csv__star_multiplier_4 = IntCSVField(col_index=5)
        self._csv__guerrilla_set = IntCSVField(col_index=6)
        self._csv__reset_type = IntCSVField(col_index=7)
        self._csv__one_time_display = BoolCSVField(col_index=8)
        self._csv__display_order = IntCSVField(col_index=9)
        self._csv__interval = IntCSVField(col_index=10)
        self._csv__challenge_flag = BoolCSVField(col_index=11)
        self._csv__difficulty_mask = IntCSVField(col_index=12)
        self._csv__hide_after_clear = IntCSVField(col_index=13)
        self._csv__map_name = StringCSVField(col_index=14)

    @staticmethod
    def find_index(map_index: int, map_type: MapType, csv: tbcml.CSV) -> int | None:
        abs_index = map_type.get_map_abs_index(map_index)
        if abs_index is None:
            return None
        for i in range(1, len(csv.lines)):
            csv.index = i
            if csv.get_int(0) == abs_index:
                return i
        return None

    def apply_csv(self, map_index: int, map_type: MapType, csv: tbcml.CSV):
        index = MapOptionInfo.find_index(map_index, map_type, csv)
        if index is None:
            index = len(csv.lines)
            csv.index = index
            abs_id = map_type.get_map_abs_index(map_index)
            if abs_id is not None:
                csv.set_str(abs_id, 0)

        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, map_index: int, map_type: MapType, csv: tbcml.CSV):
        index = MapOptionInfo.find_index(map_index, map_type, csv)
        if index is None:
            return
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class Map(tbcml.Modification):
    map_index: int
    map_type: MapType
    stages: list[tbcml.Stage] = field(default_factory=list)
    map_name_img: tbcml.BCImage | None = None
    map_stage_data_info: MapStageDataInfo | None = None
    map_option_info: MapOptionInfo | None = None

    def get_map_option_info(self) -> MapOptionInfo:
        if self.map_option_info is None:
            self.map_option_info = MapOptionInfo()
        return self.map_option_info

    def get_map_stage_data_info(self) -> MapStageDataInfo:
        if self.map_stage_data_info is None:
            self.map_stage_data_info = MapStageDataInfo()
        return self.map_stage_data_info

    def get_map_name_img(self) -> tbcml.BCImage:
        if self.map_name_img is None:
            self.map_name_img = tbcml.BCImage.from_size(256, 64)
        return self.map_name_img

    def set_stage(self, index: int, stage: tbcml.Stage):
        if index >= len(self.stages):
            self.stages.append(stage)
        else:
            self.stages[index] = stage

    def get_stage_name_csv(
        self,
        game_data: tbcml.GamePacks,
    ) -> tuple[str | None, tbcml.CSV | None]:
        file_name = self.map_type.get_stage_name_csv_file_name(game_data.get_lang())
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(
            file_name, country_code=game_data.country_code
        )

    def get_map_stage_data_csv(
        self,
        game_data: tbcml.GamePacks,
    ) -> tuple[str | None, tbcml.CSV | None]:
        file_name = self.map_type.get_map_stage_data_csv_file_name(self.map_index)
        if file_name is None:
            return None, None
        return file_name, game_data.get_csv(file_name)

    def get_map_option_csv(
        self, game_data: tbcml.GamePacks
    ) -> tuple[str, tbcml.CSV | None]:
        filename = "Map_option.csv"
        return filename, game_data.get_csv(filename)

    def get_map_texture(self, game_data: tbcml.GamePacks) -> tbcml.Texture | None:
        name = self.map_type.get_map_texture_img_name(
            self.map_index, game_data.get_lang()
        )
        if name is None:
            return None
        texture_name = self.map_type.get_map_texture_imgcut_name(
            self.map_index, game_data.get_lang()
        )
        if texture_name is None:
            return None

        texture = tbcml.Texture()
        success = texture.read_from_game_file_names(game_data, name, texture_name)
        if not success:
            return None

        return texture

    def get_map_name_png(
        self,
        game_data: tbcml.GamePacks,
    ) -> tbcml.BCImage | None:
        if self.map_name_img is not None:
            return self.map_name_img
        name = self.map_type.get_map_name_img_file_name(
            self.map_index, game_data.get_lang()
        )
        if name is None:
            return None
        return game_data.get_img(name)

    def apply_stage_name_csv(self, game_data: tbcml.GamePacks):
        if not self.stages:
            return
        file_name, csv = self.get_stage_name_csv(game_data)
        if file_name is None or csv is None:
            return

        for i, stage in enumerate(self.stages):
            stage.apply_stage_name_csv(
                csv, self.map_type, self.map_index, i, is_end=i == len(self.stages) - 1
            )

        return game_data.set_csv(file_name, csv)

    def apply_map_stage_data_csv(self, game_data: tbcml.GamePacks):
        if not self.stages:
            return
        file_name, csv = self.get_map_stage_data_csv(game_data)
        if file_name is None or csv is None:
            return
        map_stage_data_info = self.get_map_stage_data_info()
        map_stage_data_info.apply_csv(csv)

        counter = 2

        for stage in self.stages:
            did_write = stage.apply_map_stage_data_csv(
                counter, csv, self.get_map_stage_data_info().score_reward_stage_id or -1
            )
            if did_write:
                counter += 1

        return game_data.set_csv(file_name, csv)

    def apply_map_option_csv(self, game_data: tbcml.GamePacks):
        if not self.map_option_info:
            return
        file_name, csv = self.get_map_option_csv(game_data)
        if csv is None:
            return
        map_option_info = self.get_map_option_info()
        map_option_info.apply_csv(self.map_index, self.map_type, csv)

        return game_data.set_csv(file_name, csv)

    def apply_map_texture(self, game_data: tbcml.GamePacks):
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

    def apply_map_name_img(self, game_data: tbcml.GamePacks):
        if self.map_name_img is None:
            return
        map_name_img_name = self.map_type.get_map_name_img_file_name(
            self.map_index, game_data.get_lang()
        )
        if map_name_img_name is None:
            return
        return game_data.set_img(map_name_img_name, self.map_name_img)

    def read_stage_name_csv(
        self, game_data: tbcml.GamePacks, create_new_stages: bool = True
    ):
        _, csv = self.get_stage_name_csv(game_data)
        if csv is None:
            return

        if self.map_type.is_main_story():
            total_stages = len(csv.lines) - 1
        else:
            total_stages = len(csv.get_line(self.map_index)) - 1
        for i in range(total_stages):
            stage = self.get_stage(i)
            if stage is None:
                if create_new_stages:
                    stage = tbcml.Stage()
                    self.stages.append(stage)
                else:
                    continue
            stage.read_stage_name_csv(csv, self.map_type, self.map_index, i)

    def read_stage_name_csv_stage(
        self, game_data: tbcml.GamePacks, stage: tbcml.Stage, stage_index: int
    ):
        _, csv = self.get_stage_name_csv(game_data)
        if csv is None:
            return

        stage.read_stage_name_csv(csv, self.map_type, self.map_index, stage_index)

    def read_map_stage_data_csv(self, game_data: tbcml.GamePacks):
        _, csv = self.get_map_stage_data_csv(game_data)
        if csv is None:
            return

        map_stage_data_info = MapStageDataInfo()
        map_stage_data_info.read_csv(csv)

        self.map_stage_data_info = map_stage_data_info

        for i, stage in enumerate(self.stages):
            stage.read_map_stage_data_csv(
                i + 2, csv, map_stage_data_info.score_reward_stage_id or -1
            )

    def read_map_stage_data_csv_stage(
        self, game_data: tbcml.GamePacks, stage: tbcml.Stage, stage_index: int
    ):
        _, csv = self.get_map_stage_data_csv(game_data)
        if csv is None:
            return

        map_stage_data_info = MapStageDataInfo()
        map_stage_data_info.read_csv(csv)

        stage.read_map_stage_data_csv(
            stage_index + 2, csv, map_stage_data_info.score_reward_stage_id or -1
        )

    def get_stage_option_csv(
        self, game_data: tbcml.GamePacks
    ) -> tuple[str, tbcml.CSV | None]:
        file_name = "Stage_option.csv"
        return file_name, game_data.get_csv(file_name, remove_comments=False)

    def read_stage_option_csv(self, game_data: tbcml.GamePacks):
        _, csv = self.get_stage_option_csv(game_data)
        if csv is None:
            return

        indexes = tbcml.StageOptionInfo.find_indexes(self.map_index, self.map_type, csv)
        if indexes is None:
            return

        for stage in self.stages:
            stage.stage_option_info = []

        for index in indexes:
            csv.index = index
            info = tbcml.StageOptionInfo()
            info.read_csv(csv, index)
            stage_index = csv.get_int(2)
            if stage_index == -1:
                for stage in self.stages:
                    stage.get_stage_option_info().append(info)
            else:
                stage = self.get_stage(stage_index)
                if not stage:
                    stage = tbcml.Stage()
                    self.set_stage_extend(stage_index, stage)
                stage.get_stage_option_info().append(info)

    def apply_stage_option_csv(self, game_data: tbcml.GamePacks):
        file_name, csv = self.get_stage_option_csv(game_data)
        if csv is None:
            return

        indexes = tbcml.StageOptionInfo.find_indexes(self.map_index, self.map_type, csv)
        if indexes:
            new_csv_lines: list[list[str]] = []
            for i, line in enumerate(csv.lines):
                if i not in indexes:
                    new_csv_lines.append(line)
            csv.lines = new_csv_lines

        done_options: list[tuple[int, int | None]] = []  # [stage_id, star_id]

        abs_map_id = self.map_type.get_map_abs_index(self.map_index)

        index = len(csv.lines)
        for i, stage in enumerate(self.stages):
            for option in stage.get_stage_option_info():
                tp = (i, option.star_id)
                if tp in done_options:
                    continue
                csv.index = index
                csv.set_str(abs_map_id, 0)
                csv.set_str(i, 2)
                option.apply_csv(csv, index)
                done_options.append(tp)
                index += 1

        game_data.set_csv(file_name, csv)

    def set_stage_extend(self, stage_index: int, stage: tbcml.Stage):
        if stage_index >= len(self.stages):
            self.stages.extend([tbcml.Stage()] * (stage_index - len(self.stages) + 1))
        self.stages[stage_index] = stage

    def read_map_option_csv(self, game_data: tbcml.GamePacks):
        _, csv = self.get_map_option_csv(game_data)
        if csv is None:
            return

        map_option_info = MapOptionInfo()
        map_option_info.read_csv(self.map_index, self.map_type, csv)

        self.map_option_info = map_option_info

    def read_map_texture(self, game_data: tbcml.GamePacks):
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

    def read_map_name_img(self, game_data: tbcml.GamePacks):
        map_name_img = self.get_map_name_png(game_data)
        if map_name_img is None:
            return
        self.map_name_img = map_name_img

    def get_stage(self, index: int) -> tbcml.Stage | None:
        if index < 0 or index >= len(self.stages):
            return None
        return self.stages[index]

    def apply_stages(self, game_data: tbcml.GamePacks):
        for i, stage in enumerate(self.stages):
            stage.apply(game_data, i, self.map_type, self.map_index)

        self.apply_map_texture(game_data)

        self.apply_stage_option_csv(game_data)

    def read_stages(self, game_data: tbcml.GamePacks):
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
        self.read_stage_option_csv(game_data)

    def apply_game_data(self, game_data: tbcml.GamePacks):
        self.apply_stages(game_data)
        self.apply_stage_name_csv(game_data)
        self.apply_map_name_img(game_data)
        self.apply_map_stage_data_csv(game_data)
        self.apply_map_option_csv(game_data)

    def read(self, game_data: tbcml.GamePacks):
        self.read_stages(game_data)
        self.read_stage_name_csv(game_data)
        self.read_map_name_img(game_data)
        self.read_map_stage_data_csv(game_data)
        self.read_map_option_csv(game_data)

    def pre_to_json(self) -> None:
        for stage in self.stages:
            stage.pre_to_json()
        if self.map_name_img is not None:
            self.map_name_img.save_b64()

    def post_from_json(self) -> None:
        for stage in self.stages:
            stage.post_from_json()

    def set_map_index(self, map_index: int):
        self.map_index = map_index
