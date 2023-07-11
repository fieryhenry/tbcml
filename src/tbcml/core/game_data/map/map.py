"""Module for map and stage stuff"""

import enum
from typing import Any, Optional

from tbcml import core


class StageNameNameType(enum.Enum):
    """The code name of the map type for the stage name files"""

    STORY = ""
    AKU = "DM"
    GAUNTLET = "RA"
    DRINK = "RB"
    COLLAB = "RC"
    COLLAB_GAUNTLET = "RCA"
    EXTRA = "RE"
    ENIGMA = "RH"
    CHALLENGE = "RM"
    SOL = "RN"
    UNCANNY = "RNA"
    BEHEMOTH = "RQ"
    DOJO_RANK = "RR"
    REGULAR_EVENT = "RS"
    DOJO_CATCLAW = "RT"
    TOWER = "RV"

    def get_map_index_type(self) -> Optional["MapIndexType"]:
        """Gets the MapIndexType that corresponds to this StageNameNameType

        Returns:
            Optional[MapIndexType]: The MapIndexType that corresponds to this StageNameNameType
        """
        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapStageDataNameType(enum.Enum):
    """The code name of the map type for the map stage data files"""

    STORY = ""
    SOL = "N"
    REGULAR_EVENT = "S"
    COLLAB = "C"
    EXTRA = "E"
    DOJO_CATCLAW = "T"
    TOWER = "V"
    DOJO_RANK = "R"
    CHALLENGE = "M"
    UNCANNY = "A"
    DRINK = "B"
    GAUNTLET = "RA"
    ENGIMA = "H"
    COLLAB_GAUNTLET = "CA"
    BEHEMOTH = "Q"

    def get_map_index_type(self) -> Optional["MapIndexType"]:
        """Gets the MapIndexType that corresponds to this MapStageDataNameType

        Returns:
            Optional[MapIndexType]: The MapIndexType that corresponds to this MapStageDataNameType
        """
        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapNameType(enum.Enum):
    """The code name of the map type for the map name files"""

    STORY = ""
    AKU = "DM"
    EXTRA = "EX"  # also RE
    GAUNTLET = "RA"
    DRINK = "RB"
    COLLAB = "RC"
    COLLAB_GAUNTLET = "RCA"
    ENIGMA = "RH"
    CHALLENGE = "RM"
    SOL = "RN"
    UNCANNY = "RNA"
    BEHEMOTH = "RQ"
    DOJO_RANK = "RR"
    REGULAR_EVENT = "RS"
    DOJO_CATCLAW = "RT"
    TOWER = "RV"
    COTC = "Space"
    ITF = "W"
    OUTBREAKS = "Z"

    def get_map_index_type(self) -> Optional["MapIndexType"]:
        """Gets the MapIndexType that corresponds to this MapNameType

        Returns:
            Optional[MapIndexType]: The MapIndexType that corresponds to this MapNameType
        """

        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapIndexType(enum.Enum):
    """The index of the map type for the map files"""

    SOL = 0
    REGULAR_EVENT = 1000
    COLLAB = 2000
    STORY = 3000
    EXTRA = 4000
    DOJO_CATCLAW = 6000
    TOWER = 7000
    CHALLENGE = 12000
    UNCANNY = 13000
    DRINK = 14000
    LEGEND_QUEST = 16000
    OUTBREAKS_EOC = 20000
    OUTBREAKS_ITF = 21000
    OUTBREAKS_COTC = 22000
    FILIBUSTER = 23000
    GAUNTLET = 24000
    ENGIMA = 25000
    COLLAB_GAUNTLET = 27000
    BEHEMOTH = 31000

    @staticmethod
    def get_all() -> list["MapIndexType"]:
        """Gets all the MapIndexTypes

        Returns:
            list[MapIndexType]: All the MapIndexTypes
        """
        return sorted(MapIndexType, key=lambda x: x.value)

    def get_map_name_type(self) -> Optional[MapNameType]:
        """Gets the MapNameType that corresponds to this MapIndexType

        Returns:
            Optional[MapNameType]: The MapNameType that corresponds to this MapIndexType
        """
        for name_type in MapNameType:
            if name_type.name == self.name:
                return name_type
        return None

    def get_map_stage_data_name_type(self) -> Optional[MapStageDataNameType]:
        """Gets the MapStageDataNameType that corresponds to this MapIndexType

        Returns:
            Optional[MapStageDataNameType]: The MapStageDataNameType that corresponds to this MapIndexType
        """
        for name_type in MapStageDataNameType:
            if name_type.name == self.name:
                return name_type
        return None

    def get_stage_name_name_type(self) -> Optional[StageNameNameType]:
        """Gets the StageNameNameType that corresponds to this MapIndexType

        Returns:
            Optional[StageNameNameType]: The StageNameNameType that corresponds to this MapIndexType
        """
        for name_type in StageNameNameType:
            if name_type.name == self.name:
                return name_type
        return None

    @staticmethod
    def from_index(index: int) -> Optional["MapIndexType"]:
        """Gets the MapIndexType that corresponds to the given index

        Returns:
            Optional[MapIndexType]: The MapIndexType that corresponds to the given index
        """
        types_sorted = sorted(MapIndexType, key=lambda x: x.value)
        for i in range(len(types_sorted)):
            if index < types_sorted[i].value:
                return types_sorted[i - 1]
            if index == types_sorted[i].value:
                return types_sorted[i]
        return None


class ResetType(enum.Enum):
    """The type of reward reset for a map"""

    NONE = 0
    REWARD = 1
    CLEAR_STATUS = 2
    NUMBER_OF_PLAYS = 3


class MapOption:
    """Class for storing map options"""

    def __init__(
        self,
        stage_id: int,
        number_of_stars: Optional[int] = None,
        star_mult_1: Optional[int] = None,
        star_mult_2: Optional[int] = None,
        star_mult_3: Optional[int] = None,
        star_mult_4: Optional[int] = None,
        guerrilla_set: Optional[int] = None,
        reset_type: Optional[ResetType] = None,
        one_time_display: Optional[bool] = None,
        display_order: Optional[int] = None,
        interval: Optional[int] = None,
        challenge_flag: Optional[bool] = None,
        difficulty_mask: Optional[int] = None,
        hide_after_clear: Optional[bool] = None,
        map_comment: Optional[str] = None,
    ):
        """Initializes a MapOption

        Args:
            stage_id (int): The stage id
            number_of_stars (Optional[int], optional): The number of stars of the map. Defaults to None.
            star_mult_1 (Optional[int], optional): The enemy multiplier for 1 star. Defaults to None.
            star_mult_2 (Optional[int], optional): The enemy multiplier for 2 stars. Defaults to None.
            star_mult_3 (Optional[int], optional): The enemy multiplier for 3 stars. Defaults to None.
            star_mult_4 (Optional[int], optional): The enemy multiplier for 4 stars. Defaults to None.
            guerrilla_set (Optional[int], optional): The guerrilla set (idk). Defaults to None.
            reset_type (Optional[ResetType], optional): The reward reset type. Defaults to None.
            one_time_display (Optional[bool], optional): If the map is a one time display. Defaults to None.
            display_order (Optional[int], optional): The display order of the map in the map select screen list. Defaults to None.
            interval (Optional[int], optional): The interval of the map?. Defaults to None.
            challenge_flag (Optional[bool], optional): If the map is a challenge map. Defaults to None.
            difficulty_mask (Optional[int], optional): The star difficulty mask. The bits of this number reflect the pattern of the stars. Defaults to None.
            hide_after_clear (Optional[bool], optional): If the map is hidden after clearing. Defaults to None.
            map_comment (Optional[str], optional): The map comment. Defaults to None.
        """
        self.stage_id = stage_id
        self.map_index_type = MapIndexType.from_index(stage_id)
        if self.map_index_type is not None:
            self.map_name_type = self.map_index_type.get_map_name_type()
            self.map_stage_data_name_type = (
                self.map_index_type.get_map_stage_data_name_type()
            )

        self.number_of_stars = number_of_stars
        self.star_mult_1 = star_mult_1
        self.star_mult_2 = star_mult_2
        self.star_mult_3 = star_mult_3
        self.star_mult_4 = star_mult_4
        self.guerrilla_set = guerrilla_set
        self.reset_type = reset_type
        self.one_time_display = one_time_display
        self.display_order = display_order
        self.interval = interval
        self.challenge_flag = challenge_flag
        self.difficulty_mask = difficulty_mask
        self.hide_after_clear = hide_after_clear
        self.map_comment = map_comment

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dict to this MapOption

        Args:
            dict_data (dict[str, Any]): The dict to apply
        """
        self.stage_id = dict_data.get("stage_id", self.stage_id)
        self.map_index_type = MapIndexType.from_index(self.stage_id)
        if self.map_index_type is not None:
            self.map_name_type = self.map_index_type.get_map_name_type()
            self.map_stage_data_name_type = (
                self.map_index_type.get_map_stage_data_name_type()
            )

        self.number_of_stars = dict_data.get("number_of_stars", self.number_of_stars)
        self.star_mult_1 = dict_data.get("star_mult_1", self.star_mult_1)
        self.star_mult_2 = dict_data.get("star_mult_2", self.star_mult_2)
        self.star_mult_3 = dict_data.get("star_mult_3", self.star_mult_3)
        self.star_mult_4 = dict_data.get("star_mult_4", self.star_mult_4)
        self.guerrilla_set = dict_data.get("guerrilla_set", self.guerrilla_set)
        reset_type = dict_data.get("reset_type")
        if reset_type is not None:
            self.reset_type = ResetType[reset_type]
        self.one_time_display = dict_data.get("one_time_display", self.one_time_display)
        self.display_order = dict_data.get("display_order", self.display_order)
        self.interval = dict_data.get("interval", self.interval)
        self.challenge_flag = dict_data.get("challenge_flag", self.challenge_flag)
        self.difficulty_mask = dict_data.get("difficulty_mask", self.difficulty_mask)
        self.hide_after_clear = dict_data.get("hide_after_clear", self.hide_after_clear)
        self.map_comment = dict_data.get("map_comment", self.map_comment)

    @staticmethod
    def create_empty(stage_id: int) -> "MapOption":
        """Creates an empty MapOption

        Args:
            stage_id (int): The stage id

        Returns:
            MapOption: The empty MapOption
        """
        return MapOption(stage_id)


class MapOptions:
    """A class representing a collection of map options"""

    def __init__(self, options: dict[int, MapOption]):
        """Creates a MapOptions object

        Args:
            options (dict[int, MapOption]): The map options
        """
        self.options = options

    def get(self, stage_id: int) -> Optional[MapOption]:
        """Gets the map option for a stage id

        Args:
            stage_id (int): The stage id

        Returns:
            Optional[MapOption]: The map option
        """
        return self.options.get(stage_id)

    def set(self, option: MapOption):
        """Sets the map option for a stage id

        Args:
            option (MapOption): The map option
        """
        self.options[option.stage_id] = option

    @staticmethod
    def get_file_name() -> str:
        """Gets the file name of the map option file

        Returns:
            str: The file name
        """
        return "Map_option.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "MapOptions":
        """Creates a MapOptions object from game data

        Args:
            game_data (core.GamePacks): The game data

        Returns:
            MapOptions: The map options
        """
        map_options = game_data.find_file(MapOptions.get_file_name())
        if map_options is None:
            return MapOptions.create_empty()
        options: dict[int, MapOption] = {}
        csv = core.CSV(map_options.dec_data)
        for line in csv.lines[1:]:
            stage_id = int(line[0])
            options[stage_id] = MapOption(
                stage_id,
                int(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
                int(line[6]),
                ResetType(int(line[7])),
                bool(int(line[8])),
                int(line[9]),
                int(line[10]),
                bool(int(line[11])),
                int(line[12]),
                bool(int(line[13])),
                line[14],
            )
        return MapOptions(options)

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the map options to game data

        Args:
            game_data (core.GamePacks): The game data
        """

        map_options = game_data.find_file(MapOptions.get_file_name())
        if map_options is None:
            return None
        csv = core.CSV(map_options.dec_data)
        remaining = self.options.copy()
        for i, line in enumerate(csv.lines[1:]):
            stage_id = int(line[0])
            option = self.options.get(stage_id)
            if option is None:
                continue
            if option.number_of_stars is not None:
                line[1] = str(option.number_of_stars)
            if option.star_mult_1 is not None:
                line[2] = str(option.star_mult_1)
            if option.star_mult_2 is not None:
                line[3] = str(option.star_mult_2)
            if option.star_mult_3 is not None:
                line[4] = str(option.star_mult_3)
            if option.star_mult_4 is not None:
                line[5] = str(option.star_mult_4)
            if option.guerrilla_set is not None:
                line[6] = str(option.guerrilla_set)
            if option.reset_type is not None:
                line[7] = str(option.reset_type.value)
            if option.one_time_display is not None:
                line[8] = "1" if option.one_time_display else "0"
            if option.display_order is not None:
                line[9] = str(option.display_order)
            if option.interval is not None:
                line[10] = str(option.interval)
            if option.challenge_flag is not None:
                line[11] = "1" if option.challenge_flag else "0"
            if option.difficulty_mask is not None:
                line[12] = str(option.difficulty_mask)
            if option.hide_after_clear is not None:
                line[13] = "1" if option.hide_after_clear else "0"
            if option.map_comment is not None:
                line[14] = option.map_comment
            csv.lines[i + 1] = line
            del remaining[stage_id]
        for option in remaining.values():
            line: list[str] = []
            line.append(str(option.stage_id or 0))
            line.append(str(option.number_of_stars or 0))
            line.append(str(option.star_mult_1 or 0))
            line.append(str(option.star_mult_2 or 0))
            line.append(str(option.star_mult_3 or 0))
            line.append(str(option.star_mult_4 or 0))
            line.append(str(option.guerrilla_set or 0))
            line.append(str(option.reset_type.value) if option.reset_type else "0")
            line.append("1" if option.one_time_display else "0")
            line.append(str(option.display_order or 0))
            line.append(str(option.interval or 0))
            line.append("1" if option.challenge_flag else "0")
            line.append(str(option.difficulty_mask or 0))
            line.append("1" if option.hide_after_clear else "0")
            line.append(option.map_comment or "")
            csv.lines.append(line)

        game_data.set_file(MapOptions.get_file_name(), csv.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dict to the map options

        Args:
            dict_data (dict[str, Any]): The dict to apply
        """
        options = dict_data.get("options")
        if options is not None:
            current_options = self.options.copy()
            modded_options = core.ModEditDictHandler(options, current_options).get_dict(
                convert_int=True
            )
            for id, modded_option in modded_options.items():
                option = current_options.get(id)
                if option is None:
                    option = MapOption.create_empty(id)
                option.apply_dict(modded_option)
                self.set(option)

    @staticmethod
    def create_empty() -> "MapOptions":
        """Creates an empty map options object

        Returns:
            MapOptions: The created map options
        """
        return MapOptions({})


class EnemyRow:
    """Represents an enemy row in the stage csv files"""

    def __init__(
        self,
        index: int,
        enemy_id: Optional[int] = None,
        total_spawn_count: Optional[int] = None,
        start_frame: Optional[int] = None,
        min_spawn_interval: Optional[int] = None,
        max_spawn_interval: Optional[int] = None,
        spawn_base_percentage: Optional[int] = None,
        min_z: Optional[int] = None,
        max_z: Optional[int] = None,
        boss_flag: Optional[bool] = None,
        magnification: Optional[int] = None,
        spawn_1: Optional[int] = None,
        castle_1: Optional[int] = None,
        group: Optional[int] = None,
        kill_count: Optional[int] = None,
    ):
        """Creates a new enemy row

        Args:
            index (int): The index of the row
            enemy_id (Optional[int], optional): The enemy id of the row. Defaults to None.
            total_spawn_count (Optional[int], optional): The max amount of enemies to spawn. Defaults to None.
            start_frame (Optional[int], optional): The frame to start spawning enemies. Defaults to None.
            min_spawn_interval (Optional[int], optional): The min amount of frames between spawns. Defaults to None.
            max_spawn_interval (Optional[int], optional): The max amount of frames between spawns. Defaults to None.
            spawn_base_percentage (Optional[int], optional): The base percentage to spawn enemies. Defaults to None.
            min_z (Optional[int], optional): The min z level to spawn enemies. Defaults to None.
            max_z (Optional[int], optional): The max z level to spawn enemies. Defaults to None.
            boss_flag (Optional[bool], optional): Whether the enemy is a boss. Defaults to None.
            magnification (Optional[int], optional): The stat boost multiplier. Defaults to None.
            spawn_1 (Optional[int], optional): ? Defaults to None.
            castle_1 (Optional[int], optional): ? Defaults to None.
            group (Optional[int], optional): ? Defaults to None.
            kill_count (Optional[int], optional): Amount of enemies to kill before spawning enemies? Defaults to None.
        """
        self.index = index
        self.enemy_id = enemy_id
        self.total_spawn_count = total_spawn_count
        self.start_frame = start_frame
        self.min_spawn_interval = min_spawn_interval
        self.max_spawn_interval = max_spawn_interval
        self.spawn_base_percentage = spawn_base_percentage
        self.min_z = min_z
        self.max_z = max_z
        self.boss_flag = boss_flag
        self.magnification = magnification
        self.spawn_1 = spawn_1
        self.castle_1 = castle_1
        self.group = group
        self.kill_count = kill_count

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dict to the enemy row

        Args:
            dict_data (dict[str, Any]): The dict to apply
        """
        self.enemy_id = dict_data.get("enemy_id", self.enemy_id)
        self.total_spawn_count = dict_data.get(
            "total_spawn_count", self.total_spawn_count
        )
        self.start_frame = dict_data.get("start_frame", self.start_frame)
        self.min_spawn_interval = dict_data.get(
            "min_spawn_interval", self.min_spawn_interval
        )
        self.max_spawn_interval = dict_data.get(
            "max_spawn_interval", self.max_spawn_interval
        )
        self.spawn_base_percentage = dict_data.get(
            "spawn_base_percentage", self.spawn_base_percentage
        )
        self.min_z = dict_data.get("min_z", self.min_z)
        self.max_z = dict_data.get("max_z", self.max_z)
        self.boss_flag = dict_data.get("boss_flag", self.boss_flag)
        self.magnification = dict_data.get("magnification", self.magnification)
        self.spawn_1 = dict_data.get("spawn_1", self.spawn_1)
        self.castle_1 = dict_data.get("castle_1", self.castle_1)
        self.group = dict_data.get("group", self.group)
        self.kill_count = dict_data.get("kill_count", self.kill_count)

    @staticmethod
    def create_empty(index: int) -> "EnemyRow":
        """Creates an empty enemy row

        Args:
            index (int): The index of the row

        Returns:
            EnemyRow: The created enemy row
        """
        return EnemyRow(index)


class StageStats:
    """Represents the stats of a stage"""

    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        castle_type: Optional[int] = None,
        no_continues: Optional[bool] = None,
        ex_stage_prob: Optional[int] = None,
        ex_stage_chapter_id: Optional[int] = None,
        ex_stage_stage_id: Optional[int] = None,
        stage_width: Optional[int] = None,
        base_health: Optional[int] = None,
        min_production_frames: Optional[int] = None,
        max_production_frames: Optional[int] = None,
        background_type: Optional[int] = None,
        max_enemy_count: Optional[int] = None,
        unused: Optional[int] = None,
        enemies: Optional[dict[int, EnemyRow]] = None,
    ):
        """Creates a new stage stats object

        Args:
            stage_id (int): The map id of the stage
            stage_index (int): The index of the stage
            castle_type (Optional[int], optional): The castle type of the stage. Defaults to None.
            no_continues (Optional[bool], optional): Whether the stage disallows continues. Defaults to None.
            ex_stage_prob (Optional[int], optional): Probability of a second stage after you clear the first (e.g catfruit jubilee). Defaults to None.
            ex_stage_chapter_id (Optional[int], optional): The chapter id of the second stage. Defaults to None.
            ex_stage_stage_id (Optional[int], optional): The stage id of the second stage. Defaults to None.
            stage_width (Optional[int], optional): The width of the stage. Defaults to None.
            base_health (Optional[int], optional): The base health of the stage. Defaults to None.
            min_production_frames (Optional[int], optional): The minimum amount of frames between enemy spawns. Defaults to None.
            max_production_frames (Optional[int], optional): The maximum amount of frames between enemy spawns. Defaults to None.
            background_type (Optional[int], optional): The background type of the stage. Defaults to None.
            max_enemy_count (Optional[int], optional): The maximum amount of enemies that can be spawned. Defaults to None.
            unused (Optional[int], optional): ? Defaults to None.
            enemies (Optional[dict[int, EnemyRow]], optional): The enemies of the stage. Defaults to None.
        """
        self.stage_id = stage_id
        self.stage_index = stage_index
        self.map_index_type = MapIndexType.from_index(stage_id)
        if self.map_index_type is not None:
            self.map_name_type = self.map_index_type.get_map_name_type()

        self.castle_type = castle_type
        self.no_continues = no_continues
        self.ex_stage_prob = ex_stage_prob
        self.ex_stage_chapter_id = ex_stage_chapter_id
        self.ex_stage_stage_id = ex_stage_stage_id
        self.stage_width = stage_width
        self.base_health = base_health
        self.min_production_frames = min_production_frames
        self.max_production_frames = max_production_frames
        self.background_type = background_type
        self.max_enemy_count = max_enemy_count
        self.unused = unused
        self.enemies = enemies

    @staticmethod
    def get_file_name(stage_id: int, stage_index: int) -> Optional[str]:
        """Gets the file name of a stage

        Args:
            stage_id (int): The map id of the stage
            stage_index (int): The index of the stage

        Returns:
            Optional[str]: The file name of the stage
        """
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_name_type = map_index_type.get_map_name_type()
        if map_name_type is None:
            return None
        stage_id_index = stage_id - map_index_type.value
        stage_id_index_str = core.PaddedInt(stage_id_index, 3).to_str()
        stage_index_str = core.PaddedInt(stage_index, 2).to_str()
        return f"stage{map_name_type.value}{stage_id_index_str}_{stage_index_str}.csv"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        stage_id: int,
        stage_index: int,
    ) -> Optional["StageStats"]:
        """Creates a stage stats object from game data

        Args:
            game_data (core.GamePacks): The game data
            stage_id (int): The map id of the stage
            stage_index (int): The index of the stage

        Returns:
            Optional[StageStats]: The created stage stats object
        """
        file_name = StageStats.get_file_name(stage_id, stage_index)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        line_1 = csv.read_line()
        if line_1 is None:
            return None
        castle_type = int(line_1[0])
        no_continues = bool(int(line_1[1]))
        exstage_prob = int(line_1[2])
        exstage_chapter_id = int(line_1[3])
        ex_stage_stage_id = int(line_1[4])
        line_2 = csv.read_line()
        if line_2 is None:
            return None
        stage_width = int(line_2[0])
        base_health = int(line_2[1])
        min_production_frames = int(line_2[2])
        max_production_frames = int(line_2[3])
        background_type = int(line_2[4])
        max_enemy_count = int(line_2[5])
        unused = int(line_2[6])
        enemies: dict[int, EnemyRow] = {}
        for i, line in enumerate(csv.lines[2:]):
            enemy_id = int(line[0])
            total_spawn_count = int(line[1])
            start_frame = int(line[2])
            min_spawn_interval = int(line[3])
            max_spawn_interval = int(line[4])
            spawn_base_percentage = int(line[5])
            min_z = int(line[6])
            max_z = int(line[7])
            boss_flag = bool(int(line[8]))
            magnification = None
            spawn_1 = None
            castle_1 = None
            group = None
            kill_count = None
            if len(line) > 9:
                magnification = int(line[9])
            if len(line) > 10:
                try:
                    spawn_1 = int(line[10])
                except ValueError:
                    pass
            if len(line) > 11:
                castle_1 = int(line[11])
            if len(line) > 12:
                group = int(line[12])
            if len(line) > 13:
                kill_count = int(line[13])

            enemies[i] = EnemyRow(
                i,
                enemy_id,
                total_spawn_count,
                start_frame,
                min_spawn_interval,
                max_spawn_interval,
                spawn_base_percentage,
                min_z,
                max_z,
                boss_flag,
                magnification,
                spawn_1,
                castle_1,
                group,
                kill_count,
            )
        return StageStats(
            stage_id,
            stage_index,
            castle_type,
            no_continues,
            exstage_prob,
            exstage_chapter_id,
            ex_stage_stage_id,
            stage_width,
            base_health,
            min_production_frames,
            max_production_frames,
            background_type,
            max_enemy_count,
            unused,
            enemies,
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the stage stats to game data

        Args:
            game_data (core.GamePacks): The game data
        """
        file_name = StageStats.get_file_name(self.stage_id, self.stage_index)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        line_1 = csv.read_line()
        if line_1 is None:
            return None
        if self.castle_type is not None:
            line_1[0] = str(self.castle_type)
        if self.no_continues is not None:
            line_1[1] = "1" if self.no_continues else "0"
        if self.ex_stage_prob is not None:
            line_1[2] = str(self.ex_stage_prob)
        if self.ex_stage_chapter_id is not None:
            line_1[3] = str(self.ex_stage_chapter_id)
        if self.ex_stage_stage_id is not None:
            line_1[4] = str(self.ex_stage_stage_id)
        csv.lines[0] = line_1

        line_2 = csv.read_line()
        if line_2 is None:
            return None
        if self.stage_width is not None:
            line_2[0] = str(self.stage_width)
        if self.base_health is not None:
            line_2[1] = str(self.base_health)
        if self.min_production_frames is not None:
            line_2[2] = str(self.min_production_frames)
        if self.max_production_frames is not None:
            line_2[3] = str(self.max_production_frames)
        if self.background_type is not None:
            line_2[4] = str(self.background_type)
        if self.max_enemy_count is not None:
            line_2[5] = str(self.max_enemy_count)
        if self.unused is not None:
            line_2[6] = str(self.unused)
        csv.lines[1] = line_2

        if self.enemies is not None:
            for i, enemy in self.enemies.items():
                line = csv.lines[i + 2]
                if enemy.enemy_id is not None:
                    line[0] = str(enemy.enemy_id)
                if enemy.total_spawn_count is not None:
                    line[1] = str(enemy.total_spawn_count)
                if enemy.start_frame is not None:
                    line[2] = str(enemy.start_frame)
                if enemy.min_spawn_interval is not None:
                    line[3] = str(enemy.min_spawn_interval)
                if enemy.max_spawn_interval is not None:
                    line[4] = str(enemy.max_spawn_interval)
                if enemy.spawn_base_percentage is not None:
                    line[5] = str(enemy.spawn_base_percentage)
                if enemy.min_z is not None:
                    line[6] = str(enemy.min_z)
                if enemy.max_z is not None:
                    line[7] = str(enemy.max_z)
                if enemy.boss_flag is not None:
                    line[8] = "1" if enemy.boss_flag else "0"
                if enemy.magnification is not None:
                    try:
                        line[9] = str(enemy.magnification)
                    except IndexError:
                        line.append(str(enemy.magnification))
                if enemy.spawn_1 is not None:
                    line[10] = str(enemy.spawn_1)
                if enemy.castle_1 is not None:
                    line[11] = str(enemy.castle_1)
                if enemy.group is not None:
                    line[12] = str(enemy.group)
                if enemy.kill_count is not None:
                    line[13] = str(enemy.kill_count)
                csv.lines[i + 2] = line
            game_data.set_file(file_name, csv.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        self.castle_type = dict_data.get("castle_type", self.castle_type)
        self.no_continues = dict_data.get("no_continues", self.no_continues)
        self.ex_stage_prob = dict_data.get("ex_stage_prob", self.ex_stage_prob)
        self.ex_stage_chapter_id = dict_data.get(
            "ex_stage_chapter_id", self.ex_stage_chapter_id
        )
        self.ex_stage_stage_id = dict_data.get(
            "ex_stage_stage_id", self.ex_stage_stage_id
        )
        self.stage_width = dict_data.get("stage_width", self.stage_width)
        self.base_health = dict_data.get("base_health", self.base_health)
        self.min_production_frames = dict_data.get(
            "min_production_frames", self.min_production_frames
        )
        self.max_production_frames = dict_data.get(
            "max_production_frames", self.max_production_frames
        )
        self.background_type = dict_data.get("background_type", self.background_type)
        self.max_enemy_count = dict_data.get("max_enemy_count", self.max_enemy_count)
        self.unused = dict_data.get("unused", self.unused)
        enemies = dict_data.get("enemies")
        if enemies is not None:
            if self.enemies is None:
                self.enemies = {}
            current_enemies = self.enemies.copy()
            modded_enemies = core.ModEditDictHandler(enemies, current_enemies).get_dict(
                convert_int=True
            )
            for index, modded_enemy in modded_enemies.items():
                enemy = current_enemies.get(index)
                if enemy is None:
                    enemy = EnemyRow.create_empty(index)
                enemy.apply_dict(modded_enemy)
                self.enemies[index] = enemy

    @staticmethod
    def create_empty(stage_id: int, stage_index: int) -> "StageStats":
        return StageStats(
            stage_id,
            stage_index,
            0,
            False,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            {},
        )


class Stage:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        stage_stats: StageStats,
        name: "StageName",
        name_image: "StageNameImage",
    ):
        self.stage_id = stage_id
        self.stage_index = stage_index
        self.stage_stats = stage_stats
        self.name = name
        self.name_image = name_image

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        stage_id: int,
        stage_index: int,
        name: "StageName",
    ) -> Optional["Stage"]:
        stage_stats = StageStats.from_game_data(game_data, stage_id, stage_index)
        stage_image = StageNameImage.from_game_data(game_data, stage_id, stage_index)
        if stage_stats is None or stage_image is None:
            return None
        return Stage(stage_id, stage_index, stage_stats, name, stage_image)

    def to_game_data(self, game_data: "core.GamePacks"):
        self.stage_stats.to_game_data(game_data)
        self.name_image.to_game_data(game_data)

    def apply_dict(self, dict_data: dict[str, Any]):
        self.stage_stats.apply_dict(dict_data)
        self.name.apply_dict(dict_data)
        self.name_image.apply_dict(dict_data)

    @staticmethod
    def create_empty(stage_id: int, stage_index: int) -> "Stage":
        return Stage(
            stage_id,
            stage_index,
            StageStats.create_empty(stage_id, stage_index),
            StageName.create_empty(stage_id, stage_index),
            StageNameImage.create_empty(stage_id, stage_index),
        )


class ItemDrop:
    def __init__(self, probability: int, item_id: int, amount: int):
        self.item_id = item_id
        self.amount = amount
        self.probability = probability

    def apply_dict(self, dict_data: dict[str, Any]):
        self.item_id = dict_data.get("item_id", self.item_id)
        self.amount = dict_data.get("amount", self.amount)
        self.probability = dict_data.get("probability", self.probability)

    @staticmethod
    def create_empty() -> "ItemDrop":
        return ItemDrop(0, 0, 0)


class TimeScoreReward:
    def __init__(self, score: int, item_id: int, amount: int):
        self.score = score
        self.item_id = item_id
        self.amount = amount

    def apply_dict(self, dict_data: dict[str, Any]):
        self.score = dict_data.get("score", self.score)
        self.item_id = dict_data.get("item_id", self.item_id)
        self.amount = dict_data.get("amount", self.amount)

    @staticmethod
    def create_empty() -> "TimeScoreReward":
        return TimeScoreReward(0, 0, 0)


class MapStageDataStage:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        energy_cost: int,
        xp_gain: int,
        start_music: int,
        base_percentage_boss_music: int,
        boss_music: int,
        rand: int,
        item_drops: list[ItemDrop],
        max_reward_claims: int,
        time_score_rewards: list[TimeScoreReward],
    ):
        self.stage_id = stage_id
        self.stage_index = stage_index
        self.energy_cost = energy_cost
        self.xp_gain = xp_gain
        self.start_music = start_music
        self.base_percentage_boss_music = base_percentage_boss_music
        self.boss_music = boss_music
        self.item_drops = item_drops
        self.max_reward_claims = max_reward_claims
        self.time_score_rewards = time_score_rewards
        self.rand = rand

    def clear_item_drops(self):
        self.item_drops = []

    def apply_dict(self, dict_data: dict[str, Any]):
        self.energy_cost = dict_data.get("energy_cost", self.energy_cost)
        self.xp_gain = dict_data.get("xp_gain", self.xp_gain)
        self.start_music = dict_data.get("start_music", self.start_music)
        self.base_percentage_boss_music = dict_data.get(
            "base_percentage_boss_music", self.base_percentage_boss_music
        )
        self.boss_music = dict_data.get("boss_music", self.boss_music)
        self.rand = dict_data.get("rand", self.rand)
        self.max_reward_claims = dict_data.get(
            "max_reward_claims", self.max_reward_claims
        )
        item_drops = dict_data.get("item_drops")
        if item_drops is not None:
            current_item_drops = {i: item for i, item in enumerate(self.item_drops)}
            modded_item_drops = core.ModEditDictHandler(
                item_drops, current_item_drops
            ).get_dict(convert_int=True)
            for i, modded_item in modded_item_drops.items():
                item = current_item_drops.get(i)
                if item is None:
                    item = ItemDrop.create_empty()
                    self.item_drops.append(item)
                item.apply_dict(modded_item)
        time_score_rewards = dict_data.get("time_score_rewards")
        if time_score_rewards is not None:
            current_time_score_rewards = {
                i: item for i, item in enumerate(self.time_score_rewards)
            }
            modded_time_score_rewards = core.ModEditDictHandler(
                time_score_rewards, current_time_score_rewards
            ).get_dict(convert_int=True)
            for i, modded_time_score_reward in modded_time_score_rewards.items():
                time_score_reward = current_time_score_rewards.get(i)
                if time_score_reward is None:
                    time_score_reward = TimeScoreReward.create_empty()
                    self.time_score_rewards.append(time_score_reward)
                time_score_reward.apply_dict(modded_time_score_reward)

    @staticmethod
    def create_empty(stage_id: int, stage_index: int) -> "MapStageDataStage":
        return MapStageDataStage(
            stage_id,
            stage_index,
            0,
            0,
            0,
            0,
            0,
            0,
            [],
            0,
            [],
        )


class StageNameImage:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        image: "core.BCImage",
    ):
        self.stage_id = stage_id
        self.stage_index = stage_index
        self.image = image

    @staticmethod
    def get_file_name(stage_id: int, stage_index: int, lang: str) -> Optional[str]:
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_stage_data_type = map_index_type.get_map_stage_data_name_type()
        if map_stage_data_type is None:
            return None
        relative_stage_id = stage_id - map_index_type.value
        relative_stage_id_str = core.PaddedInt(relative_stage_id, 3).to_str()
        stage_index_str = core.PaddedInt(stage_index, 2).to_str()
        return f"mapsn{relative_stage_id_str}_{stage_index_str}_{map_stage_data_type.value.lower()}_{lang}.png"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        stage_id: int,
        stage_index: int,
    ):
        file_name = StageNameImage.get_file_name(
            stage_id, stage_index, game_data.localizable.get_lang()
        )
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        return StageNameImage(
            stage_id,
            stage_index,
            core.BCImage(file.dec_data),
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        file_name = StageNameImage.get_file_name(
            self.stage_id, self.stage_index, game_data.localizable.get_lang()
        )
        if file_name is None:
            return
        game_data.set_file(file_name, self.image.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        image = dict_data.get("image")
        if image is not None:
            self.image.apply_dict(image)

    @staticmethod
    def create_empty(stage_id: int, stage_index: int) -> "StageNameImage":
        return StageNameImage(
            stage_id,
            stage_index,
            core.BCImage.create_empty(),
        )


class MapNameImage:
    def __init__(
        self,
        stage_id: int,
        image: "core.BCImage",
    ):
        self.stage_id = stage_id
        self.image = image

    @staticmethod
    def get_file_name(stage_id: int, lang: str) -> Optional[str]:
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_stage_data_type = map_index_type.get_map_stage_data_name_type()
        if map_stage_data_type is None:
            return None
        relative_stage_id = stage_id - map_index_type.value
        relative_stage_id_str = core.PaddedInt(relative_stage_id, 3).to_str()
        return f"mapname{relative_stage_id_str}_{map_stage_data_type.value.lower()}_{lang}.png"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        stage_id: int,
    ):
        file_name = MapNameImage.get_file_name(
            stage_id, game_data.localizable.get_lang()
        )
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        return MapNameImage(
            stage_id,
            core.BCImage(file.dec_data),
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        file_name = MapNameImage.get_file_name(
            self.stage_id, game_data.localizable.get_lang()
        )
        if file_name is None:
            return
        game_data.set_file(file_name, self.image.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        image = dict_data.get("image")
        if image is not None:
            self.image.apply_dict(image)

    @staticmethod
    def create_empty(stage_id: int) -> "MapNameImage":
        return MapNameImage(
            stage_id,
            core.BCImage.create_empty(),
        )


class StageName:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        name: str,
    ):
        self.stage_id = stage_id
        self.stage_index = stage_index
        self.name = name

    def apply_dict(self, dict_data: dict[str, Any]):
        self.name = dict_data.get("name", self.name)

    @staticmethod
    def create_empty(stage_id: int, stage_index: int) -> "StageName":
        return StageName(
            stage_id,
            stage_index,
            "",
        )


class StageNames:
    def __init__(
        self,
        stage_id: int,
        names: dict[int, StageName],
    ):
        self.stage_id = stage_id
        self.names = names

    def get(self, stage_index: int) -> Optional[StageName]:
        return self.names.get(stage_index)

    def apply_dict(self, dict_data: dict[str, Any]):
        names = dict_data.get("names")
        if names is not None:
            current_names = self.names.copy()
            modded_names = core.ModEditDictHandler(names, current_names).get_dict(
                convert_int=True
            )
            for stage_id, modded_name in modded_names.items():
                stage = self.names.get(stage_id)
                if stage is None:
                    stage = StageName.create_empty(self.stage_id, stage_id)
                    self.names[stage_id] = stage
                stage.apply_dict(modded_name)

    @staticmethod
    def create_empty(stage_id: int) -> "StageNames":
        return StageNames(
            stage_id,
            {},
        )


class StageNameSet:
    def __init__(
        self,
        base_stage_id: int,
        names: dict[int, StageNames],
    ):
        self.base_stage_id = base_stage_id
        map_index_type = MapIndexType.from_index(base_stage_id)
        if map_index_type is None:
            raise ValueError(f"Invalid base stage id {base_stage_id}")
        self.map_index_type = map_index_type
        name_str = self.map_index_type.get_stage_name_name_type()
        if name_str is None:
            name_str = ""
        self.name_str = name_str
        self.names = names

    @staticmethod
    def get_file_name(base_stage_id: int, lang: str):
        map_index_type = MapIndexType.from_index(base_stage_id)
        if map_index_type is None:
            raise ValueError(f"Invalid base stage id {base_stage_id}")
        name_str = map_index_type.get_stage_name_name_type()
        if name_str is None:
            raise ValueError(f"Invalid base stage id {base_stage_id}")
        return f"StageName_{name_str.value}_{lang}.csv"

    @staticmethod
    def from_game_data(
        base_stage_id: int,
        game_data: "core.GamePacks",
    ) -> "StageNameSet":
        map_index_type = MapIndexType.from_index(base_stage_id)
        if map_index_type is None:
            raise ValueError(f"Invalid base stage id {base_stage_id}")
        name_str = map_index_type.get_stage_name_name_type()
        if name_str is None:
            return StageNameSet.create_empty(base_stage_id)
        file_name = StageNameSet.get_file_name(
            base_stage_id, game_data.localizable.get_lang()
        )
        file = game_data.find_file(file_name)
        if file is None:
            return StageNameSet.create_empty(base_stage_id)
        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
        )
        all_names: dict[int, StageNames] = {}
        for stage_index, line in enumerate(csv.lines):
            stage_id = base_stage_id + stage_index
            names: dict[int, StageName] = {}
            for i, name_str in enumerate(line):
                name = StageName(stage_id, i, name_str)
                names[name.stage_index] = name
            all_names[stage_id] = StageNames(stage_id, names)

        return StageNameSet(base_stage_id, all_names)

    def to_game_data(
        self,
        game_data: "core.GamePacks",
    ) -> None:
        file_name = StageNameSet.get_file_name(
            self.base_stage_id, game_data.localizable.get_lang()
        )
        file = game_data.find_file(file_name)
        if file is None:
            raise ValueError(f"Could not find file {file_name}")
        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=True,
        )
        remaining = self.names.copy()
        for stage_index, line in enumerate(csv.lines):
            stage_id = self.base_stage_id + stage_index
            names = self.names.get(stage_id)
            if names is None:
                continue
            for name_index in range(len(line)):
                name = names.names.get(name_index)
                if name is None:
                    continue
                line[name_index] = name.name
            csv.lines[stage_index] = line
            remaining.pop(stage_id)
        for stage_id, names in remaining.items():
            line = [name.name for name in names.names.values()]
            csv.lines.append(line)
        game_data.set_file(file_name, csv.to_data())

    def get(self, stage_id: int) -> Optional[StageNames]:
        return self.names.get(stage_id)

    def apply_dict(self, dict_data: dict[str, Any]):
        names = dict_data.get("names")
        if names is not None:
            current_names = self.names.copy()
            modded_names = core.ModEditDictHandler(names, current_names).get_dict(
                convert_int=True
            )
            for stage_id, modded_name in modded_names.items():
                stage = self.names.get(stage_id)
                if stage is None:
                    stage = StageNames.create_empty(stage_id)
                    self.names[stage_id] = stage
                stage.apply_dict(modded_name)

    @staticmethod
    def create_empty(base_stage_id: int) -> "StageNameSet":
        return StageNameSet(base_stage_id, {})


class StageNameSets:
    def __init__(
        self,
        sets: dict[MapIndexType, StageNameSet],
    ):
        self.sets = sets

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
    ) -> "StageNameSets":
        sets: dict[MapIndexType, StageNameSet] = {}
        ids = MapIndexType.get_all()
        for base_stage_id in ids:
            set = StageNameSet.from_game_data(base_stage_id.value, game_data)
            sets[base_stage_id] = set
        return StageNameSets(sets)

    def to_game_data(
        self,
        game_data: "core.GamePacks",
    ) -> None:
        for set in self.sets.values():
            set.to_game_data(game_data)

    def get(self, stage_id: int) -> Optional[StageNames]:
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        set = self.sets.get(map_index_type)
        if set is None:
            return None
        return set.get(stage_id)

    def set(self, stage_id: int, names: StageNames) -> None:
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            raise ValueError(f"Invalid stage id {stage_id}")
        set = self.sets.get(map_index_type)
        if set is None:
            set = StageNameSet(stage_id, {})
            self.sets[map_index_type] = set
        set.names[stage_id] = names

    def apply_dict(self, dict_data: dict[str, Any]):
        sets = dict_data.get("sets")
        if sets is not None:
            current_sets = self.sets.copy()
            current_sets = {key.value: value for key, value in current_sets.items()}
            modded_sets = core.ModEditDictHandler(sets, current_sets).get_dict(
                convert_int=True
            )
            for base_stage_id, modded_set in modded_sets.items():
                base_stage_id = MapIndexType(base_stage_id)
                set = self.sets.get(base_stage_id)
                if set is None:
                    set = StageNameSet.create_empty(base_stage_id.value)
                    self.sets[base_stage_id] = set
                set.apply_dict(modded_set)

    @staticmethod
    def create_empty() -> "StageNameSets":
        return StageNameSets({})


class StageOptionSet:
    def __init__(
        self,
        map_id: int,
        support: int,
        stage_index: int,
        rarity_limit: int,
        deploy_limit: int,
        row_limit: int,
        cost_limit_lower: int,
        cost_limit_upper: int,
        cat_group_id: int,
    ):
        self.map_id = map_id
        self.support = support
        self.stage_index = stage_index
        self.rarity_limit = rarity_limit
        self.deploy_limit = deploy_limit
        self.row_limit = row_limit
        self.cost_limit_lower = cost_limit_lower
        self.cost_limit_upper = cost_limit_upper
        self.cat_group_id = cat_group_id

    @staticmethod
    def from_row(
        row: list[int],
    ) -> "StageOptionSet":
        return StageOptionSet(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            row[8],
        )

    def to_row(self) -> list[int]:
        return [
            self.map_id,
            self.support,
            self.stage_index,
            self.rarity_limit,
            self.deploy_limit,
            self.row_limit,
            self.cost_limit_lower,
            self.cost_limit_upper,
            self.cat_group_id,
        ]

    def apply_dict(self, dict_data: dict[str, Any]):
        self.support = dict_data.get("support", self.support)
        self.stage_index = dict_data.get("stage_index", self.stage_index)
        self.rarity_limit = dict_data.get("rarity_limit", self.rarity_limit)
        self.deploy_limit = dict_data.get("deploy_limit", self.deploy_limit)
        self.row_limit = dict_data.get("row_limit", self.row_limit)
        self.cost_limit_lower = dict_data.get("cost_limit_lower", self.cost_limit_lower)
        self.cost_limit_upper = dict_data.get("cost_limit_upper", self.cost_limit_upper)
        self.cat_group_id = dict_data.get("cat_group_id", self.cat_group_id)

    @staticmethod
    def create_empty() -> "StageOptionSet":
        return StageOptionSet(
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )


class StageOption:
    def __init__(
        self,
        sets: dict[int, StageOptionSet],
    ):
        self.sets = sets

    @staticmethod
    def get_file_name() -> str:
        return "Stage_option.csv"

    @staticmethod
    def from_game_data(game_packs: "core.GamePacks") -> "StageOption":
        file = game_packs.find_file(StageOption.get_file_name())
        if file is None:
            return StageOption.create_empty()

        csv_file = core.CSV(file.dec_data)
        sets: dict[int, StageOptionSet] = {}
        for line in csv_file.lines:
            set = StageOptionSet.from_row([int(x) for x in line])
            sets[set.map_id] = set
        return StageOption(sets)

    def to_game_data(self, game_packs: "core.GamePacks") -> None:
        file = game_packs.find_file(self.get_file_name())
        if file is None:
            return

        csv_file = core.CSV(file.dec_data)
        remaining = self.sets.copy()
        for i, line in enumerate(csv_file.lines):
            map_id = int(line[0])
            if map_id in remaining:
                csv_file.lines[i] = [str(x) for x in remaining[map_id].to_row()]
                del remaining[map_id]
        for set in remaining.values():
            csv_file.lines.append([str(x) for x in set.to_row()])

        game_packs.set_file(self.get_file_name(), csv_file.to_data())

    def get(self, map_id: int) -> Optional[StageOptionSet]:
        if map_id in self.sets:
            return self.sets[map_id]
        return None

    def set(self, map_id: int, set: StageOptionSet) -> None:
        set.map_id = map_id
        self.sets[map_id] = set

    def apply_dict(self, dict_data: dict[str, Any]):
        sets = dict_data.get("sets")
        if sets is not None:
            current_sets = self.sets.copy()
            modded_sets = core.ModEditDictHandler(sets, current_sets).get_dict(
                convert_int=True
            )
            for map_id, modded_set in modded_sets.items():
                set = current_sets.get(map_id)
                if set is None:
                    set = StageOptionSet.create_empty()
                set.apply_dict(modded_set)
                self.set(map_id, set)

    @staticmethod
    def create_empty() -> "StageOption":
        return StageOption({})


class MapStageData:
    def __init__(
        self,
        stage_id: int,
        map_number: int,
        item_reward_type: int,
        score_reward_type: int,
        unknown_1: int,
        unknown_2: int,
        map_pattern: int,
        data: dict[int, MapStageDataStage],
    ):
        self.stage_id = stage_id
        self.map_number = map_number
        self.item_reward_type = item_reward_type
        self.score_reward_type = score_reward_type
        self.unknown_1 = unknown_1
        self.unknown_2 = unknown_2
        self.map_pattern = map_pattern
        self.data = data

    def apply_dict(self, dict_data: dict[str, Any]):
        self.map_number = dict_data.get("map_number", self.map_number)
        self.item_reward_type = dict_data.get("item_reward_type", self.item_reward_type)
        self.score_reward_type = dict_data.get(
            "score_reward_type", self.score_reward_type
        )
        self.unknown_1 = dict_data.get("unknown_1", self.unknown_1)
        self.unknown_2 = dict_data.get("unknown_2", self.unknown_2)
        self.map_pattern = dict_data.get("map_pattern", self.map_pattern)
        data = dict_data.get("data")
        if data is not None:
            current_data = self.data.copy()
            modded_data = core.ModEditDictHandler(data, current_data).get_dict(
                convert_int=True
            )
            for stage_id, modded_stage in modded_data.items():
                stage = current_data.get(stage_id)
                if stage is None:
                    stage = MapStageDataStage.create_empty(self.stage_id, stage_id)
                stage.apply_dict(modded_stage)
                self.data[stage_id] = stage

    @staticmethod
    def get_file_name(stage_id: int):
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_type = map_index_type.get_map_stage_data_name_type()
        if map_type is None:
            return None
        stage_index = stage_id - map_index_type.value
        stage_index_str = core.PaddedInt(stage_index, 3).to_str()
        return f"MapStageData{map_type.value}_{stage_index_str}.csv"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks", stage_id: int
    ) -> Optional["MapStageData"]:
        file_name = MapStageData.get_file_name(stage_id)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        data: dict[int, MapStageDataStage] = {}
        line_1 = csv.read_line()
        if line_1 is None:
            return None
        map_number = int(line_1[0])
        item_reward_type = int(line_1[1])
        score_reward_type = int(line_1[2])
        unknown_1 = int(line_1[3])
        unknown_2 = int(line_1[4])

        line_2 = csv.read_line()
        if line_2 is None:
            return None
        map_pattern = int(line_2[0])

        for stage_index, line in enumerate(csv.lines[2:]):
            try:
                energy = int(line[0])
            except ValueError:
                break
            xp = int(line[1])
            mus_id0 = int(line[2])
            mus_hp = int(line[3])
            mus_id1 = int(line[4])
            reward_once = int(line[-1])
            is_time = len(line) > 15
            time: list[TimeScoreReward] = []
            item_drops: list[ItemDrop] = []
            rand = 0

            if is_time:
                for i in range(8, 15):
                    if int(line[i]) != -2:
                        is_time = False
                        break
            if is_time:
                length = (len(line) - 17) // 3
                for i in range(length):
                    time.append(
                        TimeScoreReward(
                            int(line[16 + i * 3]),
                            int(line[17 + i * 3]),
                            int(line[18 + i * 3]),
                        )
                    )
            is_multi = (not is_time) and len(line) > 9
            if is_multi:
                rand = int(line[8])
                drop_length = (len(line) - 7) // 3
                for i in range(0, drop_length):
                    item_drops.append(
                        ItemDrop(
                            int(line[6 + i * 3]),
                            int(line[7 + i * 3]),
                            int(line[8 + i * 3]),
                        )
                    )
            if (len(item_drops) > 0) or not is_multi:
                if len(item_drops) == 0:
                    item_drops.append(
                        ItemDrop(
                            int(line[5]),
                            int(line[6]),
                            int(line[7]),
                        )
                    )
                else:
                    item_drops[0] = ItemDrop(
                        int(line[5]),
                        int(line[6]),
                        int(line[7]),
                    )
            data[stage_index] = MapStageDataStage(
                stage_id,
                stage_index,
                energy,
                xp,
                mus_id0,
                mus_hp,
                mus_id1,
                rand,
                item_drops,
                reward_once,
                time,
            )
        return MapStageData(
            stage_id,
            map_number,
            item_reward_type,
            score_reward_type,
            unknown_1,
            unknown_2,
            map_pattern,
            data,
        )

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        file_name = MapStageData.get_file_name(self.stage_id)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        line_1: list[str] = [
            str(self.map_number),
            str(self.item_reward_type),
            str(self.score_reward_type),
            str(self.unknown_1),
            str(self.unknown_2),
        ]
        csv.lines[0] = line_1
        line_2: list[str] = [str(self.map_pattern)]
        csv.lines[1] = line_2
        for i, stage in self.data.items():
            line: list[str] = [
                str(stage.energy_cost),
                str(stage.xp_gain),
                str(stage.start_music),
                str(stage.base_percentage_boss_music),
                str(stage.boss_music),
            ]
            if len(stage.item_drops) > 0:
                line.append(str(stage.item_drops[0].probability))
                line.append(str(stage.item_drops[0].item_id))
                line.append(str(stage.item_drops[0].amount))
            else:
                line.append(str(0))
                line.append(str(0))
                line.append(str(0))
            if len(stage.item_drops) > 1:
                line.append(str(stage.rand))
            if len(stage.item_drops) > 1:
                for drop in stage.item_drops[1:]:
                    line.append(str(drop.probability))
                    line.append(str(drop.item_id))
                    line.append(str(drop.amount))
            if stage.time_score_rewards:
                line[8:15] = [str(-2)] * 7
                line.append(str(1))
            for time in stage.time_score_rewards:
                line.append(str(time.score))
                line.append(str(time.item_id))
                line.append(str(time.amount))
            line.append(str(stage.max_reward_claims))
            csv.lines[i + 2] = line

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty(stage_id: int) -> "MapStageData":
        return MapStageData(
            stage_id,
            0,
            0,
            0,
            0,
            0,
            0,
            {},
        )


class Map:
    def __init__(
        self,
        stage_id: int,
        map_option: MapOption,
        map_stage_data: MapStageData,
        stages: dict[int, "Stage"],
        map_name_image: MapNameImage,
        restriction: Optional[StageOptionSet] = None,
    ):
        self.stage_id = stage_id
        self.map_option = map_option
        self.map_stage_data = map_stage_data
        self.stages = stages
        self.map_name_image = map_name_image
        self.restriction = restriction

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        stage_id: int,
        map_options: MapOptions,
        stage_names: StageNames,
        stage_options: StageOption,
    ) -> Optional["Map"]:
        map_option = map_options.get(stage_id)
        map_stage_data = MapStageData.from_game_data(game_data, stage_id)
        map_name_image = MapNameImage.from_game_data(game_data, stage_id)
        restriction = stage_options.get(stage_id)
        i = 0
        stages: dict[int, Stage] = {}
        while True:
            stage_name = stage_names.get(i)
            if stage_name is None:
                break
            stage = Stage.from_game_data(game_data, stage_id, i, stage_name)
            if stage is None:
                break
            stages[i] = stage
            i += 1
        if map_option is None or map_stage_data is None or map_name_image is None:
            return None

        return Map(
            stage_id, map_option, map_stage_data, stages, map_name_image, restriction
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        self.map_stage_data.to_game_data(game_data)
        self.map_name_image.to_game_data(game_data)
        for stage in self.stages.values():
            stage.to_game_data(game_data)

    def get_names(self) -> StageNames:
        return StageNames(self.stage_id, {k: v.name for k, v in self.stages.items()})

    def apply_dict(self, dict_data: dict[str, Any]):
        self.map_option.apply_dict(dict_data)
        self.map_stage_data.apply_dict(dict_data)
        self.map_name_image.apply_dict(dict_data)
        stages = dict_data.get("stages")
        if stages is not None:
            current_stages = self.stages.copy()
            modded_stages = core.ModEditDictHandler(stages, current_stages).get_dict(
                convert_int=True
            )
            for stage_id, modded_stage in modded_stages.items():
                stage = self.stages.get(stage_id)
                if stage is None:
                    stage = Stage.create_empty(self.stage_id, stage_id)
                stage.apply_dict(modded_stage)
                self.stages[stage_id] = stage

    @staticmethod
    def create_empty(stage_id: int) -> "Map":
        return Map(
            stage_id,
            MapOption.create_empty(stage_id),
            MapStageData.create_empty(stage_id),
            {},
            MapNameImage.create_empty(stage_id),
        )


class Maps(core.EditableClass):
    def __init__(self, maps: dict[int, Map]):
        self.data = maps
        super().__init__(maps)

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        if game_data.maps is not None:
            return game_data.maps
        map_options = MapOptions.from_game_data(game_data)
        stage_name_sets = StageNameSets.from_game_data(game_data)
        stage_options = StageOption.from_game_data(game_data)
        maps: dict[int, Map] = {}
        for stage_id in map_options.options.keys():
            stage_names = stage_name_sets.get(stage_id)
            if stage_names is None:
                continue
            map = Map.from_game_data(
                game_data, stage_id, map_options, stage_names, stage_options
            )
            if map is None:
                continue
            maps[stage_id] = map

        mapso = Maps(maps)
        game_data.maps = mapso
        return mapso

    def to_game_data(self, game_data: "core.GamePacks"):
        map_options = MapOptions({})
        stage_name_sets = StageNameSets({})
        stage_options = StageOption({})
        for map in self.data.values():
            map.to_game_data(game_data)
            map_options.set(map.map_option)
            stage_name_sets.set(map.map_option.stage_id, map.get_names())
            if map.restriction is not None:
                stage_options.set(map.restriction.map_id, map.restriction)

        map_options.to_game_data(game_data)
        stage_name_sets.to_game_data(game_data)
        stage_options.to_game_data(game_data)

    @staticmethod
    def get_maps_json_file_name() -> "core.Path":
        return core.Path("maps").add("maps.json")

    @staticmethod
    def create_empty() -> "Maps":
        return Maps({})

    def set_map(self, map: Map):
        self.data[map.map_option.stage_id] = map
