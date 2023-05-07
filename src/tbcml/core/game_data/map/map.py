import enum
from typing import Optional
from tbcml.core.game_data import pack
from tbcml.core import io


class StageNameNameType(enum.Enum):
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
        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapStageDataNameType(enum.Enum):
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
        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapNameType(enum.Enum):
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
        for index_type in MapIndexType:
            if index_type.name == self.name:
                return index_type
        return None


class MapIndexType(enum.Enum):
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
        return sorted(MapIndexType, key=lambda x: x.value)

    def get_map_name_type(self) -> Optional[MapNameType]:
        for name_type in MapNameType:
            if name_type.name == self.name:
                return name_type
        return None

    def get_map_stage_data_name_type(self) -> Optional[MapStageDataNameType]:
        for name_type in MapStageDataNameType:
            if name_type.name == self.name:
                return name_type
        return None

    def get_stage_name_name_type(self) -> Optional[StageNameNameType]:
        for name_type in StageNameNameType:
            if name_type.name == self.name:
                return name_type
        return None

    @staticmethod
    def from_index(index: int) -> Optional["MapIndexType"]:
        types_sorted = sorted(MapIndexType, key=lambda x: x.value)
        for i in range(len(types_sorted)):
            if index < types_sorted[i].value:
                return types_sorted[i - 1]
            if index == types_sorted[i].value:
                return types_sorted[i]
        return None


class ResetType(enum.Enum):
    NONE = 0
    REWARD = 1
    CLEAR_STATUS = 2
    NUMBER_OF_PLAYS = 3


class MapOption:
    def __init__(
        self,
        stage_id: int,
        number_of_stars: int,
        star_mult_1: int,
        star_mult_2: int,
        star_mult_3: int,
        star_mult_4: int,
        guerrilla_set: int,
        reset_type: ResetType,
        one_time_display: bool,
        display_order: int,
        interval: int,
        challenge_flag: bool,
        difficulty_mask: int,
        hide_after_clear: bool,
        map_comment: str,
    ):
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


class MapOptions:
    def __init__(self, options: dict[int, MapOption]):
        self.options = options

    def get(self, stage_id: int) -> Optional[MapOption]:
        return self.options.get(stage_id)

    def set(self, option: MapOption):
        self.options[option.stage_id] = option

    @staticmethod
    def get_file_name() -> str:
        return "Map_option.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "MapOptions":
        map_options = game_data.find_file(MapOptions.get_file_name())
        if map_options is None:
            return MapOptions.create_empty()
        options: dict[int, MapOption] = {}
        csv = io.bc_csv.CSV(map_options.dec_data)
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
                bool(line[8]),
                int(line[9]),
                int(line[10]),
                bool(line[11]),
                int(line[12]),
                bool(line[13]),
                line[14],
            )
        return MapOptions(options)

    def to_game_data(self, game_data: "pack.GamePacks"):
        map_options = game_data.find_file(MapOptions.get_file_name())
        if map_options is None:
            return None
        csv = io.bc_csv.CSV(map_options.dec_data)
        remaining = self.options.copy()
        for i, line in enumerate(csv.lines[1:]):
            stage_id = int(line[0])
            option = self.options.get(stage_id)
            if option is None:
                continue
            line[1] = str(option.number_of_stars)
            line[2] = str(option.star_mult_1)
            line[3] = str(option.star_mult_2)
            line[4] = str(option.star_mult_3)
            line[5] = str(option.star_mult_4)
            line[6] = str(option.guerrilla_set)
            line[7] = str(option.reset_type.value)
            line[8] = "1" if option.one_time_display else "0"
            line[9] = str(option.display_order)
            line[10] = str(option.interval)
            line[11] = "1" if option.challenge_flag else "0"
            line[12] = str(option.difficulty_mask)
            line[13] = "1" if option.hide_after_clear else "0"
            line[14] = option.map_comment
            csv.lines[i + 1] = line
            del remaining[stage_id]
        for option in remaining.values():
            line: list[str] = []
            line.append(str(option.stage_id))
            line.append(str(option.number_of_stars))
            line.append(str(option.star_mult_1))
            line.append(str(option.star_mult_2))
            line.append(str(option.star_mult_3))
            line.append(str(option.star_mult_4))
            line.append(str(option.guerrilla_set))
            line.append(str(option.reset_type.value))
            line.append("1" if option.one_time_display else "0")
            line.append(str(option.display_order))
            line.append(str(option.interval))
            line.append("1" if option.challenge_flag else "0")
            line.append(str(option.difficulty_mask))
            line.append("1" if option.hide_after_clear else "0")
            line.append(option.map_comment)
            csv.lines.append(line)

        game_data.set_file(MapOptions.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "MapOptions":
        return MapOptions({})


class EnemyRow:
    def __init__(
        self,
        index: int,
        enemy_id: int,
        total_spawn_count: int,
        start_frame: int,
        min_spawn_interval: int,
        max_spawn_interval: int,
        spawn_base_percentage: int,
        min_z: int,
        max_z: int,
        boss_flag: bool,
        magnification: int,
        spawn_1: Optional[int] = None,
        castle_1: Optional[int] = None,
        group: Optional[int] = None,
        kill_count: Optional[int] = None,
    ):
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


class StageStats:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        castle_type: Optional[int],
        no_continues: bool,
        ex_stage_prob: int,
        ex_stage_chapter_id: int,
        ex_stage_stage_id: int,
        stage_width: int,
        base_health: int,
        min_production_frames: int,
        max_production_frames: int,
        background_type: int,
        max_enemy_count: int,
        unused: int,
        enemies: dict[int, EnemyRow],
    ):
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
    def get_file_name(stage_id: int, stage_index: int):
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_name_type = map_index_type.get_map_name_type()
        if map_name_type is None:
            return None
        stage_id_index = stage_id - map_index_type.value
        stage_id_index_str = io.data.PaddedInt(stage_id_index, 3).to_str()
        stage_index_str = io.data.PaddedInt(stage_index, 2).to_str()
        return f"stage{map_name_type.value}{stage_id_index_str}_{stage_index_str}.csv"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", stage_id: int, stage_index: int
    ) -> Optional["StageStats"]:
        file_name = StageStats.get_file_name(stage_id, stage_index)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        line_1 = csv.read_line()
        if line_1 is None:
            return None
        castle_type = int(line_1[0])
        no_continues = bool(line_1[1])
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
            boss_flag = bool(line[8])
            magnification = int(line[9])
            spawn_1 = None
            castle_1 = None
            group = None
            kill_count = None
            if len(line) > 10:
                spawn_1 = int(line[10])
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

    def to_game_data(self, game_data: "pack.GamePacks"):
        file_name = StageStats.get_file_name(self.stage_id, self.stage_index)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        line_1 = [
            str(self.castle_type),
            "1" if self.no_continues else "0",
            str(self.ex_stage_prob),
            str(self.ex_stage_chapter_id),
            str(self.ex_stage_stage_id),
        ]
        csv.lines[0] = line_1
        line_2 = [
            str(self.stage_width),
            str(self.base_health),
            str(self.min_production_frames),
            str(self.max_production_frames),
            str(self.background_type),
            str(self.max_enemy_count),
            str(self.unused),
        ]
        csv.lines[1] = line_2
        for i, enemy in self.enemies.items():
            line: list[str] = [
                str(enemy.enemy_id),
                str(enemy.total_spawn_count),
                str(enemy.start_frame),
                str(enemy.min_spawn_interval),
                str(enemy.max_spawn_interval),
                str(enemy.spawn_base_percentage),
                str(enemy.min_z),
                str(enemy.max_z),
                "1" if enemy.boss_flag else "0",
                str(enemy.magnification),
            ]
            if enemy.spawn_1 is not None:
                line.append(str(enemy.spawn_1))
            if enemy.castle_1 is not None:
                line.append(str(enemy.castle_1))
            if enemy.group is not None:
                line.append(str(enemy.group))
            if enemy.kill_count is not None:
                line.append(str(enemy.kill_count))

            csv.lines[i + 2] = line
        game_data.set_file(file_name, csv.to_data())


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
        game_data: "pack.GamePacks",
        stage_id: int,
        stage_index: int,
        name: "StageName",
    ) -> Optional["Stage"]:
        stage_stats = StageStats.from_game_data(game_data, stage_id, stage_index)
        stage_image = StageNameImage.from_game_data(game_data, stage_id, stage_index)
        if stage_stats is None or stage_image is None:
            return None
        return Stage(stage_id, stage_index, stage_stats, name, stage_image)

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.stage_stats.to_game_data(game_data)
        self.name_image.to_game_data(game_data)


class ItemDrop:
    def __init__(self, probability: int, item_id: int, amount: int):
        self.item_id = item_id
        self.amount = amount
        self.probability = probability


class TimeScoreReward:
    def __init__(self, score: int, item_id: int, amount: int):
        self.score = score
        self.item_id = item_id
        self.amount = amount


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


class StageNameImage:
    def __init__(
        self,
        stage_id: int,
        stage_index: int,
        image: "io.bc_image.BCImage",
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
        relative_stage_id_str = io.data.PaddedInt(relative_stage_id, 3).to_str()
        stage_index_str = io.data.PaddedInt(stage_index, 2).to_str()
        return f"mapsn{relative_stage_id_str}_{stage_index_str}_{map_stage_data_type.value.lower()}_{lang}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
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
            io.bc_image.BCImage(file.dec_data),
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        file_name = StageNameImage.get_file_name(
            self.stage_id, self.stage_index, game_data.localizable.get_lang()
        )
        if file_name is None:
            return
        game_data.set_file(file_name, self.image.to_data())


class MapNameImage:
    def __init__(
        self,
        stage_id: int,
        image: "io.bc_image.BCImage",
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
        relative_stage_id_str = io.data.PaddedInt(relative_stage_id, 3).to_str()
        return f"mapname{relative_stage_id_str}_{map_stage_data_type.value.lower()}_{lang}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
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
            io.bc_image.BCImage(file.dec_data),
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        file_name = MapNameImage.get_file_name(
            self.stage_id, game_data.localizable.get_lang()
        )
        if file_name is None:
            return
        game_data.set_file(file_name, self.image.to_data())


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
        game_data: "pack.GamePacks",
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
        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
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
        game_data: "pack.GamePacks",
    ) -> None:
        file_name = StageNameSet.get_file_name(
            self.base_stage_id, game_data.localizable.get_lang()
        )
        file = game_data.find_file(file_name)
        if file is None:
            raise ValueError(f"Could not find file {file_name}")
        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
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
        game_data: "pack.GamePacks",
    ) -> "StageNameSets":
        sets: dict[MapIndexType, StageNameSet] = {}
        ids = MapIndexType.get_all()
        for base_stage_id in ids:
            set = StageNameSet.from_game_data(base_stage_id.value, game_data)
            sets[base_stage_id] = set
        return StageNameSets(sets)

    def to_game_data(
        self,
        game_data: "pack.GamePacks",
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
    def from_game_data(game_packs: "pack.GamePacks") -> "StageOption":
        file = game_packs.find_file(StageOption.get_file_name())
        if file is None:
            return StageOption.create_empty()

        csv_file = io.bc_csv.CSV(file.dec_data)
        sets: dict[int, StageOptionSet] = {}
        for line in csv_file.lines:
            set = StageOptionSet.from_row([int(x) for x in line])
            sets[set.map_id] = set
        return StageOption(sets)

    def to_game_data(self, game_packs: "pack.GamePacks") -> None:
        file = game_packs.find_file(self.get_file_name())
        if file is None:
            return

        csv_file = io.bc_csv.CSV(file.dec_data)
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

    @staticmethod
    def get_file_name(stage_id: int):
        map_index_type = MapIndexType.from_index(stage_id)
        if map_index_type is None:
            return None
        map_type = map_index_type.get_map_stage_data_name_type()
        if map_type is None:
            return None
        stage_index = stage_id - map_index_type.value
        stage_index_str = io.data.PaddedInt(stage_index, 3).to_str()
        return f"MapStageData{map_type.value}_{stage_index_str}.csv"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", stage_id: int
    ) -> Optional["MapStageData"]:
        file_name = MapStageData.get_file_name(stage_id)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
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
            energy = int(line[0])
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

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        file_name = MapStageData.get_file_name(self.stage_id)
        if file_name is None:
            return None
        file = game_data.find_file(file_name)
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
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
        game_data: "pack.GamePacks",
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

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.map_stage_data.to_game_data(game_data)
        self.map_name_image.to_game_data(game_data)
        for stage in self.stages.values():
            stage.to_game_data(game_data)

    def get_names(self) -> StageNames:
        return StageNames(self.stage_id, {k: v.name for k, v in self.stages.items()})


class Maps:
    def __init__(self, maps: dict[int, Map]):
        self.maps = maps

    def get(self, stage_id: int) -> Optional[Map]:
        return self.maps.get(stage_id)

    def set(self, map: Map):
        self.maps[map.map_option.stage_id] = map

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks"):
        map_options = MapOptions.from_game_data(game_data)
        stage_name_sets = StageNameSets.from_game_data(game_data)
        stage_options = StageOption.from_game_data(game_data)
        maps: dict[int, Map] = {}
        stage_id = 0
        while stage_id < 100000:
            stage_names = stage_name_sets.get(stage_id)
            if stage_names is None:
                stage_id += 1
                continue
            map = Map.from_game_data(
                game_data, stage_id, map_options, stage_names, stage_options
            )
            if map is None:
                stage_id += 1
                continue
            maps[stage_id] = map
            stage_id += 1
        return Maps(maps)

    def to_game_data(self, game_data: "pack.GamePacks"):
        map_options = MapOptions({})
        stage_name_sets = StageNameSets({})
        stage_options = StageOption({})
        for map in self.maps.values():
            map.to_game_data(game_data)
            map_options.set(map.map_option)
            stage_name_sets.set(map.map_option.stage_id, map.get_names())
            if map.restriction is not None:
                stage_options.set(map.restriction.map_id, map.restriction)

        map_options.to_game_data(game_data)
        stage_name_sets.to_game_data(game_data)
        stage_options.to_game_data(game_data)

    @staticmethod
    def get_maps_json_file_name() -> "io.path.Path":
        return io.path.Path("maps").add("maps.json")

    @staticmethod
    def create_empty() -> "Maps":
        return Maps({})

    def set_map(self, map: Map):
        self.maps[map.map_option.stage_id] = map
