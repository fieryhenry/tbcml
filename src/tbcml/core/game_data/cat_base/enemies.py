from typing import Any, Optional
from tbcml import core


class EnemyStats:
    def __init__(self, enemy_id: int, raw_data: list[Optional[int]]):
        self.enemy_id = enemy_id
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def extend(self, raw_data: list[Optional[int]]) -> list[Optional[int]]:
        length = 102
        raw_data = raw_data + [None] * (length - len(raw_data))
        return raw_data

    def has_targeted_effect(self) -> bool:
        to_check = [
            self.knockback.prob.percent if self.knockback.prob else None,
            self.freeze.prob.percent if self.freeze.prob else None,
            self.slow.prob.percent if self.slow.prob else None,
            self.weaken.prob.percent if self.weaken.prob else None,
            self.warp.prob.percent if self.warp.prob else None,
            self.curse.prob.percent if self.curse.prob else None,
            self.dodge.prob.percent if self.dodge.prob else None,
        ]
        return any(to_check)

    def assign(self, raw_data: list[Optional[int]]):
        self.hp = raw_data[0]
        self.kbs = raw_data[1]
        self.speed = raw_data[2]
        self.attack_interval = core.Frames.from_pair_frames(raw_data[4])
        self.range = raw_data[5]
        self.money_drop = raw_data[6]
        self.collision_start = raw_data[7]
        self.collision_width = raw_data[8]
        self.unused = raw_data[9]
        self.red = core.unit_bool(raw_data[10])
        self.area_attack = core.unit_bool(raw_data[11])
        self.floating = core.unit_bool(raw_data[13])
        self.black = core.unit_bool(raw_data[14])
        self.metal = core.unit_bool(raw_data[15])
        self.traitless = core.unit_bool(raw_data[16])
        self.angel = core.unit_bool(raw_data[17])
        self.alien = core.unit_bool(raw_data[18])
        self.zombie = core.unit_bool(raw_data[19])
        self.knockback = core.Knockback.from_values(raw_data[20])
        self.freeze = core.Freeze.from_values(raw_data[21], raw_data[22])
        self.slow = core.Slow.from_values(raw_data[23], raw_data[24])
        self.crit = core.Crit.from_values(raw_data[25])
        self.base_destroyer = core.unit_bool(raw_data[26])
        self.wave = core.Wave.from_values(
            raw_data[27], raw_data[28], core.unit_bool(raw_data[86])
        )
        self.weaken = core.Weaken.from_values(raw_data[29], raw_data[30], raw_data[31])
        self.strengthen = core.Strengthen.from_values(raw_data[32], raw_data[33])
        self.survive_lethal_strike = core.SurviveLethalStrike.from_values(raw_data[34])
        self.wave_immunity = core.unit_bool(raw_data[37])
        self.wave_blocker = core.unit_bool(raw_data[38])
        self.knockback_immunity = core.unit_bool(raw_data[39])
        self.freeze_immunity = core.unit_bool(raw_data[40])
        self.slow_immunity = core.unit_bool(raw_data[41])
        self.weaken_immunity = core.unit_bool(raw_data[42])
        self.burrow = core.Burrow.from_values(raw_data[43], raw_data[44])
        self.revive = core.Revive.from_values(raw_data[45], raw_data[46], raw_data[47])
        self.witch = core.unit_bool(raw_data[48])
        self.base = core.unit_bool(raw_data[49])
        self.attack_state = core.AttackState.from_values(raw_data[50], raw_data[52])
        self.time_before_death = (
            core.Frames(raw_data[51]) if raw_data[51] is not None else None
        )
        self.spawn_anim = core.SpawnAnim.from_values(
            raw_data[53], core.unit_bool(raw_data[62])
        )
        self.soul_anim = core.SoulAnim(raw_data[54], core.unit_bool(raw_data[63]))
        self.barrier = core.Barrier.from_values(raw_data[64])
        self.warp = core.Warp.from_values(
            raw_data[65], raw_data[66], raw_data[67], raw_data[68]
        )
        self.starred_alien = core.unit_bool(raw_data[69])
        self.warp_blocker = core.unit_bool(raw_data[70])
        self.eva_angel = core.unit_bool(raw_data[71])
        self.relic = core.unit_bool(raw_data[72])
        self.curse = core.Curse.from_values(raw_data[73], raw_data[74])
        self.savage_blow = core.SavageBlow.from_values(raw_data[75], raw_data[76])
        self.dodge = core.Dodge.from_values(raw_data[77], raw_data[78])
        self.toxic = core.Toxic.from_values(raw_data[79], raw_data[80])
        self.surge = core.Surge.from_values(
            raw_data[81], raw_data[82], raw_data[83], raw_data[84]
        )
        self.surge_immunity = core.unit_bool(raw_data[85])
        self.shield = core.Shield.from_values(raw_data[87], raw_data[88])
        self.death_surge = core.Surge.from_values(
            raw_data[89], raw_data[90], raw_data[91], raw_data[92]
        )
        self.aku = core.unit_bool(raw_data[93])
        self.baron = core.unit_bool(raw_data[94])
        self.behemoth = core.unit_bool(raw_data[101])

        self.attack_1 = core.Attack.from_values(
            raw_data[3],
            raw_data[12],
            core.unit_bool(raw_data[59]),
            True,
            raw_data[35],
            raw_data[36],
        )
        self.attack_2 = core.Attack.from_values(
            raw_data[55],
            raw_data[57],
            core.unit_bool(raw_data[60]),
            core.unit_bool(raw_data[95]),
            raw_data[96],
            raw_data[97],
        )
        self.attack_3 = core.Attack.from_values(
            raw_data[56],
            raw_data[58],
            core.unit_bool(raw_data[61]),
            core.unit_bool(raw_data[98]),
            raw_data[99],
            raw_data[100],
        )

    def to_raw_data(self) -> list[Optional[int]]:
        return [
            self.hp,  # 0
            self.kbs,  # 1
            self.speed,  # 2
            self.attack_1.damage,  # 3
            self.attack_interval.pair_frames
            if self.attack_interval is not None
            else None,  # 4
            self.range,  # 5
            self.money_drop,  # 6
            self.collision_start,  # 7
            self.collision_width,  # 8
            self.unused,  # 9
            core.unit_int(self.red),  # 10
            core.unit_int(self.area_attack),  # 11
            self.attack_1.foreswing.frames
            if self.attack_1.foreswing is not None
            else None,  # 12
            core.unit_int(self.floating),  # 13
            core.unit_int(self.black),  # 14
            core.unit_int(self.metal),  # 15
            core.unit_int(self.traitless),  # 16
            core.unit_int(self.angel),  # 17
            core.unit_int(self.alien),  # 18
            core.unit_int(self.zombie),  # 19
            self.knockback.prob.percent
            if self.knockback.prob is not None
            else None,  # 20
            self.freeze.prob.percent if self.freeze.prob is not None else None,  # 21
            self.freeze.time.frames if self.freeze.time is not None else None,  # 22
            self.slow.prob.percent if self.slow.prob is not None else None,  # 23
            self.slow.time.frames if self.slow.time is not None else None,  # 24
            self.crit.prob.percent if self.crit.prob is not None else None,  # 25
            core.unit_int(self.base_destroyer),  # 26
            self.wave.prob.percent if self.wave.prob is not None else None,  # 27
            self.wave.level,  # 28
            self.weaken.prob.percent if self.weaken.prob is not None else None,  # 29
            self.weaken.time.frames if self.weaken.time is not None else None,  # 30
            self.weaken.multiplier,  # 31
            self.strengthen.hp_percent,  # 32
            self.strengthen.multiplier_percent,  # 33
            self.survive_lethal_strike.prob.percent
            if self.survive_lethal_strike.prob is not None
            else None,  # 34
            self.attack_1.long_distance_start,  # 35
            self.attack_1.long_distance_range,  # 36
            core.unit_int(self.wave_immunity),  # 37
            core.unit_int(self.wave_blocker),  # 38
            core.unit_int(self.knockback_immunity),  # 39
            core.unit_int(self.freeze_immunity),  # 40
            core.unit_int(self.slow_immunity),  # 41
            core.unit_int(self.weaken_immunity),  # 42
            self.burrow.count,  # 43
            self.burrow.distance,  # 44
            self.revive.count,  # 45
            self.revive.time.frames if self.revive.time is not None else None,  # 46
            self.revive.hp_remain_percent,  # 47
            core.unit_int(self.witch),  # 48
            core.unit_int(self.base),  # 49
            self.attack_state.attacks_before,  # 50
            self.time_before_death.frames
            if self.time_before_death is not None
            else None,  # 51
            self.attack_state.state_id,  # 52
            self.spawn_anim.model_id,  # 53
            self.soul_anim.model_id,  # 54
            self.attack_2.damage,  # 55
            self.attack_3.damage,  # 56
            self.attack_2.foreswing.frames
            if self.attack_2.foreswing is not None
            else None,  # 57
            self.attack_3.foreswing.frames
            if self.attack_3.foreswing is not None
            else None,  # 58
            core.unit_int(self.attack_1.use_ability),  # 59
            core.unit_int(self.attack_2.use_ability),  # 60
            core.unit_int(self.attack_3.use_ability),  # 61
            core.unit_int(self.spawn_anim.has_entry_maanim),  # 62
            core.unit_int(self.soul_anim.has_death_maanim),  # 63
            self.barrier.hp,  # 64
            self.warp.prob.percent if self.warp.prob is not None else None,  # 65
            self.warp.time.frames if self.warp.time is not None else None,  # 66
            self.warp.min_distance,  # 67
            self.warp.max_distance,  # 68
            core.unit_int(self.starred_alien),  # 69
            core.unit_int(self.warp_blocker),  # 70
            core.unit_int(self.eva_angel),  # 71
            core.unit_int(self.relic),  # 72
            self.curse.prob.percent if self.curse.prob is not None else None,  # 73
            self.curse.time.frames if self.curse.time is not None else None,  # 74
            self.savage_blow.prob.percent
            if self.savage_blow.prob is not None
            else None,  # 75
            self.savage_blow.multiplier,  # 76
            self.dodge.prob.percent if self.dodge.prob is not None else None,  # 77
            self.dodge.time.frames if self.dodge.time is not None else None,  # 78
            self.toxic.prob.percent if self.toxic.prob is not None else None,  # 79
            self.toxic.hp_percent,  # 80
            self.surge.prob.percent if self.surge.prob is not None else None,  # 81
            self.surge.start,  # 82
            self.surge.range,  # 83
            self.surge.level,  # 84
            core.unit_int(self.surge_immunity),  # 85
            core.unit_int(self.wave.is_mini),  # 86
            self.shield.hp,  # 87
            self.shield.percent_heal_kb,  # 88
            self.death_surge.prob.percent
            if self.death_surge.prob is not None
            else None,  # 89
            self.death_surge.start,  # 90
            self.death_surge.range,  # 91
            self.death_surge.level,  # 92
            core.unit_int(self.aku),  # 93
            core.unit_int(self.baron),  # 94
            core.unit_int(self.attack_2.long_distance_flag),  # 95
            self.attack_2.long_distance_start,  # 96
            self.attack_2.long_distance_range,  # 97
            core.unit_int(self.attack_3.long_distance_flag),  # 98
            self.attack_3.long_distance_start,  # 99
            self.attack_3.long_distance_range,  # 100
            core.unit_int(self.behemoth),  # 101
        ]

    def apply_dict(self, dict_data: dict[str, Any]):
        raw_stats = dict_data.get("raw_stats")
        if raw_stats is not None:
            current_raw_stats = self.to_raw_data()
            mod_stats = core.ModEditDictHandler(raw_stats, current_raw_stats).get_dict(
                True
            )
            for stat_id, stat_value in mod_stats.items():
                current_raw_stats[stat_id] = core.ModEditValueHandler(
                    stat_value, current_raw_stats[stat_id]
                ).get_value()
            self.assign(current_raw_stats)

    @staticmethod
    def create_empty(enemy_id: int) -> "EnemyStats":
        return EnemyStats(enemy_id, [])

    def to_dict(self) -> dict[str, Any]:
        raw_stats = self.to_raw_data()
        data: dict[int, Any] = {}
        for stat_id, stat_value in enumerate(raw_stats):
            data[stat_id] = stat_value
        return {"raw_stats": data}


class EnemyStatsData:
    def __init__(self, stats: dict[int, EnemyStats]):
        self.stats = stats

    @staticmethod
    def get_file_name() -> str:
        return "t_core.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EnemyStatsData":
        if game_data.enemy_stats is not None:
            return game_data.enemy_stats
        stats_data = game_data.find_file(EnemyStatsData.get_file_name())
        if stats_data is None:
            return EnemyStatsData.create_empty()
        stats: dict[int, EnemyStats] = {}
        csv = core.CSV(stats_data.dec_data)
        for enemy_id, line in enumerate(csv.lines):
            enemy_id -= 2
            stats[enemy_id] = EnemyStats(enemy_id, [int(x) for x in line])
        enemy_stats = EnemyStatsData(stats)
        game_data.enemy_stats = enemy_stats
        return enemy_stats

    def to_game_data(self, game_data: "core.GamePacks"):
        stats_data = game_data.find_file(EnemyStatsData.get_file_name())
        if stats_data is None:
            return None
        csv = core.CSV(stats_data.dec_data)
        for enemy in self.stats.values():
            for stat_id, stat_value in enumerate(enemy.to_raw_data()):
                if stat_value is not None:
                    csv.lines[enemy.enemy_id + 2][stat_id] = str(stat_value)

        game_data.set_file(EnemyStatsData.get_file_name(), csv.to_data())

    def get(self, enemy_id: int) -> Optional[EnemyStats]:
        return self.stats.get(enemy_id)

    @staticmethod
    def create_empty() -> "EnemyStatsData":
        return EnemyStatsData({})


class EnemyModel:
    def __init__(self, enemy_id: int, model: "core.Model"):
        self.enemy_id = enemy_id
        self.model = model

    @staticmethod
    def get_enemy_id_str(enemy_id: int) -> str:
        return core.PaddedInt(enemy_id, 3).to_str()

    @staticmethod
    def get_img_path(enemy_id: int) -> str:
        enemy_id_str = EnemyModel.get_enemy_id_str(enemy_id)
        return f"{enemy_id_str}_e.png"

    @staticmethod
    def get_imgcut_path(enemy_id: int) -> str:
        return EnemyModel.get_img_path(enemy_id).replace(".png", ".imgcut")

    @staticmethod
    def get_mamodel_path(enemy_id: int) -> str:
        return EnemyModel.get_img_path(enemy_id).replace(".png", ".mamodel")

    @staticmethod
    def get_maanim_path(enemy_id: int, anim_type: "core.AnimType") -> str:
        anim_type_str = core.PaddedInt(anim_type.value, 2).to_str()
        return EnemyModel.get_img_path(enemy_id).replace(
            ".png", f"{anim_type_str}.maanim"
        )

    @staticmethod
    def get_maanim_paths(enemy_id: int) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in core.AnimType:
            maanim_paths.append(EnemyModel.get_maanim_path(enemy_id, anim_type))
        return maanim_paths

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks", enemy_id: int
    ) -> Optional["EnemyModel"]:
        img_path = EnemyModel.get_img_path(enemy_id)
        imgcut_path = EnemyModel.get_imgcut_path(enemy_id)
        mamodel_path = EnemyModel.get_mamodel_path(enemy_id)
        maanim_paths = EnemyModel.get_maanim_paths(enemy_id)

        an = core.Model.load(
            mamodel_path,
            imgcut_path,
            img_path,
            maanim_paths,
            game_data,
        )
        return EnemyModel(enemy_id, an)

    def to_game_data(self, game_data: "core.GamePacks"):
        self.model.save(game_data)

    def set_enemy_id(self, enemy_id: int):
        self.enemy_id = enemy_id
        self.model.set_unit_id(enemy_id)
        self.model.set_unit_form("e")

    def apply_dict(self, dict_data: dict[str, Any]):
        model = dict_data.get("model")
        if model is not None:
            self.model.apply_dict(model)

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model.to_dict()}

    @staticmethod
    def create_empty(enemy_id: int) -> "EnemyModel":
        return EnemyModel(enemy_id, core.Model.create_empty())


class EnemyNames:
    def __init__(self, names: dict[int, str]):
        self.names = names

    @staticmethod
    def get_file_name() -> str:
        return "Enemyname.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EnemyNames":
        if game_data.enemy_names is not None:
            return game_data.enemy_names
        names_data = game_data.find_file(EnemyNames.get_file_name())
        if names_data is None:
            return EnemyNames.create_empty()
        names: dict[int, str] = {}
        csv = core.CSV(names_data.dec_data, delimeter="\t", remove_empty=False)
        for enemy_id, line in enumerate(csv.lines):
            try:
                names[enemy_id] = line[0]
            except IndexError:
                pass
        enemy_names = EnemyNames(names)
        game_data.enemy_names = enemy_names
        return enemy_names

    def to_game_data(self, game_data: "core.GamePacks"):
        names_data = game_data.find_file(EnemyNames.get_file_name())
        if names_data is None:
            return None
        csv = core.CSV(names_data.dec_data, delimeter="\t", remove_empty=False)
        for enemy_id, name in self.names.items():
            csv.lines[enemy_id] = [name]

        game_data.set_file(EnemyNames.get_file_name(), csv.to_data())

    def set(self, enemy: "Enemy"):
        self.names[enemy.enemy_id] = enemy.get_name()

    def get(self, enemy_id: int) -> str:
        return self.names.get(enemy_id, "???")

    @staticmethod
    def create_empty() -> "EnemyNames":
        return EnemyNames({})


class EnemyDescriptions:
    def __init__(self, descriptions: dict[int, list[str]]):
        self.descriptions = descriptions

    @staticmethod
    def get_file_name(lang: str) -> str:
        return f"EnemyPictureBook_{lang}.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EnemyDescriptions":
        descriptions: dict[int, list[str]] = {}
        cc = game_data.country_code
        file = game_data.find_file(
            EnemyDescriptions.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return EnemyDescriptions.create_empty()
        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(cc),
            remove_empty=False,
        )
        for enemy_id, line in enumerate(csv.lines):
            descriptions[enemy_id] = line
        return EnemyDescriptions(descriptions)

    def to_game_data(self, game_data: "core.GamePacks", names: dict[int, str]):
        cc = game_data.country_code
        file = game_data.find_file(
            EnemyDescriptions.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return None
        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(cc),
            remove_empty=False,
        )
        for enemy_id, description in self.descriptions.items():
            line: list[str] = []
            if names[enemy_id] and "%s" not in description[0]:
                line.append("%s")
            line.extend(description)
            csv.lines[enemy_id] = line

        game_data.set_file(
            EnemyDescriptions.get_file_name(game_data.localizable.get_lang()),
            csv.to_data(),
        )

    def set(self, enemy: "Enemy"):
        self.descriptions[enemy.enemy_id] = enemy.get_description()

    def get(self, enemy_id: int) -> list[str]:
        return self.descriptions.get(enemy_id, [""])

    @staticmethod
    def create_empty() -> "EnemyDescriptions":
        return EnemyDescriptions({})


class Enemy:
    def __init__(
        self,
        enemy_id: Optional[int] = None,
        stats: Optional[EnemyStats] = None,
        name: Optional[str] = None,
        description: Optional[list[str]] = None,
        anim: Optional[EnemyModel] = None,
        enemy_icon: Optional["core.BCImage"] = None,
        release_id: Optional[int] = None,
    ):
        if release_id is not None:
            enemy_id = release_id - 2
        if enemy_id is None:
            raise ValueError("Enemy ID is None")

        self.enemy_id = enemy_id
        self.stats = stats
        self.name = name
        self.description = description
        self.anim = anim
        self.enemy_icon = enemy_icon

    @staticmethod
    def get_enemy_icon_name(enemy_id: int) -> str:
        enemy_id_str = core.PaddedInt(enemy_id, 3).to_str()
        return f"enemy_icon_{enemy_id_str}.png"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        enemy_id: Optional[int],
        stat_data: EnemyStatsData,
        names: EnemyNames,
        descriptions: EnemyDescriptions,
        release_id: Optional[int] = None,
    ) -> Optional["Enemy"]:
        if release_id is not None:
            enemy_id = release_id - 2
        if enemy_id is None:
            return None
        anim = EnemyModel.from_game_data(game_data, enemy_id)
        if anim is None:
            return None
        enemy_icon_file = game_data.find_file(Enemy.get_enemy_icon_name(enemy_id))
        if enemy_icon_file is None:
            return None
        enemy_icon = core.BCImage(enemy_icon_file.dec_data)

        name = names.get(enemy_id)
        description = descriptions.get(enemy_id)
        stats = stat_data.get(enemy_id)
        if stats is None:
            return None

        return Enemy(enemy_id, stats, name, description, anim, enemy_icon, release_id)

    def to_game_data(self, game_data: "core.GamePacks"):
        if self.anim is not None:
            self.anim.to_game_data(game_data)

        if self.enemy_icon is not None:
            game_data.set_file(
                Enemy.get_enemy_icon_name(self.enemy_id), self.enemy_icon.to_data()
            )

    def get_anim(self) -> EnemyModel:
        if self.anim is None:
            self.anim = EnemyModel.create_empty(self.enemy_id)
        return self.anim

    def get_name(self) -> str:
        if self.name is None:
            return ""
        return self.name

    def get_description(self) -> list[str]:
        if self.description is None:
            return []
        return self.description

    def get_enemy_icon(self) -> "core.BCImage":
        if self.enemy_icon is None:
            self.enemy_icon = core.BCImage.create_empty()
        return self.enemy_icon

    def set_enemy_id(self, enemy_id: int):
        original_enemy_id = self.enemy_id
        self.enemy_id = enemy_id
        if self.stats is not None:
            self.stats.enemy_id = enemy_id
        if original_enemy_id != enemy_id:
            self.get_anim().set_enemy_id(enemy_id)

    def get_stats(self) -> EnemyStats:
        if self.stats is None:
            self.stats = EnemyStats.create_empty(self.enemy_id)
        return self.stats

    def apply_dict(self, dict_data: dict[str, Any]):
        stats = dict_data.get("stats")
        if stats is not None:
            self.get_stats().apply_dict(stats)

        name = dict_data.get("name")
        if name is not None:
            self.name = name

        description = dict_data.get("description")
        if description is not None:
            self.description = description

        anim = dict_data.get("anim")
        if anim is not None:
            self.get_anim().apply_dict(anim)

        enemy_icon = dict_data.get("enemy_icon")
        if enemy_icon is not None:
            self.enemy_icon = enemy_icon

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats.to_dict() if self.stats is not None else None,
            "name": self.name,
            "description": self.description,
            "anim": self.anim.to_dict() if self.anim is not None else None,
            "enemy_icon": self.enemy_icon.to_dict()
            if self.enemy_icon is not None
            else None,
        }

    @staticmethod
    def create_empty(enemy_id: int) -> "Enemy":
        return Enemy(
            enemy_id,
        )


class Enemies(core.EditableClass):
    def __init__(self, enemies: dict[int, Enemy]):
        self.data = enemies
        super().__init__(self.data)

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "Enemies":
        if game_data.enemies is not None:
            return game_data.enemies
        stats = EnemyStatsData.from_game_data(game_data)
        names = EnemyNames.from_game_data(game_data)
        descriptions = EnemyDescriptions.from_game_data(game_data)
        enemies = {}
        for enemy_id in names.names.keys():
            enemy = Enemy.from_game_data(
                game_data, enemy_id, stats, names, descriptions
            )
            if enemy is not None:
                enemies[enemy_id] = enemy
        enemies_o = Enemies(enemies)
        game_data.enemies = enemies_o
        return enemies_o

    def to_game_data(self, game_data: "core.GamePacks"):
        stats = EnemyStatsData(
            {
                enemy.enemy_id: enemy.stats
                for enemy in self.data.values()
                if enemy.stats is not None
            }
        )
        names = EnemyNames(
            {
                enemy.enemy_id: enemy.name
                for enemy in self.data.values()
                if enemy.name is not None
            }
        )
        descriptions = EnemyDescriptions(
            {
                enemy.enemy_id: enemy.description
                for enemy in self.data.values()
                if enemy.description is not None
            }
        )
        stats.to_game_data(game_data)
        names.to_game_data(game_data)
        descriptions.to_game_data(game_data, names.names)
        for enemy in self.data.values():
            enemy.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Enemies":
        return Enemies({})

    def get_enemy(self, enemy_id: int) -> Optional[Enemy]:
        return self.data.get(enemy_id)

    def set_enemy(self, enemy: Enemy):
        self.data[enemy.enemy_id] = enemy
