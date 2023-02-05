from typing import Any, Optional
from bcml.core.game_data.cat_base import unit
from bcml.core.game_data import pack, bc_anim
from bcml.core import io, country_code


class Stats:
    def __init__(self, enemy_id: int, raw_data: list[int]):
        self.enemy_id = enemy_id
        raw_data = self.extend(raw_data)
        self.assign(raw_data)
        self.set_required()

    def serialize(self) -> dict[str, Any]:
        return {
            "raw_data": self.to_raw_data(),
        }

    def set_required(self):
        self.attacks_before_state = -1
        self.time_before_death.frames = -1
        self.spawn_anim_id = -1
        self.attack_1.use_ability = True

    def extend(self, raw_data: list[int]):
        length = 102
        raw_data = raw_data + [0] * (length - len(raw_data))
        return raw_data

    @staticmethod
    def deserialize(data: dict[str, Any], enemy_id: int) -> "Stats":
        return Stats(
            enemy_id,
            data["raw_data"],
        )

    def assign(self, raw_data: list[int]):
        self.hp = raw_data[0]
        self.kbs = raw_data[1]
        self.speed = raw_data[2]
        self.attack_interval = unit.Frames.from_pair_frames(raw_data[4])
        self.range = raw_data[5]
        self.money_drop = raw_data[6]
        self.hitbox_pos = raw_data[7]
        self.hitbox_width = raw_data[8]
        self.unused = raw_data[9]
        self.red = bool(raw_data[10])
        self.area_attack = bool(raw_data[11])
        self.floating = bool(raw_data[13])
        self.black = bool(raw_data[14])
        self.metal = bool(raw_data[15])
        self.traitless = bool(raw_data[16])
        self.angel = bool(raw_data[17])
        self.alien = bool(raw_data[18])
        self.zombie = bool(raw_data[19])
        self.knockback = unit.Knockback.from_values(raw_data[20])
        self.freeze = unit.Freeze.from_values(raw_data[21], raw_data[22])
        self.slow = unit.Slow.from_values(raw_data[23], raw_data[24])
        self.crit = unit.Crit.from_values(raw_data[25])
        self.base_destroyer = bool(raw_data[26])
        self.wave = unit.Wave.from_values(
            raw_data[27], raw_data[28], bool(raw_data[86])
        )
        self.weaken = unit.Weaken.from_values(raw_data[29], raw_data[30], raw_data[31])
        self.strengthen = unit.Strengthen.from_values(raw_data[32], raw_data[33])
        self.survive_lethal_strike = unit.SurviveLethalStrike.from_values(raw_data[34])
        self.wave_immunity = bool(raw_data[37])
        self.wave_blocker = bool(raw_data[38])
        self.knockback_immunity = bool(raw_data[39])
        self.freeze_immunity = bool(raw_data[40])
        self.slow_immunity = bool(raw_data[41])
        self.weaken_immunity = bool(raw_data[42])
        self.burrow = unit.Burrow.from_values(raw_data[43], raw_data[44])
        self.revive = unit.Revive.from_values(raw_data[45], raw_data[46], raw_data[47])
        self.witch = bool(raw_data[48])
        self.base = bool(raw_data[49])
        self.attacks_before_state = raw_data[50]
        self.time_before_death = unit.Frames(raw_data[51])
        self.enemy_state = raw_data[52]
        self.spawn_anim_id = raw_data[53]
        self.soul_anim = unit.SoulAnim(raw_data[54])
        self.custom_spawn_anim = bool(raw_data[62])
        self.custom_soul_anim = not bool(raw_data[63])
        self.barrier = unit.Barrier.from_values(raw_data[64])
        self.warp = unit.Warp.from_values(
            raw_data[65], raw_data[66], raw_data[67], raw_data[68]
        )
        self.starred_alien = bool(raw_data[69])
        self.warp_blocker = bool(raw_data[70])
        self.eva_angel = bool(raw_data[71])
        self.relic = bool(raw_data[72])
        self.curse = unit.Curse.from_values(raw_data[73], raw_data[74])
        self.savage_blow = unit.SavageBlow.from_values(raw_data[75], raw_data[76])
        self.dodge = unit.Dodge.from_values(raw_data[77], raw_data[78])
        self.toxic = unit.Toxic.from_values(raw_data[79], raw_data[80])
        self.surge = unit.Surge.from_values(
            raw_data[81], raw_data[82], raw_data[83], raw_data[84]
        )
        self.surge_immunity = bool(raw_data[85])
        self.shield = unit.Shield.from_values(raw_data[87], raw_data[88])
        self.death_surge = unit.Surge.from_values(
            raw_data[89], raw_data[90], raw_data[91], raw_data[92]
        )
        self.aku = bool(raw_data[93])
        self.baron = bool(raw_data[94])
        self.behemoth = bool(raw_data[101])

        self.attack_1 = unit.Attack.from_values(
            raw_data[3],
            raw_data[12],
            bool(raw_data[59]),
            True,
            raw_data[35],
            raw_data[36],
        )
        self.attack_2 = unit.Attack.from_values(
            raw_data[55],
            raw_data[57],
            bool(raw_data[60]),
            bool(raw_data[95]),
            raw_data[96],
            raw_data[97],
        )
        self.attack_3 = unit.Attack.from_values(
            raw_data[56],
            raw_data[58],
            bool(raw_data[61]),
            bool(raw_data[98]),
            raw_data[99],
            raw_data[100],
        )

    def to_raw_data(self) -> list[int]:
        return [
            self.hp,  # 0
            self.kbs,  # 1
            self.speed,  # 2
            self.attack_1.damage,  # 3
            self.attack_interval.pair_frames,  # 4
            self.range,  # 5
            self.money_drop,  # 6
            self.hitbox_pos,  # 7
            self.hitbox_width,  # 8
            self.unused,  # 9
            int(self.red),  # 10
            int(self.area_attack),  # 11
            self.attack_1.foreswing.frames,  # 12
            int(self.floating),  # 13
            int(self.black),  # 14
            int(self.metal),  # 15
            int(self.traitless),  # 16
            int(self.angel),  # 17
            int(self.alien),  # 18
            int(self.zombie),  # 19
            self.knockback.prob.percent,  # 20
            self.freeze.prob.percent,  # 21
            self.freeze.time.frames,  # 22
            self.slow.prob.percent,  # 23
            self.slow.time.frames,  # 24
            self.crit.prob.percent,  # 25
            int(self.base_destroyer),  # 26
            self.wave.prob.percent,  # 27
            self.wave.level,  # 28
            self.weaken.prob.percent,  # 29
            self.weaken.time.frames,  # 30
            self.weaken.multiplier,  # 31
            self.strengthen.hp_percent,  # 32
            self.strengthen.multiplier_percent,  # 33
            self.survive_lethal_strike.prob.percent,  # 34
            self.attack_1.long_distance_start,  # 35
            self.attack_1.long_distance_range,  # 36
            int(self.wave_immunity),  # 37
            int(self.wave_blocker),  # 38
            int(self.knockback_immunity),  # 39
            int(self.freeze_immunity),  # 40
            int(self.slow_immunity),  # 41
            int(self.weaken_immunity),  # 42
            self.burrow.count,  # 43
            self.burrow.distance,  # 44
            self.revive.count,  # 45
            self.revive.time.frames,  # 46
            self.revive.hp_remain_percent,  # 47
            int(self.witch),  # 48
            int(self.base),  # 49
            self.attacks_before_state,  # 50
            self.time_before_death.frames,  # 51
            self.enemy_state,  # 52
            self.spawn_anim_id,  # 53
            self.soul_anim.anim_type,  # 54
            self.attack_2.damage,  # 55
            self.attack_3.damage,  # 56
            self.attack_2.foreswing.frames,  # 57
            self.attack_3.foreswing.frames,  # 58
            int(self.attack_1.use_ability),  # 59
            int(self.attack_2.use_ability),  # 60
            int(self.attack_3.use_ability),  # 61
            int(self.custom_spawn_anim),  # 62
            int(not self.custom_soul_anim),  # 63
            self.barrier.hp,  # 64
            self.warp.prob.percent,  # 65
            self.warp.time.frames,  # 66
            self.warp.min_distance,  # 67
            self.warp.max_distance,  # 68
            int(self.starred_alien),  # 69
            int(self.warp_blocker),  # 70
            int(self.eva_angel),  # 71
            int(self.relic),  # 72
            self.curse.prob.percent,  # 73
            self.curse.time.frames,  # 74
            self.savage_blow.prob.percent,  # 75
            self.savage_blow.multiplier,  # 76
            self.dodge.prob.percent,  # 77
            self.dodge.time.frames,  # 78
            self.toxic.prob.percent,  # 79
            self.toxic.hp_percent,  # 80
            self.surge.prob.percent,  # 81
            self.surge.start,  # 82
            self.surge.range,  # 83
            self.surge.level,  # 84
            int(self.surge_immunity),  # 85
            int(self.wave.is_mini),  # 86
            self.shield.hp,  # 87
            self.shield.percent_heal_kb,  # 88
            self.death_surge.prob.percent,  # 89
            self.death_surge.start,  # 90
            self.death_surge.range,  # 91
            self.death_surge.level,  # 92
            int(self.aku),  # 93
            int(self.baron),  # 94
            int(self.attack_2.long_distance_flag),  # 95
            self.attack_2.long_distance_start,  # 96
            self.attack_2.long_distance_range,  # 97
            int(self.attack_3.long_distance_flag),  # 98
            self.attack_3.long_distance_start,  # 99
            self.attack_3.long_distance_range,  # 100
            int(self.behemoth),  # 101
        ]


class StatsData:
    def __init__(self, stats: dict[int, Stats]):
        self.stats = stats

    def serialize(self) -> dict[str, Any]:
        return {
            "stats": {
                str(enemy_id): stats.serialize()
                for enemy_id, stats in self.stats.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "StatsData":
        return StatsData(
            {
                int(enemy_id): Stats.deserialize(stats_data, int(enemy_id))
                for enemy_id, stats_data in data["stats"].items()
            },
        )

    @staticmethod
    def get_file_name() -> str:
        return "t_unit.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "StatsData":
        stats_data = game_data.find_file(StatsData.get_file_name())
        if stats_data is None:
            return StatsData.create_empty()
        stats: dict[int, Stats] = {}
        csv = io.bc_csv.CSV(stats_data.dec_data)
        for enemy_id, line in enumerate(csv.lines):
            enemy_id -= 2
            stats[enemy_id] = Stats(enemy_id, io.data.Data.data_list_int_list(line))
        return StatsData(stats)

    def to_game_data(self, game_data: "pack.GamePacks"):
        stats_data = game_data.find_file(StatsData.get_file_name())
        if stats_data is None:
            return None
        csv = io.bc_csv.CSV(stats_data.dec_data)
        for enemy in self.stats.values():
            csv.set_line(enemy.enemy_id + 2, enemy.to_raw_data())

        game_data.set_file(StatsData.get_file_name(), csv.to_data())

    def get(self, enemy_id: int) -> Optional[Stats]:
        return self.stats.get(enemy_id)

    @staticmethod
    def create_empty() -> "StatsData":
        return StatsData({})


class Anim:
    def __init__(self, enemy_id: int, anim: "bc_anim.Anim"):
        self.enemy_id = enemy_id
        self.anim = anim

    def serialize(self) -> dict[str, Any]:
        return {
            "anim": self.anim.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], enemy_id: int) -> "Anim":
        return Anim(
            enemy_id,
            bc_anim.Anim.deserialize(data["anim"]),
        )

    @staticmethod
    def get_enemy_id_str(enemy_id: int) -> str:
        return io.data.PaddedInt(enemy_id, 3).to_str()

    @staticmethod
    def get_img_path(enemy_id: int) -> str:
        enemy_id_str = Anim.get_enemy_id_str(enemy_id)
        return f"{enemy_id_str}_e.png"

    @staticmethod
    def get_imgcut_path(enemy_id: int) -> str:
        return Anim.get_img_path(enemy_id).replace(".png", ".imgcut")

    @staticmethod
    def get_mamodel_path(enemy_id: int) -> str:
        return Anim.get_img_path(enemy_id).replace(".png", ".mamodel")

    @staticmethod
    def get_maanim_path(enemy_id: int, anim_type: "bc_anim.AnimType") -> str:
        anim_type_str = io.data.PaddedInt(anim_type.value, 2).to_str()
        return Anim.get_img_path(enemy_id).replace(".png", f"{anim_type_str}.maanim")

    @staticmethod
    def get_maanim_paths(enemy_id: int) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in bc_anim.AnimType:
            maanim_paths.append(Anim.get_maanim_path(enemy_id, anim_type))
        return maanim_paths

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks", enemy_id: int) -> Optional["Anim"]:
        img_path = Anim.get_img_path(enemy_id)
        imgcut_path = Anim.get_imgcut_path(enemy_id)
        mamodel_path = Anim.get_mamodel_path(enemy_id)
        maanim_paths = Anim.get_maanim_paths(enemy_id)

        anim = bc_anim.Anim.from_paths(
            game_data, img_path, imgcut_path, mamodel_path, maanim_paths
        )
        if anim is None:
            return None
        return Anim(enemy_id, anim)

    def to_game_data(self, game_data: "pack.GamePacks"):
        img_path = Anim.get_img_path(self.enemy_id)
        imgcut_path = Anim.get_imgcut_path(self.enemy_id)
        mamodel_path = Anim.get_mamodel_path(self.enemy_id)
        maanim_paths = Anim.get_maanim_paths(self.enemy_id)
        self.anim.to_game_data(
            game_data, img_path, imgcut_path, mamodel_path, maanim_paths
        )

    def set_enemy_id(self, enemy_id: int):
        self.enemy_id = enemy_id
        self.anim.set_enemy_id(enemy_id)


class Names:
    def __init__(self, names: dict[int, str]):
        self.names = names

    def serialize(self) -> dict[str, Any]:
        return {
            "names": self.names,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Names":
        return Names(data["names"])

    @staticmethod
    def get_file_name() -> str:
        return "Enemyname.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Names":
        names_data = game_data.find_file(Names.get_file_name())
        if names_data is None:
            return Names.create_empty()
        names: dict[int, str] = {}
        csv = io.bc_csv.CSV(names_data.dec_data, delimeter="\t", remove_empty=False)
        for enemy_id, line in enumerate(csv.lines):
            try:
                names[enemy_id] = line[0].to_str()
            except IndexError:
                pass
        return Names(names)

    def to_game_data(self, game_data: "pack.GamePacks"):
        names_data = game_data.find_file(Names.get_file_name())
        if names_data is None:
            return None
        csv = io.bc_csv.CSV(names_data.dec_data, delimeter="\t", remove_empty=False)
        for enemy_id, name in self.names.items():
            csv.set_line(enemy_id, [name])

        game_data.set_file(Names.get_file_name(), csv.to_data())

    def set(self, enemy: "Enemy"):
        self.names[enemy.enemy_id] = enemy.name

    def get(self, enemy_id: int) -> str:
        return self.names.get(enemy_id, "???")

    @staticmethod
    def create_empty() -> "Names":
        return Names({})


class Descriptions:
    def __init__(self, descriptions: dict[int, list[str]]):
        self.descriptions = descriptions

    def serialize(self) -> dict[str, Any]:
        return {
            "descriptions": self.descriptions,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Descriptions":
        return Descriptions(data["descriptions"])

    @staticmethod
    def get_file_name(cc: "country_code.CountryCode") -> str:
        return f"EnemyPictureBook_{cc.get_language()}.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Descriptions":
        descriptions: dict[int, list[str]] = {}
        cc = game_data.country_code
        file = game_data.find_file(Descriptions.get_file_name(cc))
        if file is None:
            return Descriptions.create_empty()
        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(cc),
            remove_empty=False,
        )
        for enemy_id, line in enumerate(csv.lines):
            descriptions[enemy_id] = io.data.Data.data_list_string_list(line)
        return Descriptions(descriptions)

    def to_game_data(self, game_data: "pack.GamePacks", names: dict[int, str]):
        cc = game_data.country_code
        file = game_data.find_file(Descriptions.get_file_name(cc))
        if file is None:
            return None
        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(cc),
            remove_empty=False,
        )
        for enemy_id, description in self.descriptions.items():
            line: list[str] = []
            if names[enemy_id] and "%s" not in description[0]:
                line.append("%s")
            line.extend(description)
            csv.set_line(enemy_id, line)

        game_data.set_file(Descriptions.get_file_name(cc), csv.to_data())

    def set(self, enemy: "Enemy"):
        self.descriptions[enemy.enemy_id] = enemy.description

    def get(self, enemy_id: int) -> list[str]:
        return self.descriptions.get(enemy_id, ["???"])

    @staticmethod
    def create_empty() -> "Descriptions":
        return Descriptions({})


class Enemy:
    def __init__(
        self,
        enemy_id: Optional[int],
        stats: Stats,
        name: str,
        description: list[str],
        anim: Anim,
        enemy_icon: "io.bc_image.BCImage",
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

    def serialize(self) -> dict[str, Any]:
        return {
            "stats": self.stats.serialize(),
            "name": self.name,
            "description": self.description,
            "anim": self.anim.serialize(),
            "enemy_icon": self.enemy_icon.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], enemy_id: int) -> "Enemy":
        return Enemy(
            enemy_id,
            Stats.deserialize(data["stats"], enemy_id),
            data["name"],
            data["description"],
            Anim.deserialize(data["anim"], enemy_id),
            io.bc_image.BCImage.deserialize(data["enemy_icon"]),
        )

    @staticmethod
    def get_enemy_icon_name(enemy_id: int) -> str:
        enemy_id_str = io.data.PaddedInt(enemy_id, 3).to_str()
        return f"enemy_icon_{enemy_id_str}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
        enemy_id: Optional[int],
        stat_data: StatsData,
        names: Names,
        descriptions: Descriptions,
        release_id: Optional[int] = None,
    ) -> Optional["Enemy"]:
        if release_id is not None:
            enemy_id = release_id - 2
        if enemy_id is None:
            return None
        anim = Anim.from_game_data(game_data, enemy_id)
        if anim is None:
            return None
        enemy_icon_file = game_data.find_file(Enemy.get_enemy_icon_name(enemy_id))
        if enemy_icon_file is None:
            return None
        enemy_icon = io.bc_image.BCImage(enemy_icon_file.dec_data)

        name = names.get(enemy_id)
        description = descriptions.get(enemy_id)
        stats = stat_data.get(enemy_id)
        if name is None or description is None or stats is None:
            return None

        return Enemy(enemy_id, stats, name, description, anim, enemy_icon, release_id)

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.anim.to_game_data(game_data)
        game_data.set_file(
            Enemy.get_enemy_icon_name(self.enemy_id), self.enemy_icon.to_data()
        )

    def set_enemy_id(self, enemy_id: int):
        self.enemy_id = enemy_id
        self.stats.enemy_id = enemy_id
        self.anim.set_enemy_id(enemy_id)


class Enemies:
    def __init__(self, enemies: dict[int, Enemy]):
        self.enemies = enemies

    def serialize(self) -> dict[str, Any]:
        return {
            "enemies": {
                str(enemy_id): enemy.serialize()
                for enemy_id, enemy in self.enemies.items()
            }
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Enemies":
        return Enemies(
            {
                int(enemy_id): Enemy.deserialize(enemy_data, int(enemy_id))
                for enemy_id, enemy_data in data["enemies"].items()
            }
        )

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Enemies":
        stats = StatsData.from_game_data(game_data)
        names = Names.from_game_data(game_data)
        descriptions = Descriptions.from_game_data(game_data)
        enemies = {}
        for enemy_id in names.names.keys():
            enemy = Enemy.from_game_data(
                game_data, enemy_id, stats, names, descriptions
            )
            if enemy is not None:
                enemies[enemy_id] = enemy
        return Enemies(enemies)

    def to_game_data(self, game_data: "pack.GamePacks"):
        stats = StatsData(
            {enemy.enemy_id: enemy.stats for enemy in self.enemies.values()}
        )
        names = Names({enemy.enemy_id: enemy.name for enemy in self.enemies.values()})
        descriptions = Descriptions(
            {enemy.enemy_id: enemy.description for enemy in self.enemies.values()}
        )
        stats.to_game_data(game_data)
        names.to_game_data(game_data)
        descriptions.to_game_data(game_data, names.names)
        for enemy in self.enemies.values():
            enemy.to_game_data(game_data)

    @staticmethod
    def get_enemies_json_file_name() -> "io.path.Path":
        return io.path.Path("catbase").add("enemies.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        enemies_json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(Enemies.get_enemies_json_file_name(), enemies_json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Enemies":
        enemies_json_file = zip.get_file(Enemies.get_enemies_json_file_name())
        if enemies_json_file is None:
            return Enemies.create_empty()
        enemies_json = io.json_file.JsonFile.from_data(enemies_json_file)
        return Enemies.deserialize(enemies_json.json)

    @staticmethod
    def create_empty() -> "Enemies":
        return Enemies({})

    def get_enemy(self, enemy_id: int) -> Optional[Enemy]:
        return self.enemies.get(enemy_id)

    def set_enemy(self, enemy: Enemy):
        self.enemies[enemy.enemy_id] = enemy

    def import_enemies(self, other: "Enemies"):
        self.enemies.update(other.enemies)
