from __future__ import annotations

from dataclasses import field
import tbcml

from tbcml.io.csv_fields import (
    IntCSVField,
    BoolCSVField,
    StringCSVField,
    StrListCSVField,
)

from marshmallow_dataclass import dataclass


@dataclass
class EnemyStats:
    hp: int | None = None
    kbs: int | None = None
    speed: int | None = None
    attack_1_damage: int | None = None
    attack_interval: int | None = None
    attack_range: int | None = None
    money_drop: int | None = None
    collision_start: int | None = None
    collision_width: int | None = None
    unused: int | None = None
    red: bool | None = None
    area_attack: bool | None = None
    attack_1_foreswing: int | None = None
    floating: bool | None = None
    black: bool | None = None
    metal: bool | None = None
    traitless: bool | None = None
    angel: bool | None = None
    alien: bool | None = None
    zombie: bool | None = None
    knockback_prob: int | None = None
    freeze_prob: int | None = None
    freeze_duration: int | None = None
    slow_prob: int | None = None
    slow_duration: int | None = None
    crit_prob: int | None = None
    base_destroyer: bool | None = None
    wave_prob: int | None = None
    wave_level: int | None = None
    weaken_prob: int | None = None
    weaken_duration: int | None = None
    weaken_percentage: int | None = None
    strengthen_hp_start_percentage: int | None = None
    strengthen_hp_boost_percentage: int | None = None
    survive_lethal_strike_prob: int | None = None
    attack_1_ld_start: int | None = None
    attack_1_ld_range: int | None = None
    wave_immunity: bool | None = None
    wave_blocker: bool | None = None
    knockback_immunity: bool | None = None
    freeze_immunity: bool | None = None
    slow_immunity: bool | None = None
    weaken_immunity: bool | None = None
    burrow_count: int | None = None
    burrow_distance: int | None = None
    revive_count: int | None = None
    revive_time: int | None = None
    revive_hp_percentage: int | None = None
    witch: bool | None = None
    base: bool | None = None
    attacks_before_set_attack_state: int | None = None
    time_before_death: int | None = None
    attack_state: int | None = None
    spawn_anim_model_id: int | None = None
    soul_model_anim_id: int | None = None
    attack_2_damage: int | None = None
    attack_3_damage: int | None = None
    attack_2_foreswing: int | None = None
    attack_3_foreswing: int | None = None
    attack_1_use_ability: bool | None = None
    attack_2_use_ability: bool | None = None
    attack_3_use_ability: bool | None = None
    has_entry_maanim: bool | None = None
    has_death_maanim: bool | None = None
    barrier_hp: int | None = None
    warp_prob: int | None = None
    warp_duration: int | None = None
    warp_min_range: int | None = None
    warp_max_range: int | None = None
    starred_alien: bool | None = None
    warp_blocker: bool | None = None
    eva_angel: bool | None = None
    relic: bool | None = None
    curse_prob: int | None = None
    curse_duration: int | None = None
    savage_blow_prob: int | None = None
    savage_blow_damage_addition: int | None = None
    dodge_prob: int | None = None
    dodge_duration: int | None = None
    toxic_prob: int | None = None
    toxic_hp_percentage: int | None = None
    surge_prob: int | None = None
    surge_start: int | None = None
    surge_range: int | None = None
    surge_level: int | None = None
    surge_immunity: bool | None = None
    wave_is_mini: bool | None = None
    shield_hp: int | None = None
    sheild_kb_heal_percentage: int | None = None
    death_surge_prob: int | None = None
    death_surge_start: int | None = None
    death_surge_range: int | None = None
    death_surge_level: int | None = None
    aku: bool | None = None
    baron: bool | None = None
    attack_2_ld_flag: bool | None = None
    attack_2_ld_start: int | None = None
    attack_2_ld_range: int | None = None
    attack_3_ld_flag: bool | None = None
    attack_3_ld_start: int | None = None
    attack_3_ld_range: int | None = None
    behemoth: bool | None = None
    unkown_102: int | None = None
    counter_surge: bool | None = None

    def __post_init__(self):
        self._csv__hp = IntCSVField(col_index=0)
        self._csv__kbs = IntCSVField(col_index=1)
        self._csv__speed = IntCSVField(col_index=2)
        self._csv__attack_1_damage = IntCSVField(col_index=3)
        self._csv__attack_interval = IntCSVField(col_index=4)
        self._csv__attack_range = IntCSVField(col_index=5)
        self._csv__money_drop = IntCSVField(col_index=6)
        self._csv__collision_start = IntCSVField(col_index=7)
        self._csv__collision_width = IntCSVField(col_index=8)
        self._csv__unused = IntCSVField(col_index=9)
        self._csv__red = BoolCSVField(col_index=10)
        self._csv__area_attack = BoolCSVField(col_index=11)
        self._csv__attack_1_foreswing = IntCSVField(col_index=12)
        self._csv__floating = BoolCSVField(col_index=13)
        self._csv__black = BoolCSVField(col_index=14)
        self._csv__metal = BoolCSVField(col_index=15)
        self._csv__traitless = BoolCSVField(col_index=16)
        self._csv__angel = BoolCSVField(col_index=17)
        self._csv__alien = BoolCSVField(col_index=18)
        self._csv__zombie = BoolCSVField(col_index=19)
        self._csv__knockback_prob = IntCSVField(col_index=20)
        self._csv__freeze_prob = IntCSVField(col_index=21)
        self._csv__freeze_duration = IntCSVField(col_index=22)
        self._csv__slow_prob = IntCSVField(col_index=23)
        self._csv__slow_duration = IntCSVField(col_index=24)
        self._csv__crit_prob = IntCSVField(col_index=25)
        self._csv__base_destroyer = BoolCSVField(col_index=26)
        self._csv__wave_prob = IntCSVField(col_index=27)
        self._csv__wave_level = IntCSVField(col_index=28)
        self._csv__weaken_prob = IntCSVField(col_index=29)
        self._csv__weaken_duration = IntCSVField(col_index=30)
        self._csv__weaken_percentage = IntCSVField(col_index=31)
        self._csv__strengthen_hp_start_percentage = IntCSVField(col_index=32)
        self._csv__strengthen_hp_boost_percentage = IntCSVField(col_index=33)
        self._csv__survive_lethal_strike_prob = IntCSVField(col_index=34)
        self._csv__attack_1_ld_start = IntCSVField(col_index=35)
        self._csv__attack_1_ld_range = IntCSVField(col_index=36)
        self._csv__wave_immunity = BoolCSVField(col_index=37)
        self._csv__wave_blocker = BoolCSVField(col_index=38)
        self._csv__knockback_immunity = BoolCSVField(col_index=39)
        self._csv__freeze_immunity = BoolCSVField(col_index=40)
        self._csv__slow_immunity = BoolCSVField(col_index=41)
        self._csv__weaken_immunity = BoolCSVField(col_index=42)
        self._csv__burrow_count = IntCSVField(col_index=43)
        self._csv__burrow_distance = IntCSVField(col_index=44)
        self._csv__revive_count = IntCSVField(col_index=45)
        self._csv__revive_time = IntCSVField(col_index=46)
        self._csv__revive_hp_percentage = IntCSVField(col_index=47)
        self._csv__witch = BoolCSVField(col_index=48)
        self._csv__base = BoolCSVField(col_index=49)
        self._csv__attacks_before_set_attack_state = IntCSVField(col_index=50)
        self._csv__time_before_death = IntCSVField(col_index=51)
        self._csv__attack_state = IntCSVField(col_index=52)
        self._csv__spawn_anim_model_id = IntCSVField(col_index=53)
        self._csv__soul_model_anim_id = IntCSVField(col_index=54)
        self._csv__attack_2_damage = IntCSVField(col_index=55)
        self._csv__attack_3_damage = IntCSVField(col_index=56)
        self._csv__attack_2_foreswing = IntCSVField(col_index=57)
        self._csv__attack_3_foreswing = IntCSVField(col_index=58)
        self._csv__attack_1_use_ability = BoolCSVField(col_index=59)
        self._csv__attack_2_use_ability = BoolCSVField(col_index=60)
        self._csv__attack_3_use_ability = BoolCSVField(col_index=61)
        self._csv__has_entry_maanim = BoolCSVField(col_index=62)
        self._csv__has_death_maanim = BoolCSVField(col_index=63)
        self._csv__barrier_hp = IntCSVField(col_index=64)
        self._csv__warp_prob = IntCSVField(col_index=65)
        self._csv__warp_duration = IntCSVField(col_index=66)
        self._csv__warp_min_range = IntCSVField(col_index=67)
        self._csv__warp_max_range = IntCSVField(col_index=68)
        self._csv__starred_alien = BoolCSVField(col_index=69)
        self._csv__warp_blocker = BoolCSVField(col_index=70)
        self._csv__eva_angel = BoolCSVField(col_index=71)
        self._csv__relic = BoolCSVField(col_index=72)
        self._csv__curse_prob = IntCSVField(col_index=73)
        self._csv__curse_duration = IntCSVField(col_index=74)
        self._csv__savage_blow_prob = IntCSVField(col_index=75)
        self._csv__savage_blow_damage_addition = IntCSVField(col_index=76)
        self._csv__dodge_prob = IntCSVField(col_index=77)
        self._csv__dodge_duration = IntCSVField(col_index=78)
        self._csv__toxic_prob = IntCSVField(col_index=79)
        self._csv__toxic_hp_percentage = IntCSVField(col_index=80)
        self._csv__surge_prob = IntCSVField(col_index=81)
        self._csv__surge_start = IntCSVField(col_index=82)
        self._csv__surge_range = IntCSVField(col_index=83)
        self._csv__surge_level = IntCSVField(col_index=84)
        self._csv__surge_immunity = BoolCSVField(col_index=85)
        self._csv__wave_is_mini = BoolCSVField(col_index=86)
        self._csv__shield_hp = IntCSVField(col_index=87)
        self._csv__sheild_kb_heal_percentage = IntCSVField(col_index=88)
        self._csv__death_surge_prob = IntCSVField(col_index=89)
        self._csv__death_surge_start = IntCSVField(col_index=90)
        self._csv__death_surge_range = IntCSVField(col_index=91)
        self._csv__death_surge_level = IntCSVField(col_index=92)
        self._csv__aku = BoolCSVField(col_index=93)
        self._csv__baron = BoolCSVField(col_index=94)
        self._csv__attack_2_ld_flag = BoolCSVField(col_index=95)
        self._csv__attack_2_ld_start = IntCSVField(col_index=96)
        self._csv__attack_2_ld_range = IntCSVField(col_index=97)
        self._csv__attack_3_ld_flag = BoolCSVField(col_index=98)
        self._csv__attack_3_ld_start = IntCSVField(col_index=99)
        self._csv__attack_3_ld_range = IntCSVField(col_index=100)
        self._csv__behemoth = BoolCSVField(col_index=101)
        self._csv__unkown_102 = IntCSVField(col_index=102)
        self._csv__counter_surge = BoolCSVField(col_index=103)

    def apply_csv(self, enemy_id: int, csv: tbcml.CSV):
        csv.index = enemy_id + 2
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, enemy_id: int, csv: tbcml.CSV):
        csv.index = enemy_id + 2
        tbcml.Modification.read_csv_fields(self, csv)

    def has_targeted_effect(self) -> bool:
        to_check = [
            self.knockback_prob,
            self.freeze_prob,
            self.slow_prob,
            self.weaken_prob,
            self.warp_prob,
            self.curse_prob,
            self.dodge_prob,
        ]
        return any(to_check)


@dataclass
class Enemy(tbcml.Modification):
    enemy_id: int = field(metadata={"required": True})

    name: str | None = None
    description: list[str] | None = None
    stats: EnemyStats | None = None
    anim: tbcml.Model | None = None
    icon: tbcml.BCImage | None = None

    def __post_init__(self):
        self._csv__name = StringCSVField(col_index=0)
        self._csv__description = StrListCSVField(col_index=0, length=5)

    def set_enemy_id(self, id: int):
        self.enemy_id = id
        if self.anim is not None:
            self.anim.set_id(id, "e")

    def get_release_id(self) -> int:
        return self.enemy_id + 2

    def get_anim(self) -> tbcml.Model:
        if self.anim is None:
            self.anim = tbcml.Model()
        return self.anim

    def get_icon(self) -> tbcml.BCImage:
        if self.icon is None:
            self.icon = tbcml.BCImage.from_size(64, 64)
        return self.icon

    def get_stats(self) -> "EnemyStats":
        if self.stats is None:
            self.stats = EnemyStats()
        return self.stats

    def apply_game_data(self, game_data: tbcml.GamePacks):
        self.apply_name(game_data)
        self.apply_description(game_data)
        self.apply_stats(game_data)
        self.apply_icon(game_data)
        self.apply_anim(game_data)

    def apply_name(self, game_data: tbcml.GamePacks):
        file_name, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self._csv__name.value = self.name
            self._csv__name.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_description(self, game_data: tbcml.GamePacks):
        file_name, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self._csv__description.value = self.description
            self._csv__description.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_stats(self, game_data: tbcml.GamePacks):
        file_name, csv = Enemy.get_stats_csv(game_data)
        if csv is not None and self.stats is not None:
            self.stats.apply_csv(self.enemy_id, csv)
            game_data.set_csv(file_name, csv)

    def apply_icon(self, game_data: tbcml.GamePacks):
        game_data.set_img(self.get_enemy_icon_name(), self.icon)

    def apply_anim(self, game_data: tbcml.GamePacks):
        if self.anim is not None:
            self.anim.apply_game_data(game_data)

    def read(self, game_data: tbcml.GamePacks):
        self.read_name(game_data)
        self.read_descripion(game_data)
        self.read_stats(game_data)
        self.read_icon(game_data)
        self.read_icon(game_data)
        self.read_anim(game_data)

    def read_name(self, game_data: tbcml.GamePacks):
        _, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self._csv__name.read_from_csv(csv)
            self.name = self._csv__name.value

    def read_descripion(self, game_data: tbcml.GamePacks):
        _, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self._csv__description.read_from_csv(csv)
            if self._csv__description.value is not None:
                self.description = self._csv__description.value

    def read_stats(self, game_data: tbcml.GamePacks):
        _, csv = Enemy.get_stats_csv(game_data)
        if csv is not None:
            self.get_stats().read_csv(self.enemy_id, csv)

    def read_icon(self, game_data: tbcml.GamePacks):
        self.icon = game_data.get_img(self.get_enemy_icon_name())

    def read_anim(self, game_data: tbcml.GamePacks):
        self.anim = tbcml.Model()
        self.anim.read(
            game_data,
            self.get_sprite_file_name(),
            self.get_imgcut_file_name(),
            self.get_maanim_paths(),
            self.get_mamodel_file_name(),
        )

    def get_enemy_icon_name(self):
        return f"enemy_icon_{self.get_enemy_id_str(self.enemy_id)}.png"

    @staticmethod
    def get_enemy_id_str(enemy_id: int) -> str:
        return tbcml.PaddedInt(enemy_id, 3).to_str()

    @staticmethod
    def get_name_csv(game_data: tbcml.GamePacks) -> tuple[str, tbcml.CSV | None]:
        file_name_desc = f"Enemyname.tsv"
        name_csv = game_data.get_csv(file_name_desc, delimeter="\t")
        return file_name_desc, name_csv

    @staticmethod
    def get_descripion_csv(
        game_data: tbcml.GamePacks,
    ) -> tuple[str, tbcml.CSV | None]:
        file_name_desc = f"EnemyPictureBook_{game_data.localizable.get_lang()}.csv"
        desc_csv = game_data.get_csv(
            file_name_desc, country_code=game_data.country_code
        )
        return file_name_desc, desc_csv

    @staticmethod
    def get_stats_csv(
        game_data: tbcml.GamePacks,
    ) -> tuple[str, tbcml.CSV | None]:
        file_name_stat = f"t_unit.csv"
        stat_csv = game_data.get_csv(file_name_stat)

        return file_name_stat, stat_csv

    def pre_to_json(self):
        if self.icon is not None:
            self.icon.save_b64()
        if self.anim is not None:
            self.anim.texture.save_b64()

    def get_custom_html(self) -> str:
        return (
            f'<span style="color:#000">{self.name} (enemy id: {self.enemy_id})</span>'
        )

    def get_sprite_file_name(self):
        return f"{Enemy.get_enemy_id_str(self.enemy_id)}_e.png"

    def get_imgcut_file_name(self):
        return self.get_sprite_file_name().replace(".png", ".imgcut")

    def get_mamodel_file_name(self):
        return self.get_sprite_file_name().replace(".png", ".mamodel")

    def get_maanim_file_name(self, anim_type: tbcml.AnimType):
        anim_type_str = tbcml.PaddedInt(anim_type.value, 2).to_str()
        return self.get_sprite_file_name().replace(".png", f"{anim_type_str}.maanim")

    def get_maanim_paths(self) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in tbcml.AnimType:
            maanim_paths.append(self.get_maanim_file_name(anim_type))
        enemy_id_str = Enemy.get_enemy_id_str(self.enemy_id)
        maanim_paths.append(f"{enemy_id_str}_e_entry.maanim")
        maanim_paths.append(f"{enemy_id_str}_e_soul.maanim")
        return maanim_paths

    def import_from_bcu(self, bcu_zip: tbcml.BCUZip, bcu_id: int) -> bool:
        bcu_enemy = bcu_zip.get_bcu_enemy(self.enemy_id, bcu_id)
        if bcu_enemy is None:
            return False

        bcu_enemy.write_to_enemy(self)
        return True
