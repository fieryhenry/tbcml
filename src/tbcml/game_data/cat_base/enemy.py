from typing import Optional
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
    hp: Optional[int] = None
    kbs: Optional[int] = None
    speed: Optional[int] = None
    attack_1_damage: Optional[int] = None
    attack_interval: Optional[int] = None
    attack_range: Optional[int] = None
    money_drop: Optional[int] = None
    collision_start: Optional[int] = None
    collision_width: Optional[int] = None
    unused: Optional[int] = None
    red: Optional[bool] = None
    area_attack: Optional[bool] = None
    attack_1_foreswing: Optional[int] = None
    floating: Optional[bool] = None
    black: Optional[bool] = None
    metal: Optional[bool] = None
    traitless: Optional[bool] = None
    angel: Optional[bool] = None
    alien: Optional[bool] = None
    zombie: Optional[bool] = None
    knockback_prob: Optional[int] = None
    freeze_prob: Optional[int] = None
    freeze_duration: Optional[int] = None
    slow_prob: Optional[int] = None
    slow_duration: Optional[int] = None
    crit_prob: Optional[int] = None
    base_destroyer: Optional[bool] = None
    wave_prob: Optional[int] = None
    wave_level: Optional[int] = None
    weaken_prob: Optional[int] = None
    weaken_duration: Optional[int] = None
    weaken_percentage: Optional[int] = None
    strengthen_hp_start_percentage: Optional[int] = None
    strengthen_hp_boost_percentage: Optional[int] = None
    survive_lethal_strike_prob: Optional[int] = None
    attack_1_ld_start: Optional[int] = None
    attack_1_ld_range: Optional[int] = None
    wave_immunity: Optional[bool] = None
    wave_blocker: Optional[bool] = None
    knockback_immunity: Optional[bool] = None
    freeze_immunity: Optional[bool] = None
    slow_immunity: Optional[bool] = None
    weaken_immunity: Optional[bool] = None
    burrow_count: Optional[int] = None
    burrow_distance: Optional[int] = None
    revive_count: Optional[int] = None
    revive_time: Optional[int] = None
    revive_hp_percentage: Optional[int] = None
    witch: Optional[bool] = None
    base: Optional[bool] = None
    attacks_before_set_attack_state: Optional[int] = None
    time_before_death: Optional[int] = None
    attack_state: Optional[int] = None
    spawn_anim_model_id: Optional[int] = None
    soul_model_anim_id: Optional[int] = None
    attack_2_damage: Optional[int] = None
    attack_3_damange: Optional[int] = None
    attack_2_foreswing: Optional[int] = None
    attack_3_foreswing: Optional[int] = None
    attack_1_use_ability: Optional[bool] = None
    attack_2_use_ability: Optional[bool] = None
    attack_3_use_ability: Optional[bool] = None
    has_entry_maanim: Optional[bool] = None
    has_death_maanim: Optional[bool] = None
    barrier_hp: Optional[int] = None
    warp_prob: Optional[int] = None
    warp_duration: Optional[int] = None
    warp_min_range: Optional[int] = None
    warp_max_range: Optional[int] = None
    starred_alien: Optional[bool] = None
    warp_blocker: Optional[bool] = None
    eva_angel: Optional[bool] = None
    relic: Optional[bool] = None
    curse_prob: Optional[int] = None
    curse_duration: Optional[int] = None
    savage_blow_prob: Optional[int] = None
    savage_blow_damage_addition: Optional[int] = None
    dodge_prob: Optional[int] = None
    dodge_duration: Optional[int] = None
    toxic_prob: Optional[int] = None
    toxic_hp_percentage: Optional[int] = None
    surge_prob: Optional[int] = None
    surge_start: Optional[int] = None
    surge_range: Optional[int] = None
    surge_level: Optional[int] = None
    surge_immunity: Optional[bool] = None
    wave_is_mini: Optional[bool] = None
    shield_hp: Optional[int] = None
    sheild_kb_heal_percentage: Optional[int] = None
    death_surge_prob: Optional[int] = None
    death_surge_start: Optional[int] = None
    death_surge_range: Optional[int] = None
    death_surge_level: Optional[int] = None
    aku: Optional[bool] = None
    baron: Optional[bool] = None
    attack_2_ld_flag: Optional[bool] = None
    attack_2_ld_start: Optional[int] = None
    attack_2_ld_range: Optional[int] = None
    attack_3_ld_flag: Optional[bool] = None
    attack_3_ld_start: Optional[int] = None
    attack_3_ld_range: Optional[int] = None
    behemoth: Optional[bool] = None
    unkown_102: Optional[int] = None
    counter_surge: Optional[bool] = None

    def __post_init__(self):
        self.csv__hp = IntCSVField(col_index=0)
        self.csv__kbs = IntCSVField(col_index=1)
        self.csv__speed = IntCSVField(col_index=2)
        self.csv__attack_1_damage = IntCSVField(col_index=3)
        self.csv__attack_interval = IntCSVField(col_index=4)
        self.csv__attack_range = IntCSVField(col_index=5)
        self.csv__money_drop = IntCSVField(col_index=6)
        self.csv__collision_start = IntCSVField(col_index=7)
        self.csv__collision_width = IntCSVField(col_index=8)
        self.csv__unused = IntCSVField(col_index=9)
        self.csv__red = BoolCSVField(col_index=10)
        self.csv__area_attack = BoolCSVField(col_index=11)
        self.csv__attack_1_foreswing = IntCSVField(col_index=12)
        self.csv__floating = BoolCSVField(col_index=13)
        self.csv__black = BoolCSVField(col_index=14)
        self.csv__metal = BoolCSVField(col_index=15)
        self.csv__traitless = BoolCSVField(col_index=16)
        self.csv__angel = BoolCSVField(col_index=17)
        self.csv__alien = BoolCSVField(col_index=18)
        self.csv__zombie = BoolCSVField(col_index=19)
        self.csv__knockback_prob = IntCSVField(col_index=20)
        self.csv__freeze_prob = IntCSVField(col_index=21)
        self.csv__freeze_duration = IntCSVField(col_index=22)
        self.csv__slow_prob = IntCSVField(col_index=23)
        self.csv__slow_duration = IntCSVField(col_index=24)
        self.csv__crit_prob = IntCSVField(col_index=25)
        self.csv__base_destroyer = BoolCSVField(col_index=26)
        self.csv__wave_prob = IntCSVField(col_index=27)
        self.csv__wave_level = IntCSVField(col_index=28)
        self.csv__weaken_prob = IntCSVField(col_index=29)
        self.csv__weaken_duration = IntCSVField(col_index=30)
        self.csv__weaken_percentage = IntCSVField(col_index=31)
        self.csv__strengthen_hp_start_percentage = IntCSVField(col_index=32)
        self.csv__strengthen_hp_boost_percentage = IntCSVField(col_index=33)
        self.csv__survive_lethal_strike_prob = IntCSVField(col_index=34)
        self.csv__attack_1_ld_start = IntCSVField(col_index=35)
        self.csv__attack_1_ld_range = IntCSVField(col_index=36)
        self.csv__wave_immunity = BoolCSVField(col_index=37)
        self.csv__wave_blocker = BoolCSVField(col_index=38)
        self.csv__knockback_immunity = BoolCSVField(col_index=39)
        self.csv__freeze_immunity = BoolCSVField(col_index=40)
        self.csv__slow_immunity = BoolCSVField(col_index=41)
        self.csv__weaken_immunity = BoolCSVField(col_index=42)
        self.csv__burrow_count = IntCSVField(col_index=43)
        self.csv__burrow_distance = IntCSVField(col_index=44)
        self.csv__revive_count = IntCSVField(col_index=45)
        self.csv__revive_time = IntCSVField(col_index=46)
        self.csv__revive_hp_percentage = IntCSVField(col_index=47)
        self.csv__witch = BoolCSVField(col_index=48)
        self.csv__base = BoolCSVField(col_index=49)
        self.csv__attacks_before_set_attack_state = IntCSVField(col_index=50)
        self.csv__time_before_death = IntCSVField(col_index=51)
        self.csv__attack_state = IntCSVField(col_index=52)
        self.csv__spawn_anim_model_id = IntCSVField(col_index=53)
        self.csv__soul_model_anim_id = IntCSVField(col_index=54)
        self.csv__attack_2_damage = IntCSVField(col_index=55)
        self.csv__attack_3_damange = IntCSVField(col_index=56)
        self.csv__attack_2_foreswing = IntCSVField(col_index=57)
        self.csv__attack_3_foreswing = IntCSVField(col_index=58)
        self.csv__attack_1_use_ability = BoolCSVField(col_index=59)
        self.csv__attack_2_use_ability = BoolCSVField(col_index=60)
        self.csv__attack_3_use_ability = BoolCSVField(col_index=61)
        self.csv__has_entry_maanim = BoolCSVField(col_index=62)
        self.csv__has_death_maanim = BoolCSVField(col_index=63)
        self.csv__barrier_hp = IntCSVField(col_index=64)
        self.csv__warp_prob = IntCSVField(col_index=65)
        self.csv__warp_duration = IntCSVField(col_index=66)
        self.csv__warp_min_range = IntCSVField(col_index=67)
        self.csv__warp_max_range = IntCSVField(col_index=68)
        self.csv__starred_alien = BoolCSVField(col_index=69)
        self.csv__warp_blocker = BoolCSVField(col_index=70)
        self.csv__eva_angel = BoolCSVField(col_index=71)
        self.csv__relic = BoolCSVField(col_index=72)
        self.csv__curse_prob = IntCSVField(col_index=73)
        self.csv__curse_duration = IntCSVField(col_index=74)
        self.csv__savage_blow_prob = IntCSVField(col_index=75)
        self.csv__savage_blow_damage_addition = IntCSVField(col_index=76)
        self.csv__dodge_prob = IntCSVField(col_index=77)
        self.csv__dodge_duration = IntCSVField(col_index=78)
        self.csv__toxic_prob = IntCSVField(col_index=79)
        self.csv__toxic_hp_percentage = IntCSVField(col_index=80)
        self.csv__surge_prob = IntCSVField(col_index=81)
        self.csv__surge_start = IntCSVField(col_index=82)
        self.csv__surge_range = IntCSVField(col_index=83)
        self.csv__surge_level = IntCSVField(col_index=84)
        self.csv__surge_immunity = BoolCSVField(col_index=85)
        self.csv__wave_is_mini = BoolCSVField(col_index=86)
        self.csv__shield_hp = IntCSVField(col_index=87)
        self.csv__sheild_kb_heal_percentage = IntCSVField(col_index=88)
        self.csv__death_surge_prob = IntCSVField(col_index=89)
        self.csv__death_surge_start = IntCSVField(col_index=90)
        self.csv__death_surge_range = IntCSVField(col_index=91)
        self.csv__death_surge_level = IntCSVField(col_index=92)
        self.csv__aku = BoolCSVField(col_index=93)
        self.csv__baron = BoolCSVField(col_index=94)
        self.csv__attack_2_ld_flag = BoolCSVField(col_index=95)
        self.csv__attack_2_ld_start = IntCSVField(col_index=96)
        self.csv__attack_2_ld_range = IntCSVField(col_index=97)
        self.csv__attack_3_ld_flag = BoolCSVField(col_index=98)
        self.csv__attack_3_ld_start = IntCSVField(col_index=99)
        self.csv__attack_3_ld_range = IntCSVField(col_index=100)
        self.csv__behemoth = BoolCSVField(col_index=101)
        self.csv__unkown_102 = IntCSVField(col_index=102)
        self.csv__counter_surge = BoolCSVField(col_index=103)

    def apply_csv(self, enemy_id: int, csv: "tbcml.CSV"):
        csv.index = enemy_id + 2
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, enemy_id: int, csv: "tbcml.CSV"):
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
    modification_type: tbcml.ModificationType = tbcml.ModificationType.ENEMY

    name: Optional[str] = None
    description: Optional[list[str]] = None
    stats: Optional[EnemyStats] = None
    anim: Optional["tbcml.Model"] = None
    icon: Optional["tbcml.BCImage"] = None

    def __post_init__(self):
        self.csv__name = StringCSVField(col_index=0)
        self.csv__description = StrListCSVField(col_index=0, length=5)

        Enemy.Schema()

    def set_enemy_id(self, id: int):
        self.enemy_id = id
        if self.anim is not None:
            self.anim.set_id(id, "e")

    def get_release_id(self) -> int:
        return self.enemy_id + 2

    def get_anim(self) -> "tbcml.Model":
        if self.anim is None:
            self.anim = tbcml.Model()
        return self.anim

    def get_icon(self) -> "tbcml.BCImage":
        if self.icon is None:
            self.icon = tbcml.BCImage.from_size(64, 64)
        return self.icon

    def get_stats(self) -> "EnemyStats":
        if self.stats is None:
            self.stats = EnemyStats()
        return self.stats

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_name(game_data)
        self.apply_description(game_data)
        self.apply_stats(game_data)
        self.apply_icon(game_data)
        self.apply_anim(game_data)

    def apply_name(self, game_data: "tbcml.GamePacks"):
        file_name, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.csv__name.value = self.name
            self.csv__name.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_description(self, game_data: "tbcml.GamePacks"):
        file_name, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.csv__description.value = self.description
            self.csv__description.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_stats(self, game_data: "tbcml.GamePacks"):
        file_name, csv = Enemy.get_stats_csv(game_data)
        if csv is not None and self.stats is not None:
            self.stats.apply_csv(self.enemy_id, csv)
            game_data.set_csv(file_name, csv)

    def apply_icon(self, game_data: "tbcml.GamePacks"):
        game_data.set_img(self.get_enemy_icon_name(), self.icon)

    def apply_anim(self, game_data: "tbcml.GamePacks"):
        if self.anim is not None:
            self.anim.apply(game_data)

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_name(game_data)
        self.read_descripion(game_data)
        self.read_stats(game_data)
        self.read_icon(game_data)
        self.read_icon(game_data)
        self.read_anim(game_data)

    def read_name(self, game_data: "tbcml.GamePacks"):
        _, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.csv__name.read_from_csv(csv)
            self.name = self.csv__name.value

    def read_descripion(self, game_data: "tbcml.GamePacks"):
        _, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.csv__description.read_from_csv(csv)
            if self.csv__description.value is not None:
                self.description = self.csv__description.value

    def read_stats(self, game_data: "tbcml.GamePacks"):
        _, csv = Enemy.get_stats_csv(game_data)
        if csv is not None:
            self.get_stats().read_csv(self.enemy_id, csv)

    def read_icon(self, game_data: "tbcml.GamePacks"):
        self.icon = game_data.get_img(self.get_enemy_icon_name())

    def read_anim(self, game_data: "tbcml.GamePacks"):
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
    def get_name_csv(game_data: "tbcml.GamePacks") -> tuple[str, Optional["tbcml.CSV"]]:
        file_name_desc = f"Enemyname.tsv"
        name_csv = game_data.get_csv(file_name_desc, delimeter="\t")
        return file_name_desc, name_csv

    @staticmethod
    def get_descripion_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name_desc = f"EnemyPictureBook_{game_data.localizable.get_lang()}.csv"
        desc_csv = game_data.get_csv(
            file_name_desc, country_code=game_data.country_code
        )
        return file_name_desc, desc_csv

    @staticmethod
    def get_stats_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
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

    def get_maanim_file_name(self, anim_type: "tbcml.AnimType"):
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

    def import_from_bcu(self, bcu_zip: "tbcml.BCUZip", bcu_id: int) -> bool:
        bcu_enemy = bcu_zip.get_bcu_enemy(self.enemy_id, bcu_id)
        if bcu_enemy is None:
            return False

        bcu_enemy.write_to_enemy(self)
        return True
