from typing import Optional
from dataclasses import field
from tbcml import core

from tbcml.core.io.csv_fields import (
    IntCSVField,
    CSVField,
    BoolCSVField,
    StringCSVField,
    StrListCSVField,
)

from marshmallow_dataclass import dataclass


@dataclass
class EnemyStats:
    hp: IntCSVField = CSVField.to_field(IntCSVField, 0)
    kbs: IntCSVField = CSVField.to_field(IntCSVField, 1)
    speed: IntCSVField = CSVField.to_field(IntCSVField, 2)
    attack_1_damage: IntCSVField = CSVField.to_field(IntCSVField, 3)
    attack_interval: IntCSVField = CSVField.to_field(IntCSVField, 4)
    attack_range: IntCSVField = CSVField.to_field(IntCSVField, 5)
    money_drop: IntCSVField = CSVField.to_field(IntCSVField, 6)
    collision_start: IntCSVField = CSVField.to_field(IntCSVField, 7)
    collision_width: IntCSVField = CSVField.to_field(IntCSVField, 8)
    unused: IntCSVField = CSVField.to_field(IntCSVField, 9)
    red: BoolCSVField = CSVField.to_field(BoolCSVField, 10)
    area_attack: BoolCSVField = CSVField.to_field(BoolCSVField, 11)
    attack_1_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 12)
    floating: BoolCSVField = CSVField.to_field(BoolCSVField, 13)
    black: BoolCSVField = CSVField.to_field(BoolCSVField, 14)
    metal: BoolCSVField = CSVField.to_field(BoolCSVField, 15)
    traitless: BoolCSVField = CSVField.to_field(BoolCSVField, 16)
    angel: BoolCSVField = CSVField.to_field(BoolCSVField, 17)
    alien: BoolCSVField = CSVField.to_field(BoolCSVField, 18)
    zombie: BoolCSVField = CSVField.to_field(BoolCSVField, 19)
    knockback_prob: IntCSVField = CSVField.to_field(IntCSVField, 20)
    freeze_prob: IntCSVField = CSVField.to_field(IntCSVField, 21)
    freeze_duration: IntCSVField = CSVField.to_field(IntCSVField, 22)
    slow_prob: IntCSVField = CSVField.to_field(IntCSVField, 23)
    slow_duration: IntCSVField = CSVField.to_field(IntCSVField, 24)
    crit_prob: IntCSVField = CSVField.to_field(IntCSVField, 25)
    base_destroyer: BoolCSVField = CSVField.to_field(BoolCSVField, 26)
    wave_prob: IntCSVField = CSVField.to_field(IntCSVField, 27)
    wave_level: IntCSVField = CSVField.to_field(IntCSVField, 28)
    weaken_prob: IntCSVField = CSVField.to_field(IntCSVField, 29)
    weaken_duration: IntCSVField = CSVField.to_field(IntCSVField, 30)
    weaken_percentage: IntCSVField = CSVField.to_field(IntCSVField, 31)
    strengthen_hp_start_percentage: IntCSVField = CSVField.to_field(IntCSVField, 32)
    strengthen_hp_boost_percentage: IntCSVField = CSVField.to_field(IntCSVField, 33)
    survive_lethal_strike_prob: IntCSVField = CSVField.to_field(IntCSVField, 34)
    attack_1_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 35)
    attack_1_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 36)
    wave_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 37)
    wave_blocker: BoolCSVField = CSVField.to_field(BoolCSVField, 38)
    knockback_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 39)
    freeze_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 40)
    slow_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 41)
    weaken_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 42)
    burrow_count: IntCSVField = CSVField.to_field(IntCSVField, 43)
    burrow_distance: IntCSVField = CSVField.to_field(IntCSVField, 44)
    revive_count: IntCSVField = CSVField.to_field(IntCSVField, 45)
    revive_time: IntCSVField = CSVField.to_field(IntCSVField, 46)
    revive_hp_percentage: IntCSVField = CSVField.to_field(IntCSVField, 47)
    witch: BoolCSVField = CSVField.to_field(BoolCSVField, 48)
    base: BoolCSVField = CSVField.to_field(BoolCSVField, 49)
    attacks_before_set_attack_state: IntCSVField = CSVField.to_field(IntCSVField, 50)
    time_before_death: IntCSVField = CSVField.to_field(IntCSVField, 51)
    attack_state: IntCSVField = CSVField.to_field(IntCSVField, 52)
    spawn_anim_model_id: IntCSVField = CSVField.to_field(IntCSVField, 53)
    soul_model_anim_id: IntCSVField = CSVField.to_field(IntCSVField, 54)
    attack_2_damage: IntCSVField = CSVField.to_field(IntCSVField, 55)
    attack_3_damange: IntCSVField = CSVField.to_field(IntCSVField, 56)
    attack_2_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 57)
    attack_3_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 58)
    attack_1_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 59)
    attack_2_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 60)
    attack_3_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 61)
    has_entry_maanim: BoolCSVField = CSVField.to_field(BoolCSVField, 62)
    has_death_maanim: BoolCSVField = CSVField.to_field(BoolCSVField, 63)
    barrier_hp: IntCSVField = CSVField.to_field(IntCSVField, 64)
    warp_prob: IntCSVField = CSVField.to_field(IntCSVField, 65)
    warp_duration: IntCSVField = CSVField.to_field(IntCSVField, 66)
    warp_min_range: IntCSVField = CSVField.to_field(IntCSVField, 67)
    warp_max_range: IntCSVField = CSVField.to_field(IntCSVField, 68)
    starred_alien: BoolCSVField = CSVField.to_field(BoolCSVField, 69)
    warp_blocker: BoolCSVField = CSVField.to_field(BoolCSVField, 70)
    eva_angel: BoolCSVField = CSVField.to_field(BoolCSVField, 71)
    relic: BoolCSVField = CSVField.to_field(BoolCSVField, 72)
    curse_prob: IntCSVField = CSVField.to_field(IntCSVField, 73)
    curse_duration: IntCSVField = CSVField.to_field(IntCSVField, 74)
    savage_blow_prob: IntCSVField = CSVField.to_field(IntCSVField, 75)
    savage_blow_damage_addition: IntCSVField = CSVField.to_field(IntCSVField, 76)
    dodge_prob: IntCSVField = CSVField.to_field(IntCSVField, 77)
    dodge_duration: IntCSVField = CSVField.to_field(IntCSVField, 78)
    toxic_prob: IntCSVField = CSVField.to_field(IntCSVField, 79)
    toxic_hp_percentage: IntCSVField = CSVField.to_field(IntCSVField, 80)
    surge_prob: IntCSVField = CSVField.to_field(IntCSVField, 81)
    surge_start: IntCSVField = CSVField.to_field(IntCSVField, 82)
    surge_range: IntCSVField = CSVField.to_field(IntCSVField, 83)
    surge_level: IntCSVField = CSVField.to_field(IntCSVField, 84)
    surge_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 85)
    wave_is_mini: BoolCSVField = CSVField.to_field(BoolCSVField, 86)
    shield_hp: IntCSVField = CSVField.to_field(IntCSVField, 87)
    sheild_kb_heal_percentage: IntCSVField = CSVField.to_field(IntCSVField, 88)
    death_surge_prob: IntCSVField = CSVField.to_field(IntCSVField, 89)
    death_surge_start: IntCSVField = CSVField.to_field(IntCSVField, 90)
    death_surge_range: IntCSVField = CSVField.to_field(IntCSVField, 91)
    death_surge_level: IntCSVField = CSVField.to_field(IntCSVField, 92)
    aku: BoolCSVField = CSVField.to_field(BoolCSVField, 93)
    baron: BoolCSVField = CSVField.to_field(BoolCSVField, 94)
    attack_2_ld_flag: BoolCSVField = CSVField.to_field(BoolCSVField, 95)
    attack_2_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 96)
    attack_2_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 97)
    attack_3_ld_flag: BoolCSVField = CSVField.to_field(BoolCSVField, 98)
    attack_3_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 99)
    attack_3_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 100)
    behemoth: BoolCSVField = CSVField.to_field(BoolCSVField, 101)
    unkown_102: IntCSVField = CSVField.to_field(IntCSVField, 102)
    counter_surge: BoolCSVField = CSVField.to_field(BoolCSVField, 103)

    def apply_csv(self, enemy_id: int, csv: "core.CSV"):
        csv.index = enemy_id + 2
        core.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, enemy_id: int, csv: "core.CSV"):
        csv.index = enemy_id + 2
        core.Modification.read_csv_fields(self, csv)

    def has_targeted_effect(self) -> bool:
        to_check = [
            self.knockback_prob.value,
            self.freeze_prob.value,
            self.slow_prob.value,
            self.weaken_prob.value,
            self.warp_prob.value,
            self.curse_prob.value,
            self.dodge_prob.value,
        ]
        return any(to_check)


@dataclass
class Enemy(core.Modification):
    enemy_id: int = field(metadata={"required": True})
    name: StringCSVField = CSVField.to_field(StringCSVField, 0)
    description: StrListCSVField = CSVField.to_field(StrListCSVField, 0, length=5)
    stats: Optional[EnemyStats] = None
    anim: Optional["core.CustomModel"] = None
    icon: Optional["core.NewBCImage"] = None
    modification_type: core.ModificationType = core.ModificationType.ENEMY

    def set_enemy_id(self, id: int):
        self.enemy_id = id
        if self.anim is not None:
            self.anim.set_id(id)

    def get_release_id(self) -> int:
        return self.enemy_id + 2

    def get_anim(self) -> "core.CustomModel":
        if self.anim is None:
            self.anim = core.CustomModel()
        return self.anim

    def get_icon(self) -> "core.NewBCImage":
        if self.icon is None:
            self.icon = core.NewBCImage.from_size(64, 64)
        return self.icon

    def get_stats(self) -> "EnemyStats":
        if self.stats is None:
            self.stats = EnemyStats()
        return self.stats

    def __post_init__(
        self,
    ):  # This is required for CustomEnemy.Schema to not be a string for some reason
        Enemy.Schema()

    def apply(self, game_data: "core.GamePacks"):
        self.apply_name(game_data)
        self.apply_description(game_data)
        self.apply_stats(game_data)
        self.apply_icon(game_data)
        self.apply_anim(game_data)

    def apply_name(self, game_data: "core.GamePacks"):
        file_name, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.name.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_description(self, game_data: "core.GamePacks"):
        file_name, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.description.write_to_csv(csv)
            game_data.set_csv(file_name, csv)

    def apply_stats(self, game_data: "core.GamePacks"):
        file_name, csv = Enemy.get_stats_csv(game_data)
        if csv is not None and self.stats is not None:
            self.stats.apply_csv(self.enemy_id, csv)
            game_data.set_csv(file_name, csv)

    def apply_icon(self, game_data: "core.GamePacks"):
        game_data.set_img(self.get_enemy_icon_name(), self.icon)

    def apply_anim(self, game_data: "core.GamePacks"):
        if self.anim is not None:
            self.anim.apply(game_data)

    def read(self, game_data: "core.GamePacks"):
        self.read_name(game_data)
        self.read_descripion(game_data)
        self.read_stats(game_data)
        self.read_icon(game_data)
        self.read_icon(game_data)
        self.read_anim(game_data)

    def read_name(self, game_data: "core.GamePacks"):
        _, csv = Enemy.get_name_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.name.read_from_csv(csv)

    def read_descripion(self, game_data: "core.GamePacks"):
        _, csv = Enemy.get_descripion_csv(game_data)
        if csv is not None:
            csv.index = self.enemy_id
            self.description.read_from_csv(csv)

    def read_stats(self, game_data: "core.GamePacks"):
        _, csv = Enemy.get_stats_csv(game_data)
        if csv is not None:
            self.get_stats().read_csv(self.enemy_id, csv)

    def read_icon(self, game_data: "core.GamePacks"):
        self.icon = game_data.get_img(self.get_enemy_icon_name())

    def read_anim(self, game_data: "core.GamePacks"):
        self.anim = core.CustomModel()
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
        return core.PaddedInt(enemy_id, 3).to_str()

    @staticmethod
    def get_name_csv(game_data: "core.GamePacks") -> tuple[str, Optional["core.CSV"]]:
        file_name_desc = f"Enemyname.tsv"
        name_csv = game_data.get_csv(file_name_desc, delimeter="\t")
        return file_name_desc, name_csv

    @staticmethod
    def get_descripion_csv(
        game_data: "core.GamePacks",
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name_desc = f"EnemyPictureBook_{game_data.localizable.get_lang()}.csv"
        desc_csv = game_data.get_csv(
            file_name_desc, country_code=game_data.country_code
        )
        return file_name_desc, desc_csv

    @staticmethod
    def get_stats_csv(game_data: "core.GamePacks") -> tuple[str, Optional["core.CSV"]]:
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

    def get_maanim_file_name(self, anim_type: "core.AnimType"):
        anim_type_str = core.PaddedInt(anim_type.value, 2).to_str()
        return self.get_sprite_file_name().replace(".png", f"{anim_type_str}.maanim")

    def get_maanim_paths(self) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in core.AnimType:
            maanim_paths.append(self.get_maanim_file_name(anim_type))
        enemy_id_str = Enemy.get_enemy_id_str(self.enemy_id)
        maanim_paths.append(f"{enemy_id_str}_e_entry.maanim")
        maanim_paths.append(f"{enemy_id_str}_e_soul.maanim")
        return maanim_paths
