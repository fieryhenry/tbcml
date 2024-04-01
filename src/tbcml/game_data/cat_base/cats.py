import copy
import enum
from typing import Optional, Sequence, Union
from dataclasses import field
import tbcml

from tbcml.io.csv_fields import (
    IntCSVField,
    BoolCSVField,
    StringCSVField,
    StrListCSVField,
    IntListCSVField,
)

from marshmallow_dataclass import dataclass


class CatFormType(enum.Enum):
    """Represents the different forms a cat has.
    ```
    tbcml.CatFormType.FIRST
    tbcml.CatFormType.SECOND
    tbcml.CatFormType.THIRD
    tbcml.CatFormType.FOURTH
    ```
    """

    FIRST = "f"
    """The first form of a cat."""
    SECOND = "c"
    """The second form of a cat."""
    THIRD = "s"
    """The third form of a cat."""
    FOURTH = "u"
    """The fourth form of a cat. This is only half-supported by the game and does lead to crashes."""

    def get_index(self) -> int:
        """Get the index of the form type.

        Raises:
            ValueError: If the form type is invalid.

        Returns:
            int: The index of the form type.
        """
        if self == CatFormType.FIRST:
            return 0
        elif self == CatFormType.SECOND:
            return 1
        elif self == CatFormType.THIRD:
            return 2
        elif self == CatFormType.FOURTH:
            return 3
        else:
            raise ValueError("Invalid form type")

    @staticmethod
    def from_index(index: int) -> "CatFormType":
        """Get the form type from the index.

        Args:
            index (int): The index of the form type.

        Raises:
            ValueError: If the index is invalid.

        Returns:
            FormType: The form type.
        """
        if index == 0:
            return CatFormType.FIRST
        elif index == 1:
            return CatFormType.SECOND
        elif index == 2:
            return CatFormType.THIRD
        elif index == 3:
            return CatFormType.FOURTH
        else:
            raise ValueError("Invalid form index")

    def __int__(self) -> int:
        """Get the index of the form type.

        Returns:
            int: The index of the form type.
        """
        return self.get_index()


@dataclass
class FormStats:
    """Form Stats Object"""

    hp: Optional[int] = None
    kbs: Optional[int] = None
    speed: Optional[int] = None
    attack_1_damage: Optional[int] = None
    attack_interval: Optional[int] = None
    attack_range: Optional[int] = None
    cost: Optional[int] = None
    recharge_time: Optional[int] = None
    collision_start: Optional[int] = None
    collision_width: Optional[int] = None
    target_red: Optional[bool] = None
    unused: Optional[int] = None
    area_attack: Optional[bool] = None
    attack_1_foreswing: Optional[int] = None
    min_z_layer: Optional[int] = None
    max_z_layer: Optional[int] = None
    target_floating: Optional[bool] = None
    target_black: Optional[bool] = None
    target_metal: Optional[bool] = None
    target_traitless: Optional[bool] = None
    target_angel: Optional[bool] = None
    target_alien: Optional[bool] = None
    target_zombie: Optional[bool] = None
    strong: Optional[bool] = None
    knockback_prob: Optional[int] = None
    freeze_prob: Optional[int] = None
    freeze_duration: Optional[int] = None
    slow_prob: Optional[int] = None
    slow_duration: Optional[int] = None
    resistant: Optional[bool] = None
    massive_damage: Optional[bool] = None
    crit_prob: Optional[int] = None
    attacks_only: Optional[bool] = None
    extra_money: Optional[bool] = None
    base_destroyer: Optional[bool] = None
    wave_prob: Optional[int] = None
    wave_level: Optional[int] = None
    weaken_prob: Optional[int] = None
    weaken_duration: Optional[int] = None
    weaken_percentage: Optional[int] = None
    strengthen_hp_start_percentage: Optional[int] = None
    strengthen_hp_boost_percentage: Optional[int] = None
    lethal_strike_prob: Optional[int] = None
    is_metal: Optional[bool] = None
    attack_1_ld_start: Optional[int] = None
    attack_1_ld_range: Optional[int] = None
    wave_immunity: Optional[bool] = None
    wave_blocker: Optional[bool] = None
    knockback_immunity: Optional[bool] = None
    freeze_immunity: Optional[bool] = None
    slow_immunity: Optional[bool] = None
    weaken_immunity: Optional[bool] = None
    zombie_killer: Optional[bool] = None
    witch_killer: Optional[bool] = None
    target_witch: Optional[bool] = None
    attacks_before_set_attack_state: Optional[int] = None
    shockwave_immune: Optional[bool] = None
    time_before_death: Optional[int] = None
    attack_state: Optional[int] = None
    attack_2_damage: Optional[int] = None
    attack_3_damage: Optional[int] = None
    attack_2_foreswing: Optional[int] = None
    attack_3_foreswing: Optional[int] = None
    attack_1_use_ability: Optional[bool] = None
    attack_2_use_ability: Optional[bool] = None
    attack_3_use_ability: Optional[bool] = None
    spawn_anim_model_id: Optional[int] = None
    soul_model_anim_id: Optional[int] = None
    has_entry_maanim: Optional[bool] = None
    has_death_maanim: Optional[bool] = None
    barrier_break_prob: Optional[int] = None
    warp_prob: Optional[int] = None
    warp_duration: Optional[int] = None
    warp_min_range: Optional[int] = None
    warp_max_range: Optional[int] = None
    warp_blocker: Optional[bool] = None
    target_eva: Optional[bool] = None
    eva_killer: Optional[bool] = None
    target_relic: Optional[bool] = None
    curse_immunity: Optional[bool] = None
    insanely_tough: Optional[bool] = None
    insane_damage: Optional[bool] = None
    savage_blow_prob: Optional[int] = None
    savage_blow_damage_addition: Optional[int] = None
    dodge_prob: Optional[int] = None
    dodge_duration: Optional[int] = None
    surge_prob: Optional[int] = None
    surge_start: Optional[int] = None
    surge_range: Optional[int] = None
    surge_level: Optional[int] = None
    toxic_immunity: Optional[bool] = None
    surge_immunity: Optional[bool] = None
    curse_prob: Optional[int] = None
    curse_duration: Optional[int] = None
    wave_is_mini: Optional[bool] = None
    shield_pierce_prob: Optional[int] = None
    target_aku: Optional[bool] = None
    collossus_slayer: Optional[bool] = None
    soul_strike: Optional[bool] = None
    attack_2_ld_flag: Optional[bool] = None
    attack_2_ld_start: Optional[int] = None
    attack_2_ld_range: Optional[int] = None
    attack_3_ld_flag: Optional[bool] = None
    attack_3_ld_start: Optional[int] = None
    attack_3_ld_range: Optional[int] = None
    behemoth_slayer: Optional[bool] = None
    behemoth_dodge_prob: Optional[int] = None
    behemoth_dodge_duration: Optional[int] = None
    unknown_108: Optional[int] = None
    counter_surge: Optional[bool] = None
    summon_id: Optional[int] = None
    sage_slayer: Optional[bool] = None

    def __post_init__(self):
        self._csv__hp = IntCSVField(col_index=0)
        self._csv__kbs = IntCSVField(col_index=1)
        self._csv__speed = IntCSVField(col_index=2)
        self._csv__attack_1_damage = IntCSVField(col_index=3)
        self._csv__attack_interval = IntCSVField(col_index=4)
        self._csv__attack_range = IntCSVField(col_index=5)
        self._csv__cost = IntCSVField(col_index=6)
        self._csv__recharge_time = IntCSVField(col_index=7)
        self._csv__collision_start = IntCSVField(col_index=8)
        self._csv__collision_width = IntCSVField(col_index=9)
        self._csv__target_red = BoolCSVField(col_index=10)
        self._csv__unused = IntCSVField(col_index=11)
        self._csv__area_attack = BoolCSVField(col_index=12)
        self._csv__attack_1_foreswing = IntCSVField(col_index=13)
        self._csv__min_z_layer = IntCSVField(col_index=14)
        self._csv__max_z_layer = IntCSVField(col_index=15)
        self._csv__target_floating = BoolCSVField(col_index=16)
        self._csv__target_black = BoolCSVField(col_index=17)
        self._csv__target_metal = BoolCSVField(col_index=18)
        self._csv__target_traitless = BoolCSVField(col_index=19)
        self._csv__target_angel = BoolCSVField(col_index=20)
        self._csv__target_alien = BoolCSVField(col_index=21)
        self._csv__target_zombie = BoolCSVField(col_index=22)
        self._csv__strong = BoolCSVField(col_index=23)
        self._csv__knockback_prob = IntCSVField(col_index=24)
        self._csv__freeze_prob = IntCSVField(col_index=25)
        self._csv__freeze_duration = IntCSVField(col_index=26)
        self._csv__slow_prob = IntCSVField(col_index=27)
        self._csv__slow_duration = IntCSVField(col_index=28)
        self._csv__resistant = BoolCSVField(col_index=29)
        self._csv__massive_damage = BoolCSVField(col_index=30)
        self._csv__crit_prob = IntCSVField(col_index=31)
        self._csv__attacks_only = BoolCSVField(col_index=32)
        self._csv__extra_money = BoolCSVField(col_index=33)
        self._csv__base_destroyer = BoolCSVField(col_index=34)
        self._csv__wave_prob = IntCSVField(col_index=35)
        self._csv__wave_level = IntCSVField(col_index=36)
        self._csv__weaken_prob = IntCSVField(col_index=37)
        self._csv__weaken_duration = IntCSVField(col_index=38)
        self._csv__weaken_percentage = IntCSVField(col_index=39)
        self._csv__strengthen_hp_start_percentage = IntCSVField(col_index=40)
        self._csv__strengthen_hp_boost_percentage = IntCSVField(col_index=41)
        self._csv__lethal_strike_prob = IntCSVField(col_index=42)
        self._csv__is_metal = BoolCSVField(col_index=43)
        self._csv__attack_1_ld_start = IntCSVField(col_index=44)
        self._csv__attack_1_ld_range = IntCSVField(col_index=45)
        self._csv__wave_immunity = BoolCSVField(col_index=46)
        self._csv__wave_blocker = BoolCSVField(col_index=47)
        self._csv__knockback_immunity = BoolCSVField(col_index=48)
        self._csv__freeze_immunity = BoolCSVField(col_index=49)
        self._csv__slow_immunity = BoolCSVField(col_index=50)
        self._csv__weaken_immunity = BoolCSVField(col_index=51)
        self._csv__zombie_killer = BoolCSVField(col_index=52)
        self._csv__witch_killer = BoolCSVField(col_index=53)
        self._csv__target_witch = BoolCSVField(col_index=54)
        self._csv__attacks_before_set_attack_state = IntCSVField(col_index=55)
        self._csv__shockwave_immune = BoolCSVField(col_index=56)
        self._csv__time_before_death = IntCSVField(col_index=57)
        self._csv__attack_state = IntCSVField(col_index=58)
        self._csv__attack_2_damage = IntCSVField(col_index=59)
        self._csv__attack_3_damage = IntCSVField(col_index=60)
        self._csv__attack_2_foreswing = IntCSVField(col_index=61)
        self._csv__attack_3_foreswing = IntCSVField(col_index=62)
        self._csv__attack_1_use_ability = BoolCSVField(col_index=63)
        self._csv__attack_2_use_ability = BoolCSVField(col_index=64)
        self._csv__attack_3_use_ability = BoolCSVField(col_index=65)
        self._csv__spawn_anim_model_id = IntCSVField(col_index=66)
        self._csv__soul_model_anim_id = IntCSVField(col_index=67)
        self._csv__has_entry_maanim = BoolCSVField(col_index=68)
        self._csv__has_death_maanim = BoolCSVField(col_index=69)
        self._csv__barrier_break_prob = IntCSVField(col_index=70)
        self._csv__warp_prob = IntCSVField(col_index=71)
        self._csv__warp_duration = IntCSVField(col_index=72)
        self._csv__warp_min_range = IntCSVField(col_index=73)
        self._csv__warp_max_range = IntCSVField(col_index=74)
        self._csv__warp_blocker = BoolCSVField(col_index=75)
        self._csv__target_eva = BoolCSVField(col_index=76)
        self._csv__eva_killer = BoolCSVField(col_index=77)
        self._csv__target_relic = BoolCSVField(col_index=78)
        self._csv__curse_immunity = BoolCSVField(col_index=79)
        self._csv__insanely_tough = BoolCSVField(col_index=80)
        self._csv__insane_damage = BoolCSVField(col_index=81)
        self._csv__savage_blow_prob = IntCSVField(col_index=82)
        self._csv__savage_blow_damage_addition = IntCSVField(col_index=83)
        self._csv__dodge_prob = IntCSVField(col_index=84)
        self._csv__dodge_duration = IntCSVField(col_index=85)
        self._csv__surge_prob = IntCSVField(col_index=86)
        self._csv__surge_start = IntCSVField(col_index=87)
        self._csv__surge_range = IntCSVField(col_index=88)
        self._csv__surge_level = IntCSVField(col_index=89)
        self._csv__toxic_immunity = BoolCSVField(col_index=90)
        self._csv__surge_immunity = BoolCSVField(col_index=91)
        self._csv__curse_prob = IntCSVField(col_index=92)
        self._csv__curse_duration = IntCSVField(col_index=93)
        self._csv__wave_is_mini = BoolCSVField(col_index=94)
        self._csv__shield_pierce_prob = IntCSVField(col_index=95)
        self._csv__target_aku = BoolCSVField(col_index=96)
        self._csv__collossus_slayer = BoolCSVField(col_index=97)
        self._csv__soul_strike = BoolCSVField(col_index=98)
        self._csv__attack_2_ld_flag = BoolCSVField(col_index=99)
        self._csv__attack_2_ld_start = IntCSVField(col_index=100)
        self._csv__attack_2_ld_range = IntCSVField(col_index=101)
        self._csv__attack_3_ld_flag = BoolCSVField(col_index=102)
        self._csv__attack_3_ld_start = IntCSVField(col_index=103)
        self._csv__attack_3_ld_range = IntCSVField(col_index=104)
        self._csv__behemoth_slayer = BoolCSVField(col_index=105)
        self._csv__behemoth_dodge_prob = IntCSVField(col_index=106)
        self._csv__behemoth_dodge_duration = IntCSVField(col_index=107)
        self._csv__unknown_108 = IntCSVField(col_index=108)
        self._csv__counter_surge = BoolCSVField(col_index=109)
        self._csv__summon_id = IntCSVField(col_index=110)
        self._csv__sage_slayer = BoolCSVField(col_index=111)

    def apply_csv(self, form_type: "CatFormType", csv: "tbcml.CSV"):
        index = form_type.get_index()
        csv.index = index
        tbcml.Modification.apply_csv_fields(
            self,
            csv,
            self.get_required(),
            remove_others=False,
        )

    def get_required(self):
        required: list[tuple[int, int]] = [
            (55, -1),
            (57, -1),
            (63, 1),
            (66, -1),
            (110, -1),
        ]

        return required

    def read_csv(self, form_type: "CatFormType", csv: "tbcml.CSV"):
        index = form_type.get_index()
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv, self.get_required())

    def import_enemy(
        self, enemy_stats: "tbcml.EnemyStats", target_all_effects: bool = True
    ):
        has_targeted_effect = enemy_stats.has_targeted_effect()

        self.hp = enemy_stats.hp
        self.kbs = enemy_stats.kbs
        self.speed = enemy_stats.speed
        self.attack_1_damage = enemy_stats.attack_1_damage
        self.attack_interval = enemy_stats.attack_interval
        self.attack_range = enemy_stats.attack_range
        self.collision_start = enemy_stats.collision_start
        self.collision_width = enemy_stats.collision_width
        self.collision_width = enemy_stats.collision_width
        self.unused = enemy_stats.unused
        self.area_attack = enemy_stats.area_attack
        self.attack_1_foreswing = enemy_stats.attack_1_foreswing
        self.knockback_prob = enemy_stats.knockback_prob
        self.freeze_prob = enemy_stats.freeze_prob
        self.freeze_duration = enemy_stats.freeze_duration
        self.slow_prob = enemy_stats.slow_prob
        self.slow_duration = enemy_stats.slow_duration
        self.crit_prob = enemy_stats.crit_prob
        self.wave_prob = enemy_stats.wave_prob
        self.wave_level = enemy_stats.wave_level
        self.weaken_prob = enemy_stats.weaken_prob
        self.weaken_duration = enemy_stats.weaken_duration
        self.weaken_percentage = enemy_stats.weaken_percentage
        self.strengthen_hp_start_percentage = enemy_stats.strengthen_hp_start_percentage
        self.strengthen_hp_boost_percentage = enemy_stats.strengthen_hp_boost_percentage

        self.is_metal = enemy_stats.metal
        self.attack_1_ld_start = enemy_stats.attack_1_ld_start
        self.attack_1_ld_range = enemy_stats.attack_1_ld_range
        self.wave_immunity = enemy_stats.wave_immunity
        self.wave_blocker = enemy_stats.wave_blocker
        self.knockback_immunity = enemy_stats.knockback_immunity
        self.freeze_immunity = enemy_stats.freeze_immunity
        self.slow_immunity = enemy_stats.slow_immunity
        self.weaken_immunity = enemy_stats.weaken_immunity
        self.attacks_before_set_attack_state = (
            enemy_stats.attacks_before_set_attack_state
        )

        self.time_before_death = enemy_stats.time_before_death
        self.attack_state = enemy_stats.attack_state
        self.attack_2_damage = enemy_stats.attack_2_damage
        self.attack_3_damage = enemy_stats.attack_3_damage
        self.attack_2_foreswing = enemy_stats.attack_2_foreswing
        self.attack_3_foreswing = enemy_stats.attack_3_foreswing
        self.attack_1_use_ability = enemy_stats.attack_1_use_ability
        self.attack_2_use_ability = enemy_stats.attack_2_use_ability
        self.attack_3_use_ability = enemy_stats.attack_3_use_ability
        self.spawn_anim_model_id = enemy_stats.spawn_anim_model_id
        self.soul_model_anim_id = enemy_stats.soul_model_anim_id
        self.has_entry_maanim = enemy_stats.has_entry_maanim
        self.has_death_maanim = enemy_stats.has_death_maanim
        self.warp_prob = enemy_stats.warp_prob
        self.warp_duration = enemy_stats.warp_duration
        self.warp_min_range = enemy_stats.warp_min_range
        self.warp_max_range = enemy_stats.warp_max_range
        self.warp_blocker = enemy_stats.warp_blocker
        self.dodge_prob = enemy_stats.dodge_prob
        self.dodge_duration = enemy_stats.dodge_duration
        self.surge_prob = enemy_stats.surge_prob
        self.surge_start = enemy_stats.surge_start
        self.surge_range = enemy_stats.surge_range
        self.surge_level = enemy_stats.surge_level
        self.surge_immunity = enemy_stats.surge_immunity
        self.curse_prob = enemy_stats.curse_prob
        self.curse_duration = enemy_stats.curse_duration
        self.wave_is_mini = enemy_stats.wave_is_mini
        self.attack_2_ld_flag = enemy_stats.attack_2_ld_flag
        self.attack_2_ld_start = enemy_stats.attack_2_ld_start
        self.attack_2_ld_range = enemy_stats.attack_2_ld_range
        self.attack_3_ld_flag = enemy_stats.attack_3_ld_flag
        self.attack_3_ld_start = enemy_stats.attack_3_ld_start
        self.unknown_108 = enemy_stats.unkown_102
        self.counter_surge = enemy_stats.counter_surge

        if target_all_effects:
            self.target_red = has_targeted_effect
            self.target_floating = has_targeted_effect
            self.target_black = has_targeted_effect
            self.target_metal = has_targeted_effect
            self.target_traitless = has_targeted_effect
            self.target_angel = has_targeted_effect
            self.target_alien = has_targeted_effect
            self.target_zombie = has_targeted_effect
            self.target_witch = has_targeted_effect
            self.target_eva = has_targeted_effect
            self.target_relic = has_targeted_effect
            self.target_aku = has_targeted_effect


@dataclass
class UnitBuy:
    stage_unlock: Optional[int] = None
    purchase_cost: Optional[int] = None
    upgrade_costs: Optional[list[int]] = None
    unlock_source: Optional[int] = None
    rarity: Optional[int] = None
    position_order: Optional[int] = None
    chapter_unlock: Optional[int] = None
    sell_price: Optional[int] = None
    gatya_rarity: Optional[int] = None
    original_max_base: Optional[int] = None
    original_max_plus: Optional[int] = None
    force_tf_level: Optional[int] = None
    second_form_unlock_level: Optional[int] = None
    unknown_22: Optional[int] = None
    tf_id: Optional[int] = None
    uf_id: Optional[int] = None
    evolve_level_tf: Optional[int] = None
    evolve_level_uf: Optional[int] = None
    evolve_cost_tf: Optional[int] = None
    evolve_items_tf: Optional[list[int]] = None
    evolve_cost_uf: Optional[int] = None
    evolve_items_uf: Optional[list[int]] = None
    max_base_no_catseye: Optional[int] = None
    max_base_catseye: Optional[int] = None
    max_plus: Optional[int] = None
    gatya_ofset_y_1st: Optional[int] = None
    gatya_ofset_y_2nd: Optional[int] = None
    gatya_ofset_y_3rd: Optional[int] = None
    gatya_ofset_y_4th: Optional[int] = None
    catseye_usage_pattern: Optional[int] = None
    game_version: Optional[int] = None
    np_sell_price: Optional[int] = None
    unknown_59: Optional[int] = None
    unknown_60: Optional[int] = None
    egg_val: Optional[int] = None
    egg_id: Optional[int] = None

    def get_evolve_items_tf(self) -> list[tuple[int, int]]:
        if self.evolve_items_tf is None:
            return []
        return [
            (self.evolve_items_tf[i], self.evolve_items_tf[i + 1])
            for i in range(0, len(self.evolve_items_tf), 2)
        ]

    def get_evolve_items_uf(self) -> list[tuple[int, int]]:
        if self.evolve_items_uf is None:
            return []
        return [
            (self.evolve_items_uf[i], self.evolve_items_uf[i + 1])
            for i in range(0, len(self.evolve_items_uf), 2)
        ]

    def set_evolve_items_tf(self, items: Sequence[tuple[int, int]]):
        self.evolve_items_tf = [item for pair in items for item in pair]

    def set_evolve_items_uf(self, items: Sequence[tuple[int, int]]):
        self.evolve_items_uf = [item for pair in items for item in pair]

    def __post_init__(self):
        self._csv__stage_unlock = IntCSVField(col_index=0)
        self._csv__purchase_cost = IntCSVField(col_index=1)
        self._csv__upgrade_costs = IntListCSVField(col_index=2, length=10)
        self._csv__unlock_source = IntCSVField(col_index=12)
        self._csv__rarity = IntCSVField(col_index=13)
        self._csv__position_order = IntCSVField(col_index=14)
        self._csv__chapter_unlock = IntCSVField(col_index=15)
        self._csv__sell_price = IntCSVField(col_index=16)
        self._csv__gatya_rarity = IntCSVField(col_index=17)
        self._csv__original_max_base = IntCSVField(col_index=18)
        self._csv__original_max_plus = IntCSVField(col_index=19)
        self._csv__force_tf_level = IntCSVField(col_index=20)
        self._csv__second_form_unlock_level = IntCSVField(col_index=21)
        self._csv__unknown_22 = IntCSVField(col_index=22)
        self._csv__tf_id = IntCSVField(col_index=23)
        self._csv__uf_id = IntCSVField(col_index=24)
        self._csv__evolve_level_tf = IntCSVField(col_index=25)
        self._csv__evolve_level_uf = IntCSVField(col_index=26)
        self._csv__evolve_cost_tf = IntCSVField(col_index=27)
        self._csv__evolve_items_tf = IntListCSVField(col_index=28, length=5 * 2)
        self._csv__evolve_cost_uf = IntCSVField(col_index=38)
        self._csv__evolve_items_uf = IntListCSVField(col_index=39, length=5 * 2)
        self._csv__max_base_no_catseye = IntCSVField(col_index=49)
        self._csv__max_base_catseye = IntCSVField(col_index=50)
        self._csv__max_plus = IntCSVField(col_index=51)
        self._csv__gatya_ofset_y_1st = IntCSVField(col_index=52)
        self._csv__gatya_ofset_y_2nd = IntCSVField(col_index=53)
        self._csv__gatya_ofset_y_3rd = IntCSVField(col_index=54)
        self._csv__gatya_ofset_y_4th = IntCSVField(col_index=55)
        self._csv__catseye_usage_pattern = IntCSVField(col_index=56)
        self._csv__game_version = IntCSVField(col_index=57)
        self._csv__np_sell_price = IntCSVField(col_index=58)
        self._csv__unknown_59 = IntCSVField(col_index=59)
        self._csv__unknown_60 = IntCSVField(col_index=60)
        self._csv__egg_val = IntCSVField(col_index=61)
        self._csv__egg_id = IntCSVField(col_index=62)

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.read_csv_fields(self, csv)

    def set_obtainable(self, obtainable: bool):
        if not obtainable:
            self.game_version = -1
        else:
            if self.game_version == -1:
                self.game_version = 0

    def is_obtainable(self) -> bool:
        return self.game_version != -1

    def set_max_level(
        self,
        max_base: int,
        max_plus: int,
        level_until_catsye_req: Optional[int] = None,
        original_base_max: Optional[int] = None,
        original_plus_max: Optional[int] = None,
    ):
        self.max_base_catseye = max_base
        self.max_plus = max_plus
        if level_until_catsye_req is not None:
            self.max_base_no_catseye = level_until_catsye_req
        if original_base_max is not None:
            self.original_max_base = original_base_max
        if original_plus_max is not None:
            self.original_max_plus = original_plus_max

    def reset_upgrade_costs(self):
        self.upgrade_costs = [0] * 10


@dataclass
class NyankoPictureBook:
    is_displayed_in_cat_guide: Optional[bool] = None
    limited: Optional[bool] = None
    total_forms: Optional[int] = None
    hint_display_type: Optional[int] = None
    scale_1st: Optional[int] = None
    scale_2nd: Optional[int] = None
    scale_3rd: Optional[int] = None
    scale_4th: Optional[int] = None

    def __post_init__(self):
        self._csv__is_displayed_in_cat_guide = BoolCSVField(col_index=0)
        self._csv__limited = BoolCSVField(col_index=1)
        self._csv__total_forms = IntCSVField(col_index=2)
        self._csv__hint_display_type = IntCSVField(col_index=3)
        self._csv__scale_1st = IntCSVField(col_index=4)
        self._csv__scale_2nd = IntCSVField(col_index=5)
        self._csv__scale_3rd = IntCSVField(col_index=6)
        self._csv__scale_4th = IntCSVField(col_index=7)

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class CatTalent:
    ability_id: Optional[int] = None
    max_level: Optional[int] = None
    min_1: Optional[int] = None
    max_1: Optional[int] = None
    min_2: Optional[int] = None
    max_2: Optional[int] = None
    min_3: Optional[int] = None
    max_3: Optional[int] = None
    min_4: Optional[int] = None
    max_4: Optional[int] = None
    text_id: Optional[int] = None
    np_cost_set: Optional[int] = None
    name_id: Optional[int] = None
    ultra: Optional[bool] = None

    def __post_init__(self):
        self._csv__ability_id = IntCSVField(col_index=2)
        self._csv__max_level = IntCSVField(col_index=3)
        self._csv__min_1 = IntCSVField(col_index=4)
        self._csv__max_1 = IntCSVField(col_index=5)
        self._csv__min_2 = IntCSVField(col_index=6)
        self._csv__max_2 = IntCSVField(col_index=7)
        self._csv__min_3 = IntCSVField(col_index=8)
        self._csv__max_3 = IntCSVField(col_index=9)
        self._csv__min_4 = IntCSVField(col_index=10)
        self._csv__max_4 = IntCSVField(col_index=11)
        self._csv__text_id = IntCSVField(col_index=12)
        self._csv__np_cost_set = IntCSVField(col_index=13)  # levelID
        self._csv__name_id = IntCSVField(col_index=14)
        self._csv__ultra = BoolCSVField(col_index=15)  # limit

    def apply_csv(self, index: int, field_offset: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(
            self, csv, remove_others=False, field_offset=field_offset
        )

    def read_csv(self, index: int, field_offset: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv, field_offset=field_offset)


@dataclass
class CatTalents:
    cat_id: Optional[int] = None
    type_id: Optional[int] = None
    talents: list[CatTalent] = field(default_factory=lambda: [])

    def __post_init__(self):
        self._csv__cat_id = IntCSVField(col_index=0)
        self._csv__type_id = IntCSVField(col_index=1)

    @staticmethod
    def find_index(cat_id: int, csv: "tbcml.CSV") -> Optional[int]:
        for _ in csv:
            try:
                if int(csv.get_str(0)) == cat_id:
                    return csv.index
            except (IndexError, ValueError):
                continue
        return None

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        self.cat_id = cat_id
        index = CatTalents.find_index(cat_id, csv) or len(csv.lines)
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)
        line_length = len(csv.lines[0])
        total_talents = (line_length - 2) // 14
        if total_talents < 0:
            return
        for i in range(total_talents):
            try:
                talent = self.talents[i]
            except IndexError:
                talent = CatTalent()
            talent.apply_csv(index, i * 14, csv)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV") -> bool:
        index = CatTalents.find_index(cat_id, csv)
        if index is None:
            return False
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)
        line_length = len(csv.lines[0])
        total_talents = (line_length - 2) // 14
        if total_talents < 0:
            return False
        self.talents = []
        for i in range(total_talents):
            talent = CatTalent()
            talent.read_csv(index, i * 14, csv)
            self.talents.append(talent)
        return True


@dataclass
class CatForm:
    """CatForm object
    Any mention of a form object in this documentation is an instance of the CatForm class
    Any mention of a cat object in this documentation is an instance of the Cat class

    Basic Usage:
        Basic, no inheritance method:
        ```
        form = CatForm(form_type=tbcml.CatFormType.FIRST)
        form.name = "Some cool name"
        ```

        Alternatively, if you want to encapsulate logic and data into your own class you can:
        ```
        class CoolCatForm(tbcml.CatForm):
            def __init__(self):
                super().__init__(form_type=tbcml.CatFormType.FIRST)

                self.name = "Some cool name"
        form = CoolCatForm()
        ```

        After creating the form object, it needs to be added to a cat:
        ```
        cat.set_form(form)
        ```
        where `cat` is a `Cat` instance

        If you want to do some modifications to the base form data, or just
        want to read the base game data for the form you can do the following:
        ```
        form = CatForm(form_type=tbcml.CatFormType.FIRST)
        form.read(game_data)
        print(form.name)
        form.name += " custom cat ending"
        ```
        or
        ```
        class CoolCatForm(tbcml.CatForm):
            def __init__(self, game_data: "tbcml.GamePacks"):
                super().__init__(form_type=tbcml.CatFormType.FIRST)
                self.read(game_data)

                print(self.name)
                self.name.value += " custom cat ending"
        ```
        where `game_data` is a `tbcml.GamePacks` instance, to create this, look at the `GamePacks` documention.

        Note that reading from game data will overwrite any previously set data.


    Attributes:
        For more documentation, see each field's definition separately lower down.

        form_type: (CatFormType), what form position the form should apply to:
        ```
        tbcml.CatFormType.FIRST
        tbcml.CatFormType.SECOND
        tbcml.CatFormType.THIRD
        tbcml.CatFormType.FOURTH
        ```

        name: (str), the name of the form
        description: (list[str]), the description of the form, list of 3 elements, one element for each line

        The following attributes will be `None` if they haven't been read from
        the game yet, and so if you want to get the object and create a new
        empty object if it is None, then you should use the getter functions:
        ```
        get_stats()
        get_anim()
        get_upgrade_icon()
        get_deploy_icon()

        # e.g
        form.get_stats().hp = 10
        ```

        stats: (FormStats, optional), the stats for the form, specifies stuff such as hp, movement speed, attack damage, etc
        anim: (CustomModel, optional), the animation of the unit
        upgrade_icon: (BCImage, optional), the icon you see in the upgrade screen for the cat
        deploy_icon: (BCImage, optional), the icon you see in, battle, the equip screen, and the cat guide
    """

    form_type: "tbcml.CatFormType" = field(metadata={"required": True})
    """What form position the form should apply to:
    ```
    tbcml.CatFormType.FIRST
    tbcml.CatFormType.SECOND
    tbcml.CatFormType.THIRD
    tbcml.CatFormType.FOURTH
    ```
    """
    name: Optional[str] = None
    """Name of the form"""

    description: Optional[list[str]] = None
    """Description of the form.
    
    It is a list of 3 elements, each element is a new line.
    """
    cat_guide_text: Optional[list[str]] = None
    """Text that specifies how to unlock the form

    It is a list of 3 elements, each element is a new line.
    """
    stats: Optional[FormStats] = None
    """Stats of the form.
    See `FormStats` for more documentation

    Usage:
    ```
    stats = form.get_stats()
    stats.hp = 1000
    """
    anim: Optional["tbcml.Model"] = None
    """Animation for the form
    See `tbcml.CustomModel` for more documentation.

    Usage:
    ```
    anim = form.get_anim()
    anim.flip_x()
    """

    def __post_init__(self):
        self._csv__name = StringCSVField(col_index=0)
        self._csv__description = StrListCSVField(col_index=1, length=3)

    upgrade_icon: Optional["tbcml.BCImage"] = None
    deploy_icon: Optional["tbcml.BCImage"] = None

    def sync(self, parent: "tbcml.Cat", form_type: "tbcml.CatFormType"):
        original_cat = parent.get_form(form_type)
        if original_cat is not None:
            original_cat = copy.deepcopy(original_cat)
            tbcml.Modification.sync(self, original_cat)

    def get_stats(self) -> "tbcml.FormStats":
        if self.stats is None:
            self.stats = tbcml.FormStats()
        return self.stats

    def get_anim(self) -> "tbcml.Model":
        if self.anim is None:
            self.anim = tbcml.Model()
        return self.anim

    def get_deploy_icon(self) -> "tbcml.BCImage":
        if self.deploy_icon is None:
            self.deploy_icon = tbcml.BCImage.from_size(128, 128)
        return self.deploy_icon

    def get_upgrade_icon(self) -> "tbcml.BCImage":
        if self.upgrade_icon is None:
            self.upgrade_icon = tbcml.BCImage.from_size(512, 128)
        return self.upgrade_icon

    def apply_game_data(self, cat_id: int, game_data: "tbcml.GamePacks"):
        name_file_name, name_csv = Cat.get_name_csv(game_data, cat_id)
        stats_file_name, stats_csv = Cat.get_stats_csv(game_data, cat_id)
        nypb_file_name, nypb_csv = Cat.get_cat_guide_text_csv(game_data)
        self.apply_csv(name_csv, stats_csv, nypb_csv, game_data, cat_id)
        game_data.set_csv(name_file_name, name_csv)
        game_data.set_csv(stats_file_name, stats_csv)
        game_data.set_csv(nypb_file_name, nypb_csv)

    def set_icons(self, cat_id: int, game_data: "tbcml.GamePacks"):
        game_data.set_img(self.get_upgrade_icon_file_name(cat_id), self.upgrade_icon)
        game_data.set_img(self.get_deploy_icon_file_name(cat_id), self.deploy_icon)

    def read_game_data(self, cat_id: int, game_data: "tbcml.GamePacks"):
        self.read_stats(cat_id, game_data)
        self.read_name_desc(cat_id, game_data)
        self.read_cat_guide_text(cat_id, game_data)
        self.read_anim(cat_id, game_data)
        self.read_icons(cat_id, game_data)

    def read_stats(self, cat_id: int, game_data: "tbcml.GamePacks"):
        _, stats_csv = Cat.get_stats_csv(game_data, cat_id)
        if stats_csv is None:
            return
        self.stats = FormStats()
        self.stats.read_csv(self.form_type, stats_csv)

    def read_name_desc(self, cat_id: int, game_data: "tbcml.GamePacks"):
        _, name_csv = Cat.get_name_csv(game_data, cat_id)
        if name_csv is None:
            return
        self.read_name_desc_csv(name_csv)

    def read_cat_guide_text(self, cat_id: int, game_data: "tbcml.GamePacks"):
        _, csv = Cat.get_cat_guide_text_csv(game_data)
        if csv is None:
            return
        self.read_cat_guide_text_csv(csv, cat_id)

    def get_upgrade_icon_file_name(self, cat_id: int):
        return f"udi{Cat.get_cat_id_str(cat_id)}_{self.form_type.value}.png"

    def get_deploy_icon_file_name(self, cat_id: int):
        return f"uni{Cat.get_cat_id_str(cat_id)}_{self.form_type.value}00.png"

    def get_sprite_file_name(self, cat_id: int):
        return f"{Cat.get_cat_id_str(cat_id)}_{self.form_type.value}.png"

    def get_imgcut_file_name(self, cat_id: int):
        return self.get_sprite_file_name(cat_id).replace(".png", ".imgcut")

    def get_mamodel_file_name(self, cat_id: int):
        return self.get_sprite_file_name(cat_id).replace(".png", ".mamodel")

    def get_maanim_file_name(self, cat_id: int, anim_type: "tbcml.AnimType"):
        anim_type_str = tbcml.PaddedInt(anim_type.value, 2).to_str()
        return self.get_sprite_file_name(cat_id).replace(
            ".png", f"{anim_type_str}.maanim"
        )

    def get_maanim_paths(self, cat_id: int) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in tbcml.AnimType:
            maanim_paths.append(self.get_maanim_file_name(cat_id, anim_type))
        cat_id_str = Cat.get_cat_id_str(cat_id)
        maanim_paths.append(f"{cat_id_str}_{self.form_type.value}_entry.maanim")
        maanim_paths.append(f"{cat_id_str}_{self.form_type.value}_soul.maanim")
        return maanim_paths

    def read_anim(self, cat_id: int, game_data: "tbcml.GamePacks"):
        self.anim = tbcml.Model()
        self.anim.read(
            game_data,
            self.get_sprite_file_name(cat_id),
            self.get_imgcut_file_name(cat_id),
            self.get_maanim_paths(cat_id),
            self.get_mamodel_file_name(cat_id),
        )

    def apply_csv(
        self,
        name_csv: Optional["tbcml.CSV"],
        stat_csv: Optional["tbcml.CSV"],
        cat_guide_text_csv: Optional["tbcml.CSV"],
        game_data: Optional["tbcml.GamePacks"],
        cat_id: Optional[int],
    ):
        if name_csv is not None:
            self.apply_name_desc(name_csv)
        if self.stats is not None and stat_csv is not None:
            self.stats.apply_csv(self.form_type, stat_csv)
        if cat_guide_text_csv is not None and cat_id is not None:
            self.apply_cat_guide_text_csv(cat_guide_text_csv, cat_id)
        if self.anim is not None and game_data is not None:
            self.anim.apply(game_data)
        if cat_id is not None and game_data is not None:
            self.set_icons(cat_id, game_data)

    def apply_name_desc(self, csv: "tbcml.CSV"):
        index = self.form_type.get_index()
        csv.index = index

        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_name_desc_csv(self, csv: "tbcml.CSV"):
        index = self.form_type.get_index()
        csv.index = index

        tbcml.Modification.read_csv_fields(self, csv)

    def read_cat_guide_text_csv(self, csv: "tbcml.CSV", cat_id: int):
        csv.index = cat_id

        row = self.form_type.get_index() * 3
        field = StrListCSVField(col_index=row, length=3, blank="＠")

        field.read_from_csv(csv)

    def apply_cat_guide_text_csv(self, csv: "tbcml.CSV", cat_id: int):
        csv.index = cat_id

        row = self.form_type.get_index() * 3
        field = StrListCSVField(col_index=row, length=3, blank="＠")
        field.set(self.cat_guide_text)

        field.write_to_csv(csv)

    def read_csv(
        self,
        name_csv: Optional["tbcml.CSV"],
        stat_csv: Optional["tbcml.CSV"],
        cat_guide_text_csv: Optional["tbcml.CSV"],
        cat_id: Optional[int],
        game_data: Optional["tbcml.GamePacks"],
        read_anim: bool = True,
    ):
        if name_csv is not None:
            self.read_name_desc_csv(name_csv)
        if stat_csv is not None:
            self.stats = FormStats()
            self.stats.read_csv(self.form_type, stat_csv)
        if cat_guide_text_csv is not None and cat_id is not None:
            self.read_cat_guide_text_csv(cat_guide_text_csv, cat_id)
        if game_data is not None and cat_id is not None:
            if read_anim:
                self.read_anim(cat_id, game_data)
            self.read_icons(cat_id, game_data)

    def read_icons(self, cat_id: int, game_data: "tbcml.GamePacks"):
        self.upgrade_icon = game_data.get_img(self.get_upgrade_icon_file_name(cat_id))
        self.deploy_icon = game_data.get_img(self.get_deploy_icon_file_name(cat_id))

    def pre_to_json(self):
        if self.deploy_icon is not None:
            self.deploy_icon.save_b64()
        if self.upgrade_icon is not None:
            self.upgrade_icon.save_b64()
        if self.anim is not None:
            self.anim.texture.save_b64()

    def get_deploy_border(self) -> "tbcml.BCImage":
        path = tbcml.Path.get_asset_file_path(f"uni_{self.form_type.value}.png")
        return tbcml.BCImage(path.read().to_base_64())

    def get_upgrade_bg(self) -> "tbcml.BCImage":
        path = tbcml.Path.get_asset_file_path(f"udi_{self.form_type.value}.png")
        return tbcml.BCImage(path.read().to_base_64())

    def import_enemy_deploy_icon(
        self,
        enemy_icon: "tbcml.BCImage",
        offset: tuple[int, int] = (-20, -20),
        scale: float = 2.5,
    ):
        enemy_icon.scale(scale)
        enemy_icon.convert_to_rgba()
        base_image = tbcml.BCImage.from_size(128, 128)
        base_image.paste(enemy_icon, offset[0], offset[1])
        base_image = base_image.crop_rect(
            14,
            26,
            113,
            101,
        )
        border_img = self.get_deploy_border()
        border_img.convert_to_rgba()
        border_img.paste(base_image, 14, 26)
        self.deploy_icon = border_img

    def import_enemy_upgrade_icon(
        self,
        enemy_icon: "tbcml.BCImage",
        offset: tuple[int, int] = (-140, -20),
        scale: float = 2.5,
    ):
        enemy_icon.scale(scale)
        enemy_icon.convert_to_rgba()

        base_image = tbcml.BCImage.from_size(512, 128)
        base_image.paste(enemy_icon, offset[0], offset[1])
        base_image = self.crop_upgrade_icon(base_image)

        bg_img = self.get_upgrade_bg()
        bg_img = CatForm.format_bcu_upgrade_icon_s(bg_img)
        bg_img.convert_to_rgba()
        bg_img.paste(base_image, 0, 0)
        self.upgrade_icon = bg_img

    def format_bcu_deploy_icon(self):
        deploy_icon = self.get_deploy_icon()
        if deploy_icon.width == 128 and deploy_icon.height == 128:
            return
        deploy_icon.convert_to_rgba()
        base_image = tbcml.BCImage.from_size(128, 128)
        base_image.paste(deploy_icon, 9, 21)
        self.deploy_icon = base_image

    def format_bcu_upgrade_icon(self):
        upgrade_icon = self.get_upgrade_icon()
        base_image = CatForm.format_bcu_upgrade_icon_s(upgrade_icon)
        self.upgrade_icon = base_image

    @staticmethod
    def format_bcu_upgrade_icon_s(upgrade_icon: "tbcml.BCImage"):
        if upgrade_icon.width == 85 and upgrade_icon.height == 32:
            upgrade_icon.scale(3.5)

        base_image = tbcml.BCImage.from_size(512, 128)
        base_image.paste(upgrade_icon, 13, 1)

        return CatForm.crop_upgrade_icon(base_image)

    @staticmethod
    def crop_upgrade_icon(img: "tbcml.BCImage") -> "tbcml.BCImage":
        start_pos = (146, 112)
        end_pos = (118, 70)
        start_offset = 0
        start_width = 311 - start_pos[0]
        for i in range(start_pos[1] - end_pos[1]):
            for j in range(start_width):
                img.putpixel(
                    start_pos[0] + j + start_offset, start_pos[1] - i, (0, 0, 0, 0)
                )
            start_offset += 1
            start_width -= 1

        img = img.crop_rect(13, 1, 307, 112)
        base_img = tbcml.BCImage.from_size(512, 128)
        base_img.paste(img, 13, 1)

        return base_img

    def import_enemy(
        self,
        cat_id: int,
        enemy: "tbcml.Enemy",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
        upgrade_icon_offset: tuple[int, int] = (-140, -20),
        upgrade_icon_scale: float = 2.5,
    ):
        if enemy.name is not None:
            self.name = enemy.name
        if enemy.description is not None:
            self.description = enemy.description[1:]
        if enemy.anim is not None:
            self.anim = enemy.anim.deepcopy()
            self.anim.flip_x()
            self.anim.set_unit_form(cat_id, self.form_type.value)
            self.anim.set_id(cat_id, self.form_type.value)
            self.anim.mamodel.dup_ints()

        if enemy.icon is not None:
            self.import_enemy_deploy_icon(
                enemy.icon, deploy_icon_offset, deploy_icon_scale
            )
            self.import_enemy_upgrade_icon(
                enemy.icon, upgrade_icon_offset, upgrade_icon_scale
            )

        if enemy.stats is not None:
            self.get_stats().import_enemy(enemy.stats)

    def set_id(self, cat_id: int, form_type: CatFormType):
        if self.anim is not None:
            self.anim.set_id(cat_id, form_type.value)
            self.anim.set_unit_form(cat_id, form_type.value)

    def import_enemy_from_id(
        self,
        cat_id: int,
        enemy_id: int,
        game_data: "tbcml.GamePacks",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
        upgrade_icon_offset: tuple[int, int] = (-140, -20),
        upgrade_icon_scale: float = 2.5,
    ) -> "tbcml.Enemy":
        enemy = tbcml.Enemy(enemy_id)
        enemy.read(game_data)
        self.import_enemy(
            cat_id,
            enemy,
            deploy_icon_offset,
            deploy_icon_scale,
            upgrade_icon_offset,
            upgrade_icon_scale,
        )
        return enemy

    def import_enemy_from_release_id(
        self,
        cat_id: int,
        enemy_release_id: int,
        game_data: "tbcml.GamePacks",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
        upgrade_icon_offset: tuple[int, int] = (-140, -20),
        upgrade_icon_scale: float = 2.5,
    ) -> "tbcml.Enemy":
        return self.import_enemy_from_id(
            cat_id,
            enemy_release_id - 2,
            game_data,
            deploy_icon_offset,
            deploy_icon_scale,
            upgrade_icon_offset,
            upgrade_icon_scale,
        )

    def set_cat_id(self, id: int):
        if self.anim is not None:
            self.anim.set_id(id, self.form_type.value)

    def set_form(self, form: Union[int, "tbcml.CatFormType"], cat_id: int):
        if isinstance(form, int):
            form = tbcml.CatFormType.from_index(form)

        self.form_type = form
        if self.anim is not None:
            self.anim.set_unit_form(cat_id, form.value)


@dataclass
class CatEvolveText:
    first_evol: Optional[list[str]] = None
    blank: Optional[str] = None
    second_evol: Optional[list[str]] = None
    comment: Optional[str] = None

    def __post_init__(self):
        self._csv__first_evol = StrListCSVField(
            col_index=0,
            length=3,
            blank="＠",
        )
        self._csv__blank = StringCSVField(col_index=3)
        self._csv__second_evol = StrListCSVField(
            col_index=4,
            length=3,
            blank="＠",
        )
        self._csv__comment = StringCSVField(col_index=7)

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class Cat(tbcml.Modification):
    cat_id: int = field(metadata={"required": True})
    forms: Optional[dict["tbcml.CatFormType", CatForm]] = None
    unitbuy: Optional[UnitBuy] = None
    nyanko_picture_book: Optional[NyankoPictureBook] = None
    evolve_text: Optional[CatEvolveText] = None
    talents: Optional[CatTalents] = None

    def get_form_create(self, form: Union[int, "tbcml.CatFormType"]):
        if isinstance(form, int):
            form = tbcml.CatFormType.from_index(form)

        if self.forms is None:
            self.forms = {}

        form_obj = self.forms.get(form)
        if form_obj is None:
            form_obj = CatForm(form)
            self.forms[form] = form_obj

        return form_obj

    def get_form(self, form: Union[int, "tbcml.CatFormType"]) -> Optional[CatForm]:
        if isinstance(form, int):
            form = tbcml.CatFormType.from_index(form)

        if self.forms is None:
            return None

        return self.forms.get(form)

    def get_talents(self) -> CatTalents:
        if self.talents is None:
            self.talents = CatTalents()
        return self.talents

    def get_evolve_text(self) -> CatEvolveText:
        if self.evolve_text is None:
            self.evolve_text = CatEvolveText()
        return self.evolve_text

    def get_unitbuy(self) -> "UnitBuy":
        if self.unitbuy is None:
            self.unitbuy = UnitBuy()
        return self.unitbuy

    def get_nyanko_picture_book(self) -> "NyankoPictureBook":
        if self.nyanko_picture_book is None:
            self.nyanko_picture_book = NyankoPictureBook()
        return self.nyanko_picture_book

    def apply(self, game_data: "tbcml.GamePacks"):
        self.apply_forms(game_data)

        name, csv = self.get_unit_buy_csv(game_data)
        self.apply_unit_buy(csv)
        game_data.set_csv(name, csv)

        name, csv = self.get_nyanko_picture_book_data_csv(game_data)
        self.apply_nyanko_picture_book(csv)
        game_data.set_csv(name, csv)

        name, csv = self.get_evolve_text_csv(game_data)
        self.apply_evolve_text(csv)
        game_data.set_csv(name, csv)

        name, csv = self.get_talents_csv(game_data)
        self.apply_talents(csv)
        game_data.set_csv(name, csv)

    def read(self, game_data: "tbcml.GamePacks", read_anim: bool = True):
        success = self.read_forms(game_data, read_anim)
        self.read_unit_buy(game_data)
        self.read_nyanko_picture_book(game_data)
        self.read_talents(game_data)
        return success

    @staticmethod
    def get_cat_id_str(cat_id: int) -> str:
        return tbcml.PaddedInt(cat_id, 3).to_str()

    @staticmethod
    def get_name_csv(
        game_data: "tbcml.GamePacks", cat_id: int
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name_desc = (
            f"Unit_Explanation{cat_id+1}_{game_data.localizable.get_lang()}.csv"
        )
        name_csv = game_data.get_csv(
            file_name_desc,
            country_code=game_data.country_code,
            remove_empty=False,
        )
        return file_name_desc, name_csv

    @staticmethod
    def get_cat_guide_text_csv(game_data: "tbcml.GamePacks"):
        file_name = f"nyankoPictureBook_{game_data.get_lang()}.csv"

        csv = game_data.get_csv(
            file_name, country_code=game_data.country_code, remove_empty=False
        )
        return file_name, csv

    @staticmethod
    def get_stats_csv(
        game_data: "tbcml.GamePacks", cat_id: int
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name_stat = f"unit{tbcml.PaddedInt(cat_id+1,3 )}.csv"
        stat_csv = game_data.get_csv(file_name_stat)

        return file_name_stat, stat_csv

    @staticmethod
    def get_unit_buy_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = "unitbuy.csv"
        csv = game_data.get_csv(file_name)

        return file_name, csv

    @staticmethod
    def get_total_cats(game_data: "tbcml.GamePacks") -> Optional[int]:
        csv = game_data.get_csv("unitbuy.csv")
        if csv is None:
            csv = game_data.get_csv(
                f"unitevolve_{game_data.localizable.get_lang()}.csv",
                remove_comments=False,
                remove_empty=False,
            )
        if csv is None:
            return None
        return len(csv.lines)

    @staticmethod
    def get_nyanko_picture_book_data_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = "nyankoPictureBookData.csv"
        csv = game_data.get_csv(file_name)

        return file_name, csv

    @staticmethod
    def get_evolve_text_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = f"unitevolve_{game_data.localizable.get_lang()}.csv"
        csv = game_data.get_csv(
            file_name,
            country_code=game_data.country_code,
            remove_comments=False,
            remove_empty=False,
        )

        return file_name, csv

    @staticmethod
    def get_talents_csv(
        game_data: "tbcml.GamePacks",
    ) -> tuple[str, Optional["tbcml.CSV"]]:
        file_name = f"SkillAcquisition.csv"
        csv = game_data.get_csv(file_name)

        return file_name, csv

    def apply_unit_buy(self, unit_buy_csv: Optional["tbcml.CSV"]):
        if self.unitbuy is not None and unit_buy_csv is not None:
            self.unitbuy.apply_csv(self.cat_id, unit_buy_csv)

    def apply_nyanko_picture_book(self, nyanko_picture_book_csv: Optional["tbcml.CSV"]):
        if self.nyanko_picture_book is not None and nyanko_picture_book_csv is not None:
            self.nyanko_picture_book.apply_csv(self.cat_id, nyanko_picture_book_csv)

    def apply_evolve_text(self, evolve_text_csv: Optional["tbcml.CSV"]):
        if self.evolve_text is not None and evolve_text_csv is not None:
            self.evolve_text.apply_csv(self.cat_id, evolve_text_csv)

    def apply_talents(self, talents_csv: Optional["tbcml.CSV"]):
        if self.talents is not None and talents_csv is not None:
            self.talents.apply_csv(self.cat_id, talents_csv)

    def apply_forms(self, game_data: "tbcml.GamePacks"):
        file_name_desc, name_csv = Cat.get_name_csv(game_data, self.cat_id)
        file_name_stat, stat_csv = Cat.get_stats_csv(game_data, self.cat_id)
        file_name_nypb, nypb_csv = Cat.get_cat_guide_text_csv(game_data)

        if self.forms:
            for form in self.forms.values():
                form.apply_csv(name_csv, stat_csv, nypb_csv, game_data, self.cat_id)

        game_data.set_csv(file_name_desc, name_csv)
        game_data.set_csv(file_name_stat, stat_csv)
        game_data.set_csv(file_name_nypb, nypb_csv)

    def read_unit_buy_csv(self, csv: Optional["tbcml.CSV"]):
        if csv is None:
            return
        self.get_unitbuy().read_csv(self.cat_id, csv)

    def read_nyanko_picture_book_csv(self, csv: Optional["tbcml.CSV"]):
        if csv is None:
            return
        self.get_nyanko_picture_book().read_csv(self.cat_id, csv)

    def read_evolve_text_csv(self, csv: Optional["tbcml.CSV"]):
        if csv is None:
            return
        self.get_evolve_text().read_csv(self.cat_id, csv)

    def read_talents_csv(self, csv: Optional["tbcml.CSV"]):
        if csv is None:
            return
        if not self.get_talents().read_csv(self.cat_id, csv):
            self.talents = None

    def read_unit_buy(self, game_data: "tbcml.GamePacks"):
        self.read_unit_buy_csv(self.get_unit_buy_csv(game_data)[1])

    def read_nyanko_picture_book(self, game_data: "tbcml.GamePacks"):
        self.read_nyanko_picture_book_csv(
            self.get_nyanko_picture_book_data_csv(game_data)[1]
        )

    def read_evolve_text(self, game_data: "tbcml.GamePacks"):
        self.read_evolve_text_csv(self.get_evolve_text_csv(game_data)[1])

    def read_talents(self, game_data: "tbcml.GamePacks"):
        self.read_talents_csv(self.get_talents_csv(game_data)[1])

    def read_forms(self, game_data: "tbcml.GamePacks", read_anim: bool = True) -> bool:
        _, name_csv = self.get_name_csv(game_data, self.cat_id)
        _, stat_csv = self.get_stats_csv(game_data, self.cat_id)
        _, nyanko_pic_book = self.get_cat_guide_text_csv(game_data)

        total_forms = None

        if stat_csv is not None:
            total_forms = len(stat_csv.lines)
        elif name_csv is not None:
            total_forms = len(name_csv.lines)

        if total_forms is None:
            return False

        self.forms = {}

        for form_index in range(total_forms):
            form_type = tbcml.CatFormType.from_index(form_index)
            self.forms[form_type] = CatForm(form_type)

        for form in self.forms.values():
            form.read_csv(
                name_csv, stat_csv, nyanko_pic_book, self.cat_id, game_data, read_anim
            )

        return True

    def set_form(self, form: CatForm, form_type: Optional["tbcml.CatFormType"] = None):
        if self.forms is None:
            self.forms = {}

        if form_type is not None:
            form.form_type = form_type

        if form_type is None:
            form_type = form.form_type

        self.forms[form_type] = form

        self.set_cat_id_form(self.cat_id, form_type)

    def set_cat_id_form(self, cat_id: int, form_type: "tbcml.CatFormType"):
        if self.forms is not None:
            form = self.forms.get(form_type)
            if form is not None:
                form.set_id(cat_id, form_type)

    def pre_to_json(self):
        for form in (self.forms or {}).values():
            form.pre_to_json()

    def get_custom_html(self) -> str:
        names = [str(form.name) for form in (self.forms or {}).values()]
        name_str = ", ".join(names)
        return f'<span style="color:#000">{name_str} (cat id: {self.cat_id})</span>'

    def set_cat_id(self, id: int):
        self.cat_id = id
        if self.forms is not None:
            for form in self.forms.values():
                form.set_cat_id(id)

    def import_from_bcu(self, bcu_zip: "tbcml.BCUZip", bcu_id: int) -> bool:
        bcu_cat = bcu_zip.get_bcu_cat(self.cat_id, bcu_id)
        if bcu_cat is None:
            return False

        bcu_cat.write_to_cat(self)
        return True

    def add_ultra_form_catfruit_evol(
        self,
        form: Optional[CatForm],
        evolve_items: Sequence[tuple[int, int]],
        evolve_id: int = 25000,
        evolve_cost: int = 100000,
        evolve_level: int = 40,
        evolve_text: Optional[list[str]] = None,
        cat_guide_text: Optional[list[str]] = None,
    ):
        if form is not None:
            self.set_form(form, CatFormType.FOURTH)
            form.cat_guide_text = cat_guide_text

        unitbuy = self.get_unitbuy()
        unitbuy.set_evolve_items_uf(evolve_items)
        unitbuy.uf_id = evolve_id
        unitbuy.evolve_cost_uf = evolve_cost
        unitbuy.evolve_level_uf = evolve_level

        evolve_text = evolve_text or ["", "", ""]
        self.get_evolve_text().second_evol = evolve_text

        nyanko_picture_book = self.get_nyanko_picture_book()
        nyanko_picture_book.total_forms = 4
        nyanko_picture_book.scale_4th = 100

    def add_true_form_catfruit_evol(
        self,
        form: Optional[CatForm],
        evolve_items: list[tuple[int, int]],
        evolve_id: int = 15000,
        evolve_cost: int = 100000,
        evolve_level: int = 30,
        evolve_text: Optional[list[str]] = None,
        cat_guide_text: Optional[list[str]] = None,
    ):
        if form is not None:
            self.set_form(form, CatFormType.THIRD)
            form.cat_guide_text = cat_guide_text
        unitbuy = self.get_unitbuy()
        unitbuy.set_evolve_items_tf(evolve_items)
        unitbuy.tf_id = evolve_id
        unitbuy.evolve_cost_tf = evolve_cost
        unitbuy.evolve_level_tf = evolve_level

        evolve_text = evolve_text or ["", "", ""]
        self.get_evolve_text().first_evol = evolve_text

        nyanko_picture_book = self.get_nyanko_picture_book()
        nyanko_picture_book.total_forms = 3
        nyanko_picture_book.scale_3rd = 100
