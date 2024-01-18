import enum
from typing import Optional, Union
from dataclasses import field
import tbcml

from tbcml.io.csv_fields import (
    IntCSVField,
    CSVField,
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

    hp: IntCSVField = CSVField.to_field(IntCSVField, 0)
    kbs: IntCSVField = CSVField.to_field(IntCSVField, 1)
    speed: IntCSVField = CSVField.to_field(IntCSVField, 2)
    attack_1_damage: IntCSVField = CSVField.to_field(IntCSVField, 3)
    attack_interval: IntCSVField = CSVField.to_field(IntCSVField, 4)
    attack_range: IntCSVField = CSVField.to_field(IntCSVField, 5)
    cost: IntCSVField = CSVField.to_field(IntCSVField, 6)
    recharge_time: IntCSVField = CSVField.to_field(IntCSVField, 7)
    collision_start: IntCSVField = CSVField.to_field(IntCSVField, 8)
    collision_width: IntCSVField = CSVField.to_field(IntCSVField, 9)
    target_red: BoolCSVField = CSVField.to_field(BoolCSVField, 10)
    unused: IntCSVField = CSVField.to_field(IntCSVField, 11)
    area_attack: BoolCSVField = CSVField.to_field(BoolCSVField, 12)
    attack_1_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 13)
    min_z_layer: IntCSVField = CSVField.to_field(IntCSVField, 14)
    max_z_layer: IntCSVField = CSVField.to_field(IntCSVField, 15)
    target_floating: BoolCSVField = CSVField.to_field(BoolCSVField, 16)
    target_black: BoolCSVField = CSVField.to_field(BoolCSVField, 17)
    target_metal: BoolCSVField = CSVField.to_field(BoolCSVField, 18)
    target_traitless: BoolCSVField = CSVField.to_field(BoolCSVField, 19)
    target_angel: BoolCSVField = CSVField.to_field(BoolCSVField, 20)
    target_alien: BoolCSVField = CSVField.to_field(BoolCSVField, 21)
    target_zombie: BoolCSVField = CSVField.to_field(BoolCSVField, 22)
    strong: BoolCSVField = CSVField.to_field(BoolCSVField, 23)
    knockback_prob: IntCSVField = CSVField.to_field(IntCSVField, 24)
    freeze_prob: IntCSVField = CSVField.to_field(IntCSVField, 25)
    freeze_duration: IntCSVField = CSVField.to_field(IntCSVField, 26)
    slow_prob: IntCSVField = CSVField.to_field(IntCSVField, 27)
    slow_duration: IntCSVField = CSVField.to_field(IntCSVField, 28)
    resistant: BoolCSVField = CSVField.to_field(BoolCSVField, 29)
    massive_damage: BoolCSVField = CSVField.to_field(BoolCSVField, 30)
    crit_prob: IntCSVField = CSVField.to_field(IntCSVField, 31)
    attacks_only: BoolCSVField = CSVField.to_field(BoolCSVField, 32)
    extra_money: BoolCSVField = CSVField.to_field(BoolCSVField, 33)
    base_destroyer: BoolCSVField = CSVField.to_field(BoolCSVField, 34)
    wave_prob: IntCSVField = CSVField.to_field(IntCSVField, 35)
    wave_level: IntCSVField = CSVField.to_field(IntCSVField, 36)
    weaken_prob: IntCSVField = CSVField.to_field(IntCSVField, 37)
    weaken_duration: IntCSVField = CSVField.to_field(IntCSVField, 38)
    weaken_percentage: IntCSVField = CSVField.to_field(IntCSVField, 39)
    strengthen_hp_start_percentage: IntCSVField = CSVField.to_field(IntCSVField, 40)
    strengthen_hp_boost_percentage: IntCSVField = CSVField.to_field(IntCSVField, 41)
    lethal_strike_prob: IntCSVField = CSVField.to_field(IntCSVField, 42)
    is_metal: BoolCSVField = CSVField.to_field(BoolCSVField, 43)
    attack_1_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 44)
    attack_1_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 45)
    wave_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 46)
    wave_blocker: BoolCSVField = CSVField.to_field(BoolCSVField, 47)
    knockback_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 48)
    freeze_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 49)
    slow_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 50)
    weaken_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 51)
    zombie_killer: BoolCSVField = CSVField.to_field(BoolCSVField, 52)
    witch_killer: BoolCSVField = CSVField.to_field(BoolCSVField, 53)
    target_witch: BoolCSVField = CSVField.to_field(BoolCSVField, 54)
    attacks_before_set_attack_state: IntCSVField = CSVField.to_field(IntCSVField, 55)
    shockwave_immune: BoolCSVField = CSVField.to_field(BoolCSVField, 56)
    time_before_death: IntCSVField = CSVField.to_field(IntCSVField, 57)
    attack_state: IntCSVField = CSVField.to_field(IntCSVField, 58)
    attack_2_damage: IntCSVField = CSVField.to_field(IntCSVField, 59)
    attack_3_damange: IntCSVField = CSVField.to_field(IntCSVField, 60)
    attack_2_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 61)
    attack_3_foreswing: IntCSVField = CSVField.to_field(IntCSVField, 62)
    attack_1_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 63)
    attack_2_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 64)
    attack_3_use_ability: BoolCSVField = CSVField.to_field(BoolCSVField, 65)
    spawn_anim_model_id: IntCSVField = CSVField.to_field(IntCSVField, 66)
    soul_model_anim_id: IntCSVField = CSVField.to_field(IntCSVField, 67)
    has_entry_maanim: BoolCSVField = CSVField.to_field(BoolCSVField, 68)
    has_death_maanim: BoolCSVField = CSVField.to_field(BoolCSVField, 69)
    barrier_break_prob: IntCSVField = CSVField.to_field(IntCSVField, 70)
    warp_prob: IntCSVField = CSVField.to_field(IntCSVField, 71)
    warp_duration: IntCSVField = CSVField.to_field(IntCSVField, 72)
    warp_min_range: IntCSVField = CSVField.to_field(IntCSVField, 73)
    warp_max_range: IntCSVField = CSVField.to_field(IntCSVField, 74)
    warp_blocker: BoolCSVField = CSVField.to_field(BoolCSVField, 75)
    target_eva: BoolCSVField = CSVField.to_field(BoolCSVField, 76)
    eva_killer: BoolCSVField = CSVField.to_field(BoolCSVField, 77)
    target_relic: BoolCSVField = CSVField.to_field(BoolCSVField, 78)
    curse_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 79)
    insanely_tough: BoolCSVField = CSVField.to_field(BoolCSVField, 80)
    insane_damage: BoolCSVField = CSVField.to_field(BoolCSVField, 81)
    savage_blow_prob: IntCSVField = CSVField.to_field(IntCSVField, 82)
    savage_blow_damage_addition: IntCSVField = CSVField.to_field(IntCSVField, 83)
    dodge_prob: IntCSVField = CSVField.to_field(IntCSVField, 84)
    dodge_duration: IntCSVField = CSVField.to_field(IntCSVField, 85)
    surge_prob: IntCSVField = CSVField.to_field(IntCSVField, 86)
    surge_start: IntCSVField = CSVField.to_field(IntCSVField, 87)
    surge_range: IntCSVField = CSVField.to_field(IntCSVField, 88)
    surge_level: IntCSVField = CSVField.to_field(IntCSVField, 89)
    toxic_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 90)
    surge_immunity: BoolCSVField = CSVField.to_field(BoolCSVField, 91)
    curse_prob: IntCSVField = CSVField.to_field(IntCSVField, 92)
    curse_duration: IntCSVField = CSVField.to_field(IntCSVField, 93)
    wave_is_mini: BoolCSVField = CSVField.to_field(BoolCSVField, 94)
    shield_pierce_prob: IntCSVField = CSVField.to_field(IntCSVField, 95)
    target_aku: BoolCSVField = CSVField.to_field(BoolCSVField, 96)
    collossus_slayer: BoolCSVField = CSVField.to_field(BoolCSVField, 97)
    soul_strike: BoolCSVField = CSVField.to_field(BoolCSVField, 98)
    attack_2_ld_flag: BoolCSVField = CSVField.to_field(BoolCSVField, 99)
    attack_2_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 100)
    attack_2_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 101)
    attack_3_ld_flag: BoolCSVField = CSVField.to_field(BoolCSVField, 102)
    attack_3_ld_start: IntCSVField = CSVField.to_field(IntCSVField, 103)
    attack_3_ld_range: IntCSVField = CSVField.to_field(IntCSVField, 104)
    behemoth_slayer: BoolCSVField = CSVField.to_field(BoolCSVField, 105)
    behemoth_dodge_prob: IntCSVField = CSVField.to_field(IntCSVField, 106)
    behemoth_dodge_duration: IntCSVField = CSVField.to_field(IntCSVField, 107)
    unknown_108: IntCSVField = CSVField.to_field(IntCSVField, 108)
    counter_surge: BoolCSVField = CSVField.to_field(BoolCSVField, 109)

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
        ]

        return required

    def read_csv(self, form_type: "CatFormType", csv: "tbcml.CSV"):
        index = form_type.get_index()
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv, self.get_required())

    def import_enemy(
        self, enemy_stats: "tbcml.EnemyStats", target_all_effects: bool = True
    ):
        if target_all_effects:
            has_targeted_effect = enemy_stats.has_targeted_effect()
        else:
            has_targeted_effect = None
        self.hp.set(enemy_stats.hp.get())
        self.kbs.set(enemy_stats.kbs.get())
        self.speed.set(enemy_stats.speed.get())
        self.attack_1_damage.set(enemy_stats.attack_1_damage.get())
        self.attack_interval.set(enemy_stats.attack_interval.get())
        self.attack_range.set(enemy_stats.attack_range.get())
        self.collision_start.set(enemy_stats.collision_start.get())
        self.collision_width.set(enemy_stats.collision_width.get())
        self.collision_width.set(enemy_stats.collision_width.get())
        self.unused.set(enemy_stats.unused.get())
        self.area_attack.set(enemy_stats.area_attack.get())
        self.attack_1_foreswing.set(enemy_stats.attack_1_foreswing.get())
        self.knockback_prob.set(enemy_stats.knockback_prob.get())
        self.freeze_prob.set(enemy_stats.freeze_prob.get())
        self.freeze_duration.set(enemy_stats.freeze_duration.get())
        self.slow_prob.set(enemy_stats.slow_prob.get())
        self.slow_duration.set(enemy_stats.slow_duration.get())
        self.crit_prob.set(enemy_stats.crit_prob.get())
        self.wave_prob.set(enemy_stats.wave_prob.get())
        self.wave_level.set(enemy_stats.wave_level.get())
        self.weaken_prob.set(enemy_stats.weaken_prob.get())
        self.weaken_duration.set(enemy_stats.weaken_duration.get())
        self.weaken_percentage.set(enemy_stats.weaken_percentage.get())
        self.strengthen_hp_start_percentage.set(
            enemy_stats.strengthen_hp_start_percentage.get()
        )
        self.strengthen_hp_boost_percentage.set(
            enemy_stats.strengthen_hp_boost_percentage.get()
        )
        self.is_metal.set(enemy_stats.metal.get())
        self.attack_1_ld_start.set(enemy_stats.attack_1_ld_start.get())
        self.attack_1_ld_range.set(enemy_stats.attack_1_ld_range.get())
        self.wave_immunity.set(enemy_stats.wave_immunity.get())
        self.wave_blocker.set(enemy_stats.wave_blocker.get())
        self.knockback_immunity.set(enemy_stats.knockback_immunity.get())
        self.freeze_immunity.set(enemy_stats.freeze_immunity.get())
        self.slow_immunity.set(enemy_stats.slow_immunity.get())
        self.weaken_immunity.set(enemy_stats.weaken_immunity.get())
        self.attacks_before_set_attack_state.set(
            enemy_stats.attacks_before_set_attack_state.get()
        )
        self.time_before_death.set(enemy_stats.time_before_death.get())
        self.attack_state.set(enemy_stats.attack_state.get())
        self.attack_2_damage.set(enemy_stats.attack_2_damage.get())
        self.attack_3_damange.set(enemy_stats.attack_3_damange.get())
        self.attack_2_foreswing.set(enemy_stats.attack_2_foreswing.get())
        self.attack_3_foreswing.set(enemy_stats.attack_3_foreswing.get())
        self.attack_1_use_ability.set(enemy_stats.attack_1_use_ability.get())
        self.attack_2_use_ability.set(enemy_stats.attack_2_use_ability.get())
        self.attack_3_use_ability.set(enemy_stats.attack_3_use_ability.get())
        self.spawn_anim_model_id.set(enemy_stats.spawn_anim_model_id.get())
        self.soul_model_anim_id.set(enemy_stats.soul_model_anim_id.get())
        self.has_entry_maanim.set(enemy_stats.has_entry_maanim.get())
        self.has_death_maanim.set(enemy_stats.has_death_maanim.get())
        self.warp_prob.set(enemy_stats.warp_prob.get())
        self.warp_duration.set(enemy_stats.warp_duration.get())
        self.warp_min_range.set(enemy_stats.warp_min_range.get())
        self.warp_max_range.set(enemy_stats.warp_max_range.get())
        self.warp_blocker.set(enemy_stats.warp_blocker.get())
        self.dodge_prob.set(enemy_stats.dodge_prob.get())
        self.dodge_duration.set(enemy_stats.dodge_duration.get())
        self.surge_prob.set(enemy_stats.surge_prob.get())
        self.surge_start.set(enemy_stats.surge_start.get())
        self.surge_range.set(enemy_stats.surge_range.get())
        self.surge_level.set(enemy_stats.surge_level.get())
        self.surge_immunity.set(enemy_stats.surge_immunity.get())
        self.curse_prob.set(enemy_stats.curse_prob.get())
        self.curse_duration.set(enemy_stats.curse_duration.get())
        self.wave_is_mini.set(enemy_stats.wave_is_mini.get())
        self.attack_2_ld_flag.set(enemy_stats.attack_2_ld_flag.get())
        self.attack_2_ld_start.set(enemy_stats.attack_2_ld_start.get())
        self.attack_2_ld_range.set(enemy_stats.attack_2_ld_range.get())
        self.attack_3_ld_flag.set(enemy_stats.attack_3_ld_flag.get())
        self.attack_3_ld_start.set(enemy_stats.attack_3_ld_start.get())
        self.unknown_108.set(enemy_stats.unkown_102.get())
        self.counter_surge.set(enemy_stats.counter_surge.get())

        self.target_red.set_ignore_none(has_targeted_effect)
        self.target_floating.set_ignore_none(has_targeted_effect)
        self.target_black.set_ignore_none(has_targeted_effect)
        self.target_metal.set_ignore_none(has_targeted_effect)
        self.target_traitless.set_ignore_none(has_targeted_effect)
        self.target_angel.set_ignore_none(has_targeted_effect)
        self.target_alien.set_ignore_none(has_targeted_effect)
        self.target_zombie.set_ignore_none(has_targeted_effect)
        self.target_witch.set_ignore_none(has_targeted_effect)
        self.target_eva.set_ignore_none(has_targeted_effect)
        self.target_relic.set_ignore_none(has_targeted_effect)
        self.target_aku.set_ignore_none(has_targeted_effect)


@dataclass
class UnitBuy:
    stage_unlock: IntCSVField = CSVField.to_field(IntCSVField, 0)
    purchase_cost: IntCSVField = CSVField.to_field(IntCSVField, 1)
    upgrade_costs: IntListCSVField = CSVField.to_field(IntListCSVField, 2, length=10)
    unlock_source: IntCSVField = CSVField.to_field(IntCSVField, 12)
    rarity: IntCSVField = CSVField.to_field(IntCSVField, 13)
    position_order: IntCSVField = CSVField.to_field(IntCSVField, 14)
    chapter_unlock: IntCSVField = CSVField.to_field(IntCSVField, 15)
    sell_price: IntCSVField = CSVField.to_field(IntCSVField, 16)
    gatya_rarity: IntCSVField = CSVField.to_field(IntCSVField, 17)
    original_max_base: IntCSVField = CSVField.to_field(IntCSVField, 18)
    original_max_plus: IntCSVField = CSVField.to_field(IntCSVField, 19)
    force_tf_level: IntCSVField = CSVField.to_field(IntCSVField, 20)
    second_form_unlock_level: IntCSVField = CSVField.to_field(IntCSVField, 21)
    unknown_22: IntCSVField = CSVField.to_field(IntCSVField, 22)
    tf_id: IntCSVField = CSVField.to_field(IntCSVField, 23)
    uf_id: IntCSVField = CSVField.to_field(IntCSVField, 24)
    evolve_level_tf: IntCSVField = CSVField.to_field(IntCSVField, 25)
    evolve_level_uf: IntCSVField = CSVField.to_field(IntCSVField, 26)
    evolve_cost_tf: IntCSVField = CSVField.to_field(IntCSVField, 27)
    evolve_items_tf: IntListCSVField = CSVField.to_field(
        IntListCSVField, 28, length=5 * 2
    )
    evolve_cost_ff: IntCSVField = CSVField.to_field(IntCSVField, 38)
    evolve_items_uf: IntListCSVField = CSVField.to_field(
        IntListCSVField, 39, length=5 * 2
    )
    max_base_no_catseye: IntCSVField = CSVField.to_field(IntCSVField, 49)
    max_base_catseye: IntCSVField = CSVField.to_field(IntCSVField, 50)
    max_plus: IntCSVField = CSVField.to_field(IntCSVField, 51)
    gatya_ofset_y_1st: IntCSVField = CSVField.to_field(IntCSVField, 52)
    gatya_ofset_y_2nd: IntCSVField = CSVField.to_field(IntCSVField, 53)
    gatya_ofset_y_3rd: IntCSVField = CSVField.to_field(IntCSVField, 54)
    gatya_ofset_y_4th: IntCSVField = CSVField.to_field(IntCSVField, 55)
    catseye_usage_pattern: IntCSVField = CSVField.to_field(IntCSVField, 56)
    game_version: IntCSVField = CSVField.to_field(IntCSVField, 57)
    np_sell_price: IntCSVField = CSVField.to_field(IntCSVField, 58)
    unknown_59: IntCSVField = CSVField.to_field(IntCSVField, 59)
    unknown_60: IntCSVField = CSVField.to_field(IntCSVField, 60)
    egg_val: IntCSVField = CSVField.to_field(IntCSVField, 61)
    egg_id: IntCSVField = CSVField.to_field(IntCSVField, 62)

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.read_csv_fields(self, csv)

    def set_obtainable(self, obtainable: bool):
        if not obtainable:
            self.game_version.set(-1)
        else:
            self.game_version.set(
                0 if self.game_version.get() == -1 else self.game_version.get()
            )

    def is_obtainable(self) -> bool:
        return self.game_version.get() != -1

    def set_max_level(
        self,
        max_base: int,
        max_plus: int,
        level_until_catsye_req: Optional[int] = None,
        original_base_max: Optional[int] = None,
        original_plus_max: Optional[int] = None,
    ):
        self.max_base_catseye.set(max_base)
        self.max_plus.set(max_plus)
        if level_until_catsye_req is not None:
            self.max_base_no_catseye.set(level_until_catsye_req)
        if original_base_max is not None:
            self.original_max_base.set(original_base_max)
        if original_plus_max is not None:
            self.original_max_plus.set(original_plus_max)

    def reset_upgrade_costs(self):
        for i in range(len(self.upgrade_costs.get())):
            self.upgrade_costs.set_element(0, i)


@dataclass
class NyankoPictureBook:
    is_displayed_in_cat_guide: BoolCSVField = CSVField.to_field(BoolCSVField, 0)
    limited: BoolCSVField = CSVField.to_field(BoolCSVField, 1)
    total_forms: IntCSVField = CSVField.to_field(IntCSVField, 2)
    hint_display_type: IntCSVField = CSVField.to_field(IntCSVField, 3)
    scale_1st: IntCSVField = CSVField.to_field(IntCSVField, 4)
    scale_2nd: IntCSVField = CSVField.to_field(IntCSVField, 5)
    scale_3rd: IntCSVField = CSVField.to_field(IntCSVField, 6)
    scale_4th: IntCSVField = CSVField.to_field(IntCSVField, 7)

    def apply_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "tbcml.CSV"):
        csv.index = cat_id
        tbcml.Modification.read_csv_fields(self, csv)


@dataclass
class CatTalent:
    ability_id: IntCSVField = CSVField.to_field(IntCSVField, 2)
    max_level: IntCSVField = CSVField.to_field(IntCSVField, 3)
    min_1: IntCSVField = CSVField.to_field(IntCSVField, 4)
    max_1: IntCSVField = CSVField.to_field(IntCSVField, 5)
    min_2: IntCSVField = CSVField.to_field(IntCSVField, 6)
    max_2: IntCSVField = CSVField.to_field(IntCSVField, 7)
    min_3: IntCSVField = CSVField.to_field(IntCSVField, 8)
    max_3: IntCSVField = CSVField.to_field(IntCSVField, 9)
    min_4: IntCSVField = CSVField.to_field(IntCSVField, 10)
    max_4: IntCSVField = CSVField.to_field(IntCSVField, 11)
    text_id: IntCSVField = CSVField.to_field(IntCSVField, 12)
    np_cost_set: IntCSVField = CSVField.to_field(IntCSVField, 13)  # levelID
    name_id: IntCSVField = CSVField.to_field(IntCSVField, 14)
    ultra: BoolCSVField = CSVField.to_field(BoolCSVField, 15)  # limit

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
    cat_id: IntCSVField = CSVField.to_field(IntCSVField, 0)
    type_id: IntCSVField = CSVField.to_field(IntCSVField, 1)
    talents: list[CatTalent] = field(default_factory=lambda: [])

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
        self.cat_id.set(cat_id)
        index = CatTalents.find_index(cat_id, csv) or len(csv.lines)
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv, remove_others=False)
        line_length = len(csv.get_current_line() or [])
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
        line_length = len(csv.get_current_line() or [])
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
        form.name.set("Some cool name")
        ```

        Alternatively, if you want to encapsulate logic and data into your own class you can:
        ```
        class CoolCatForm(tbcml.CatForm):
            def __init__(self):
                super().__init__(form_type=tbcml.CatFormType.FIRST)

                self.name.set("Some cool name")
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
        print(form.name.get())
        form.name.value_ += " custom cat ending"
        ```
        or
        ```
        class CoolCatForm(tbcml.CatForm):
            def __init__(self, game_data: "tbcml.GamePacks"):
                super().__init__(form_type=tbcml.CatFormType.FIRST)
                self.read(game_data)

                print(self.name.get())
                self.name.value_ += " custom cat ending"
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

        The following attributes should not be created when initializing the object
        and instead should be set with `.set(value)` and retrieved with
        `.get()`, e.g `form.name.set("test")` where `form` is a CatForm object

        name: (StringCSVField), the name of the form
        description: (StrListCSVField), the description of the form, list of 3 elements, one element for each line

        The following attributes can be accessed directly like normal, but they
        will be `None` if they haven't been read from the game yet, and so if you want
        to get the object and create a new empty object if it is None, then you
        should use the getter functions:
        ```
        get_stats()
        get_anim()
        get_upgrade_icon()
        get_deploy_icon()

        # e.g
        form.get_stats().hp.set(10)
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
    name: StringCSVField = CSVField.to_field(StringCSVField, 0)
    """Name of the form

    Usage:
    ```
    # getting
    name = form.name.get()

    # setting
    form.name.set("Cool Custom Cat")
    ```
    """
    description: StrListCSVField = CSVField.to_field(StrListCSVField, 1, length=3)
    """Description of the form.
    
    It is a list of 3 elements, each element is a new line.

    Usage:
    ```
    # getting
    description = form.description.get()
    line_1 = description[0]

    # setting
    form.description.set(["line 1", "line 2", "line 3"])
    ```
    """
    stats: Optional[FormStats] = None
    """Stats of the form.
    
    See `FormStats` for more documentation

    Usage:
    ```
    # getting
    stats = form.stats  # may be None if not loaded from game data or already defined
    hp = stats.hp.get()  # may error if stats is None

    stats = form.get_stats()  # will not be None as if it is None, it will create a new FormStats object
    hp = stats.hp.get()  # will not error

    # setting
    stats.hp.set(10)  # should get stats object as above
    """
    anim: Optional["tbcml.Model"] = None
    """Animation for the form

    See `tbcml.CustomModel` for more documentation.
    See `stats` field for difference between `form.anim` and `form.get_anim()`

    Usage:
    ```
    anim = form.anim
    anim = form.get_anim()
    anim.flip_x()
    """
    upgrade_icon: Optional["tbcml.BCImage"] = None
    deploy_icon: Optional["tbcml.BCImage"] = None

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
        self.apply_csv(name_csv, stats_csv, game_data, cat_id)
        game_data.set_csv(name_file_name, name_csv)
        game_data.set_csv(stats_file_name, stats_csv)

    def set_icons(self, cat_id: int, game_data: "tbcml.GamePacks"):
        game_data.set_img(self.get_upgrade_icon_file_name(cat_id), self.upgrade_icon)
        game_data.set_img(self.get_deploy_icon_file_name(cat_id), self.deploy_icon)

    def read_game_data(self, cat_id: int, game_data: "tbcml.GamePacks"):
        self.read_stats(cat_id, game_data)
        self.read_name_desc(cat_id, game_data)
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
        game_data: Optional["tbcml.GamePacks"],
        cat_id: Optional[int],
    ):
        if name_csv is not None:
            self.apply_name_desc(name_csv)
        if self.stats is not None and stat_csv is not None:
            self.stats.apply_csv(self.form_type, stat_csv)
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

    def read_csv(
        self,
        name_csv: Optional["tbcml.CSV"],
        stat_csv: Optional["tbcml.CSV"],
        cat_id: Optional[int],
        game_data: Optional["tbcml.GamePacks"],
    ):
        if name_csv is not None:
            self.read_name_desc_csv(name_csv)
        if stat_csv is not None:
            self.stats = FormStats()
            self.stats.read_csv(self.form_type, stat_csv)
        if game_data is not None and cat_id is not None:
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
        if upgrade_icon.width == 85 and upgrade_icon.height == 32:
            upgrade_icon.scale(3.5)

        base_image = tbcml.BCImage.from_size(512, 128)
        base_image.paste(upgrade_icon, 13, 1)

        start_pos = (146, 112)
        end_pos = (118, 70)
        start_offset = 0
        start_width = 311 - start_pos[0]
        for i in range(start_pos[1] - end_pos[1]):
            for j in range(start_width):
                base_image.putpixel(
                    start_pos[0] + j + start_offset, start_pos[1] - i, (0, 0, 0, 0)
                )
            start_offset += 1
            start_width -= 1
        self.upgrade_icon = base_image

    def import_enemy(
        self,
        cat_id: int,
        enemy: "tbcml.Enemy",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
    ):
        self.name.set(enemy.name.get())
        self.description.set(enemy.description.get()[1:])
        if enemy.anim is not None:
            self.anim = enemy.anim.deepcopy()
            self.anim.flip_x()
            self.anim.set_unit_form(self.form_type.value)
            self.anim.set_id(cat_id)
            self.anim.mamodel.dup_ints()

        if enemy.icon is not None:
            self.import_enemy_deploy_icon(
                enemy.icon, deploy_icon_offset, deploy_icon_scale
            )

        if enemy.stats is not None:
            self.get_stats().import_enemy(enemy.stats)

    def import_enemy_from_id(
        self,
        cat_id: int,
        enemy_id: int,
        game_data: "tbcml.GamePacks",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
    ) -> "tbcml.Enemy":
        enemy = tbcml.Enemy(enemy_id)
        enemy.read(game_data)
        self.import_enemy(cat_id, enemy, deploy_icon_offset, deploy_icon_scale)
        return enemy

    def import_enemy_from_release_id(
        self,
        cat_id: int,
        enemy_release_id: int,
        game_data: "tbcml.GamePacks",
        deploy_icon_offset: tuple[int, int] = (-20, -20),
        deploy_icon_scale: float = 2.5,
    ) -> "tbcml.Enemy":
        return self.import_enemy_from_id(
            cat_id,
            enemy_release_id - 2,
            game_data,
            deploy_icon_offset,
            deploy_icon_scale,
        )

    def set_cat_id(self, id: int):
        if self.anim is not None:
            self.anim.set_id(id)

    def set_form(self, form: Union[int, "tbcml.CatFormType"]):
        if isinstance(form, int):
            form = tbcml.CatFormType.from_index(form)

        self.form_type = form
        if self.anim is not None:
            self.anim.set_unit_form(form.value)


@dataclass
class CatEvolveText:
    first_evol: StrListCSVField = CSVField.to_field(
        StrListCSVField,
        0,
        length=3,
        blank="＠",
    )
    blank: StringCSVField = CSVField.to_field(StringCSVField, 3)
    second_evol: StrListCSVField = CSVField.to_field(
        StrListCSVField,
        4,
        length=3,
        blank="＠",
    )
    comment: StringCSVField = CSVField.to_field(StringCSVField, 7)

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
    modification_type: tbcml.ModificationType = tbcml.ModificationType.CAT
    evolve_text: Optional[CatEvolveText] = None
    talents: Optional[CatTalents] = None

    def __post_init__(self):
        Cat.Schema()

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

    def read(self, game_data: "tbcml.GamePacks"):
        self.read_forms(game_data)
        self.read_unit_buy(game_data)
        self.read_nyanko_picture_book(game_data)
        self.read_talents(game_data)

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
            file_name_desc, country_code=game_data.country_code
        )
        return file_name_desc, name_csv

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
        csv = game_data.get_csv(file_name, country_code=game_data.country_code)

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

        if self.forms:
            for form in self.forms.values():
                form.apply_csv(name_csv, stat_csv, game_data, self.cat_id)

        game_data.set_csv(file_name_desc, name_csv)
        game_data.set_csv(file_name_stat, stat_csv)

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

    def read_forms(self, game_data: "tbcml.GamePacks"):
        _, name_csv = self.get_name_csv(game_data, self.cat_id)
        _, stat_csv = self.get_stats_csv(game_data, self.cat_id)

        total_forms = None

        if stat_csv is not None:
            total_forms = len(stat_csv.lines)
        elif name_csv is not None:
            total_forms = len(name_csv.lines)

        if total_forms is None:
            raise ValueError("Could not find name or stat csv!")

        self.forms = {}

        for form_index in range(total_forms):
            form_type = tbcml.CatFormType.from_index(form_index)
            self.forms[form_type] = CatForm(form_type)

        for form in self.forms.values():
            form.read_csv(name_csv, stat_csv, self.cat_id, game_data)

    def set_form(self, form: CatForm, form_type: Optional["tbcml.CatFormType"] = None):
        if self.forms is None:
            self.forms = {}

        if form_type is not None:
            form.form_type = form_type

        if form_type is None:
            form_type = form.form_type

        self.forms[form_type] = form

    def pre_to_json(self):
        for form in (self.forms or {}).values():
            form.pre_to_json()

    def get_custom_html(self) -> str:
        names = [form.name.get() for form in (self.forms or {}).values()]
        name_str = ", ".join(names)
        return f'<span style="color:#000">{name_str} (cat id: {self.cat_id})</span>'

    def set_cat_id(self, id: int):
        self.cat_id = id
        if self.forms is not None:
            for form in self.forms.values():
                form.set_cat_id(id)
