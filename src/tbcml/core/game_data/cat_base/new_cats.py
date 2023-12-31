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
class CustomCatStats(core.Modification):
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

    def __post_init__(self):
        CustomCatStats.Schema()

    def apply_csv(self, form_type: "core.CatFormType", csv: "core.CSV"):
        index = form_type.get_index()
        csv.index = index
        required = [
            (55, -1),
            (57, -1),
            (63, 1),
            (66, -1),
        ]
        core.Modification.apply_csv_fields(self, csv, required)


@dataclass
class CustomForm(core.Modification):
    form_type: "core.CatFormType" = field(metadata={"required": True})
    name: StringCSVField = CSVField.to_field(StringCSVField, col_index=0)
    description: StrListCSVField = CSVField.to_field(
        StrListCSVField, col_index=1, length=3
    )
    stats: Optional[CustomCatStats] = None

    def __post_init__(self):
        CustomForm.Schema()

    def apply_csv(
        self,
        name_csv: Optional["core.CSV"] = None,
        stat_csv: Optional["core.CSV"] = None,
    ):
        if name_csv is not None:
            self.apply_name_desc(name_csv)
        if self.stats is not None and stat_csv is not None:
            self.stats.apply_csv(self.form_type, stat_csv)

    def apply_name_desc(self, csv: "core.CSV"):
        index = self.form_type.get_index()
        csv.index = index

        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomCat(core.Modification):
    cat_id: int = field(metadata={"required": True})
    forms: Optional[dict["core.CatFormType", CustomForm]] = None
    modification_type: core.ModificationType = core.ModificationType.CAT

    def __post_init__(
        self,
    ):  # This is required for CustomCat.Schema to not be a string for some reason
        CustomCat.Schema()

    def apply(self, game_data: "core.GamePacks"):
        return self.apply_forms(game_data)

    def apply_forms(self, game_data: "core.GamePacks"):
        file_name_desc = (
            f"Unit_Explanation{self.cat_id+1}_{game_data.localizable.get_lang()}.csv"
        )
        name_csv = game_data.get_csv(
            file_name_desc, country_code=game_data.country_code
        )

        file_name_stat = f"unit{core.PaddedInt(self.cat_id+1,3 )}.csv"
        stat_csv = game_data.get_csv(file_name_stat)

        if self.forms:
            for form in self.forms.values():
                form.apply_csv(name_csv, stat_csv)

        game_data.set_csv(file_name_desc, name_csv)
        game_data.set_csv(file_name_stat, stat_csv)

    def set_form(
        self, form: CustomForm, form_type: Optional["core.CatFormType"] = None
    ):
        if self.forms is None:
            self.forms = {}

        if form_type is None:
            form_type = form.form_type

        self.forms[form_type] = form
