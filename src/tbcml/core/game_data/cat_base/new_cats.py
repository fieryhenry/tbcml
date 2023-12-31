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
    # attack_interval: Optional["core.Frames"] = None
    attack_range: IntCSVField = CSVField.to_field(IntCSVField, 5)
    cost: IntCSVField = CSVField.to_field(IntCSVField, 6)
    # recharge_time: Optional["core.Frames"] = None
    collision_start: IntCSVField = CSVField.to_field(IntCSVField, 8)
    collision_width: IntCSVField = CSVField.to_field(IntCSVField, 9)
    target_red: BoolCSVField = CSVField.to_field(BoolCSVField, 10)
    unused: IntCSVField = CSVField.to_field(IntCSVField, 11)
    area_attack: BoolCSVField = CSVField.to_field(BoolCSVField, 12)
    # z_layers: Optional["core.ZLayers"] = None
    target_floating: BoolCSVField = CSVField.to_field(BoolCSVField, 16)
    target_black: BoolCSVField = CSVField.to_field(BoolCSVField, 17)
    target_metal: BoolCSVField = CSVField.to_field(BoolCSVField, 18)
    target_traitless: BoolCSVField = CSVField.to_field(BoolCSVField, 19)
    target_angel: BoolCSVField = CSVField.to_field(BoolCSVField, 20)
    target_alien: BoolCSVField = CSVField.to_field(BoolCSVField, 21)
    target_zombie: BoolCSVField = CSVField.to_field(BoolCSVField, 22)
    strong: BoolCSVField = CSVField.to_field(BoolCSVField, 23)
    # knockback: Optional["core.Knockback"] = None
    # freeze: Optional["core.Freeze"] = None
    # slow: Optional["core.Slow"] = None
    # resistant: Optional[bool] = None
    # massive_damage: Optional[bool] = None
    # crit: Optional["core.Crit"] = None
    # attacks_only: Optional[bool] = None
    # extra_money: Optional[bool] = None
    # base_destroyer: Optional[bool] = None
    # wave: Optional["core.Wave"] = None
    # weaken: Optional["core.Weaken"] = None
    # strengthen: Optional["core.Strengthen"] = None
    # lethal_strike: Optional["core.LethalStrike"] = None
    # is_metal: Optional[bool] = None
    # wave_immunity: Optional[bool] = None
    # wave_blocker: Optional[bool] = None
    # knockback_immunity: Optional[bool] = None
    # freeze_immunity: Optional[bool] = None
    # slow_immunity: Optional[bool] = None
    # weaken_immunity: Optional[bool] = None
    # zombie_killer: Optional[bool] = None
    # witch_killer: Optional[bool] = None
    # target_witch: Optional[bool] = None
    # attack_state: Optional["core.AttackState"] = None
    # time_before_death: Optional["core.Frames"] = None
    # attack_1: Optional["core.Attack"] = None
    # attack_2: Optional["core.Attack"] = None
    # attack_3: Optional["core.Attack"] = None
    # spawn_anim: Optional["core.SpawnAnim"] = None
    # soul_anim: Optional["core.SoulAnim"] = None
    # barrier_breaker: Optional["core.BarrierBreak"] = None
    # warp: Optional["core.Warp"] = None
    # warp_blocker: Optional[bool] = None
    # target_eva: Optional[bool] = None
    # eva_killer: Optional[bool] = None
    # target_relic: Optional[bool] = None
    # curse_immunity: Optional[bool] = None
    # insanely_tough: Optional[bool] = None
    # insane_damage: Optional[bool] = None
    # savage_blow: Optional["core.SavageBlow"] = None
    # dodge: Optional["core.Dodge"] = None
    # surge: Optional["core.Surge"] = None
    # toxic_immunity: Optional[bool] = None
    # surge_immunity: Optional[bool] = None
    # curse: Optional["core.Curse"] = None
    # shield_pierce: Optional["core.ShieldPierce"] = None
    # target_aku: Optional[bool] = None
    # collossus_slayer: Optional[bool] = None
    # soul_strike: Optional[bool] = None
    # behemoth_slayer: Optional[bool] = None
    # behemoth_dodge: Optional["core.BehemothDodge"] = None
    # unknown_108: Optional[int] = None
    # counter_surge: Optional[bool] = None

    def __post_init__(self):
        CustomCatStats.Schema()

    def apply_csv(self, form_type: "core.CatFormType", csv: "core.CSV"):
        index = form_type.get_index()
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)


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
