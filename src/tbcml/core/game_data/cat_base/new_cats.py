from typing import Optional
from dataclasses import field
from tbcml import core

from tbcml.core.io.csv_fields import (
    IntCSVField,
    CSVField,
    BoolCSVField,
    StringCSVField,
    StrListCSVField,
    IntListCSVField,
)

from marshmallow_dataclass import dataclass


@dataclass
class CustomCatStats:
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

    def apply_csv(self, form_type: "core.CatFormType", csv: "core.CSV"):
        index = form_type.get_index()
        csv.index = index
        required: list[tuple[int, int]] = [
            (55, -1),
            (57, -1),
            (63, 1),
            (66, -1),
        ]
        core.Modification.apply_csv_fields(self, csv, required, remove_others=False)

    def read_csv(self, form_type: "core.CatFormType", csv: "core.CSV"):
        index = form_type.get_index()
        csv.index = index
        core.Modification.read_csv_fields(self, csv)


@dataclass
class CustomUnitBuy:
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

    def apply_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.read_csv_fields(self, csv)


@dataclass
class CustomNyankoPictureBook:
    is_displayed_in_cat_guide: BoolCSVField = CSVField.to_field(BoolCSVField, 0)
    limited: BoolCSVField = CSVField.to_field(BoolCSVField, 1)
    total_forms: IntCSVField = CSVField.to_field(IntCSVField, 2)
    hint_display_type: IntCSVField = CSVField.to_field(IntCSVField, 3)
    scale_1st: IntCSVField = CSVField.to_field(IntCSVField, 4)
    scale_2nd: IntCSVField = CSVField.to_field(IntCSVField, 5)
    scale_3rd: IntCSVField = CSVField.to_field(IntCSVField, 6)
    scale_4th: IntCSVField = CSVField.to_field(IntCSVField, 7)

    def apply_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.read_csv_fields(self, csv)


@dataclass
class CustomForm:
    form_type: "core.CatFormType" = field(metadata={"required": True})
    name: StringCSVField = CSVField.to_field(StringCSVField, 0)
    description: StrListCSVField = CSVField.to_field(StrListCSVField, 1, length=3)
    stats: Optional[CustomCatStats] = None
    anim: Optional["core.CustomModel"] = None
    upgrade_icon: Optional["core.NewBCImage"] = None
    deploy_icon: Optional["core.NewBCImage"] = None

    def get_anim(self) -> "core.CustomModel":
        if self.anim is None:
            self.anim = core.CustomModel()
        return self.anim

    def get_deploy_icon(self) -> "core.NewBCImage":
        if self.deploy_icon is None:
            self.deploy_icon = core.NewBCImage.from_size(128, 128)
        return self.deploy_icon

    def get_upgrade_icon(self) -> "core.NewBCImage":
        if self.upgrade_icon is None:
            self.upgrade_icon = core.NewBCImage.from_size(512, 128)
        return self.upgrade_icon

    def apply_game_data(self, cat_id: int, game_data: "core.GamePacks"):
        name_file_name, name_csv = CustomCat.get_name_csv(game_data, cat_id)
        stats_file_name, stats_csv = CustomCat.get_stats_csv(game_data, cat_id)
        self.apply_csv(name_csv, stats_csv, game_data, cat_id)
        game_data.set_csv(name_file_name, name_csv)
        game_data.set_csv(stats_file_name, stats_csv)

    def set_icons(self, cat_id: int, game_data: "core.GamePacks"):
        game_data.set_img(self.get_upgrade_icon_file_name(cat_id), self.upgrade_icon)
        game_data.set_img(self.get_deploy_icon_file_name(cat_id), self.deploy_icon)

    def read_game_data(self, cat_id: int, game_data: "core.GamePacks"):
        _, name_csv = CustomCat.get_name_csv(game_data, cat_id)
        _, stats_csv = CustomCat.get_stats_csv(game_data, cat_id)
        self.read_csv(name_csv, stats_csv, cat_id, game_data)

    def get_upgrade_icon_file_name(self, cat_id: int):
        return f"udi{CustomCat.get_cat_id_str(cat_id)}_{self.form_type.value}.png"

    def get_deploy_icon_file_name(self, cat_id: int):
        return f"uni{CustomCat.get_cat_id_str(cat_id)}_{self.form_type.value}00.png"

    def get_sprite_file_name(self, cat_id: int):
        return f"{CustomCat.get_cat_id_str(cat_id)}_{self.form_type.value}.png"

    def get_imgcut_file_name(self, cat_id: int):
        return self.get_sprite_file_name(cat_id).replace(".png", ".imgcut")

    def get_mamodel_file_name(self, cat_id: int):
        return self.get_sprite_file_name(cat_id).replace(".png", ".mamodel")

    def get_maanim_file_name(self, cat_id: int, anim_type: "core.AnimType"):
        anim_type_str = core.PaddedInt(anim_type.value, 2).to_str()
        return self.get_sprite_file_name(cat_id).replace(
            ".png", f"{anim_type_str}.maanim"
        )

    def get_maanim_paths(self, cat_id: int) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in core.AnimType:
            maanim_paths.append(self.get_maanim_file_name(cat_id, anim_type))
        cat_id_str = CustomCat.get_cat_id_str(cat_id)
        maanim_paths.append(f"{cat_id_str}_{self.form_type.value}_entry.maanim")
        maanim_paths.append(f"{cat_id_str}_{self.form_type.value}_soul.maanim")
        return maanim_paths

    def read_anim(self, cat_id: int, game_data: "core.GamePacks"):
        self.anim = core.CustomModel()
        self.anim.read(
            game_data,
            self.get_sprite_file_name(cat_id),
            self.get_imgcut_file_name(cat_id),
            self.get_maanim_paths(cat_id),
            self.get_mamodel_file_name(cat_id),
        )

    def apply_csv(
        self,
        name_csv: Optional["core.CSV"],
        stat_csv: Optional["core.CSV"],
        game_data: Optional["core.GamePacks"],
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

    def apply_name_desc(self, csv: "core.CSV"):
        index = self.form_type.get_index()
        csv.index = index

        core.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_name_desc(self, csv: "core.CSV"):
        index = self.form_type.get_index()
        csv.index = index

        core.Modification.read_csv_fields(self, csv)

    def read_csv(
        self,
        name_csv: Optional["core.CSV"],
        stat_csv: Optional["core.CSV"],
        cat_id: Optional[int],
        game_data: Optional["core.GamePacks"],
    ):
        if name_csv is not None:
            self.read_name_desc(name_csv)
        if stat_csv is not None:
            self.stats = CustomCatStats()
            self.stats.read_csv(self.form_type, stat_csv)
        if game_data is not None and cat_id is not None:
            self.read_anim(cat_id, game_data)
            self.read_icons(cat_id, game_data)

    def read_icons(self, cat_id: int, game_data: "core.GamePacks"):
        self.upgrade_icon = game_data.get_img(self.get_upgrade_icon_file_name(cat_id))
        self.deploy_icon = game_data.get_img(self.get_deploy_icon_file_name(cat_id))

    def on_add_to_mod(self):
        if self.deploy_icon is not None:
            self.deploy_icon.save_b64()
        if self.upgrade_icon is not None:
            self.upgrade_icon.save_b64()
        if self.anim is not None:
            self.anim.texture.save_b64()


@dataclass
class CustomEvolveText:
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

    def apply_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.apply_csv_fields(self, csv, remove_others=False)

    def read_csv(self, cat_id: int, csv: "core.CSV"):
        csv.index = cat_id
        core.Modification.read_csv_fields(self, csv)


@dataclass
class CustomCat(core.Modification):
    cat_id: int = field(metadata={"required": True})
    forms: Optional[dict["core.CatFormType", CustomForm]] = None
    unitbuy: Optional[CustomUnitBuy] = None
    nyanko_picture_book: Optional[CustomNyankoPictureBook] = None
    modification_type: core.ModificationType = core.ModificationType.CAT
    evolve_text: Optional[CustomEvolveText] = None

    def __post_init__(
        self,
    ):  # This is required for CustomCat.Schema to not be a string for some reason
        CustomCat.Schema()

    def get_evolve_text(self) -> CustomEvolveText:
        if self.evolve_text is None:
            self.evolve_text = CustomEvolveText()
        return self.evolve_text

    def get_unitbuy(self) -> "CustomUnitBuy":
        if self.unitbuy is None:
            self.unitbuy = CustomUnitBuy()
        return self.unitbuy

    def get_nyanko_picture_book(self) -> "CustomNyankoPictureBook":
        if self.nyanko_picture_book is None:
            self.nyanko_picture_book = CustomNyankoPictureBook()
        return self.nyanko_picture_book

    def apply(self, game_data: "core.GamePacks"):
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

    def read(self, game_data: "core.GamePacks"):
        self.read_forms(game_data)
        self.read_unit_buy(game_data)
        self.read_nyanko_picture_book(game_data)

    @staticmethod
    def get_cat_id_str(cat_id: int) -> str:
        return core.PaddedInt(cat_id, 3).to_str()

    @staticmethod
    def get_name_csv(
        game_data: "core.GamePacks", cat_id: int
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name_desc = (
            f"Unit_Explanation{cat_id+1}_{game_data.localizable.get_lang()}.csv"
        )
        name_csv = game_data.get_csv(
            file_name_desc, country_code=game_data.country_code
        )
        return file_name_desc, name_csv

    @staticmethod
    def get_stats_csv(
        game_data: "core.GamePacks", cat_id: int
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name_stat = f"unit{core.PaddedInt(cat_id+1,3 )}.csv"
        stat_csv = game_data.get_csv(file_name_stat)

        return file_name_stat, stat_csv

    @staticmethod
    def get_unit_buy_csv(
        game_data: "core.GamePacks",
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name = "unitbuy.csv"
        csv = game_data.get_csv(file_name)

        return file_name, csv

    @staticmethod
    def get_nyanko_picture_book_data_csv(
        game_data: "core.GamePacks",
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name = "nyankoPictureBookData.csv"
        csv = game_data.get_csv(file_name)

        return file_name, csv

    @staticmethod
    def get_evolve_text_csv(
        game_data: "core.GamePacks",
    ) -> tuple[str, Optional["core.CSV"]]:
        file_name = f"unitevolve_{game_data.localizable.get_lang()}.csv"
        csv = game_data.get_csv(file_name, country_code=game_data.country_code)

        return file_name, csv

    def apply_unit_buy(self, unit_buy_csv: Optional["core.CSV"]):
        if self.unitbuy is not None and unit_buy_csv is not None:
            self.unitbuy.apply_csv(self.cat_id, unit_buy_csv)

    def apply_nyanko_picture_book(self, nyanko_picture_book_csv: Optional["core.CSV"]):
        if self.nyanko_picture_book is not None and nyanko_picture_book_csv is not None:
            self.nyanko_picture_book.apply_csv(self.cat_id, nyanko_picture_book_csv)

    def apply_evolve_text(self, evolve_text_csv: Optional["core.CSV"]):
        if self.evolve_text is not None and evolve_text_csv is not None:
            self.evolve_text.apply_csv(self.cat_id, evolve_text_csv)

    def apply_forms(self, game_data: "core.GamePacks"):
        file_name_desc, name_csv = CustomCat.get_name_csv(game_data, self.cat_id)
        file_name_stat, stat_csv = CustomCat.get_stats_csv(game_data, self.cat_id)

        if self.forms:
            for form in self.forms.values():
                form.apply_csv(name_csv, stat_csv, game_data, self.cat_id)

        game_data.set_csv(file_name_desc, name_csv)
        game_data.set_csv(file_name_stat, stat_csv)

    def read_unit_buy_csv(self, csv: Optional["core.CSV"]):
        if csv is None:
            return
        self.get_unitbuy().read_csv(self.cat_id, csv)

    def read_nyanko_picture_book_csv(self, csv: Optional["core.CSV"]):
        if csv is None:
            return
        self.get_nyanko_picture_book().read_csv(self.cat_id, csv)

    def read_evolve_text_csv(self, csv: Optional["core.CSV"]):
        if csv is None:
            return
        self.get_evolve_text().read_csv(self.cat_id, csv)

    def read_unit_buy(self, game_data: "core.GamePacks"):
        self.read_unit_buy_csv(self.get_unit_buy_csv(game_data)[1])

    def read_nyanko_picture_book(self, game_data: "core.GamePacks"):
        self.read_nyanko_picture_book_csv(
            self.get_nyanko_picture_book_data_csv(game_data)[1]
        )

    def read_evolve_text(self, game_data: "core.GamePacks"):
        self.read_evolve_text_csv(self.get_evolve_text_csv(game_data)[1])

    def read_forms(self, game_data: "core.GamePacks"):
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
            form_type = core.CatFormType.from_index(form_index)
            self.forms[form_type] = CustomForm(form_type)

        for form in self.forms.values():
            form.read_csv(name_csv, stat_csv, self.cat_id, game_data)

    def set_form(
        self, form: CustomForm, form_type: Optional["core.CatFormType"] = None
    ):
        if self.forms is None:
            self.forms = {}

        if form_type is not None:
            form.form_type = form_type

        if form_type is None:
            form_type = form.form_type

        self.forms[form_type] = form

    def on_add_to_mod(self):
        for form in (self.forms or {}).values():
            form.on_add_to_mod()
