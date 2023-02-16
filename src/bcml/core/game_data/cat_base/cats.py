import enum
from typing import Any, Optional, Union
from bcml.core.game_data.cat_base import unit, enemies
from bcml.core.game_data import pack, bc_anim
from bcml.core import io, country_code


class FormType(enum.Enum):
    FIRST = "f"
    SECOND = "c"
    THIRD = "s"
    FOURTH = "u"

    def get_index(self) -> int:
        if self == FormType.FIRST:
            return 0
        elif self == FormType.SECOND:
            return 1
        elif self == FormType.THIRD:
            return 2
        elif self == FormType.FOURTH:
            return 3
        else:
            raise ValueError("Invalid form type")

    @staticmethod
    def from_index(index: int) -> "FormType":
        if index == 0:
            return FormType.FIRST
        elif index == 1:
            return FormType.SECOND
        elif index == 2:
            return FormType.THIRD
        elif index == 3:
            return FormType.FOURTH
        else:
            raise ValueError("Invalid form index")


class Stats:
    def __init__(self, cat_id: int, form: FormType, raw_data: list[int]):
        self.cat_id = cat_id
        self.form = form
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def extend(self, raw_data: list[int]):
        length = 108
        raw_data = raw_data + [0] * (length - len(raw_data))
        return raw_data

    def set_required(self):
        self.attacks_before_state = -1
        self.time_before_death.frames = -1
        self.attack_1.use_ability = True
        self.spawn_anim_id = -1

    def assign(self, raw_data: list[int]):
        self.hp = raw_data[0]
        self.kbs = raw_data[1]
        self.speed = raw_data[2]
        self.attack_interval = unit.Frames.from_pair_frames(raw_data[4])
        self.range = raw_data[5]
        self.cost = raw_data[6]
        self.recharge_time = unit.Frames.from_pair_frames(raw_data[7])
        self.hitbox_pos = raw_data[8]
        self.hitbox_width = raw_data[9]
        self.target_red = bool(raw_data[10])
        self.unused = raw_data[11]
        self.area_attack = bool(raw_data[12])
        self.z_layers = unit.ZLayers.from_values(raw_data[14], raw_data[15])
        self.target_floating = bool(raw_data[16])
        self.target_black = bool(raw_data[17])
        self.target_metal = bool(raw_data[18])
        self.target_traitless = bool(raw_data[19])
        self.target_angel = bool(raw_data[20])
        self.target_alien = bool(raw_data[21])
        self.target_zombie = bool(raw_data[22])
        self.strong = bool(raw_data[23])
        self.knockback = unit.Knockback.from_values(raw_data[24])
        self.freeze = unit.Freeze.from_values(raw_data[25], raw_data[26])
        self.slow = unit.Slow.from_values(raw_data[27], raw_data[28])
        self.resistant = bool(raw_data[29])
        self.massive_damage = bool(raw_data[30])
        self.crit = unit.Crit.from_values(raw_data[31])
        self.attacks_only = bool(raw_data[32])
        self.extra_money = bool(raw_data[33])
        self.base_destroyer = bool(raw_data[34])
        self.wave = unit.Wave.from_values(
            raw_data[35], raw_data[36], bool(raw_data[94])
        )
        self.weaken = unit.Weaken.from_values(raw_data[37], raw_data[38], raw_data[39])
        self.strengthen = unit.Strengthen.from_values(raw_data[40], raw_data[41])
        self.lethal_strike = unit.LethalStrike.from_values(raw_data[42])
        self.is_metal = bool(raw_data[43])
        self.wave_immunity = bool(raw_data[46])
        self.wave_blocker = bool(raw_data[47])
        self.knockback_immunity = bool(raw_data[48])
        self.freeze_immunity = bool(raw_data[49])
        self.slow_immunity = bool(raw_data[50])
        self.weaken_immunity = bool(raw_data[51])
        self.zombie_killer = bool(raw_data[52])
        self.witch_killer = bool(raw_data[53])
        self.target_witch = bool(raw_data[54])
        self.attacks_before_state = raw_data[55]
        self.shockwave_immune = bool(raw_data[56])
        self.time_before_death = unit.Frames(raw_data[57])
        self.unit_state = raw_data[58]
        self.attack_1 = unit.Attack.from_values(
            raw_data[3],
            raw_data[13],
            bool(raw_data[63]),
            True,
            raw_data[44],
            raw_data[45],
        )
        self.attack_2 = unit.Attack.from_values(
            raw_data[59],
            raw_data[61],
            bool(raw_data[64]),
            bool(raw_data[99]),
            raw_data[100],
            raw_data[101],
        )
        self.attack_3 = unit.Attack.from_values(
            raw_data[60],
            raw_data[62],
            bool(raw_data[65]),
            bool(raw_data[102]),
            raw_data[103],
            raw_data[104],
        )
        self.spawn_anim_id = raw_data[66]
        self.soul_anim = unit.SoulAnim(raw_data[67])
        self.custom_spawn_anim = bool(raw_data[68])
        self.custom_soul_anim = not bool(raw_data[69])
        self.barrier_breaker = unit.BarrierBreak.from_values(raw_data[70])
        self.warp = unit.Warp.from_values(
            raw_data[71], raw_data[72], raw_data[73], raw_data[74]
        )
        self.warp_blocker = bool(raw_data[75])
        self.target_eva = bool(raw_data[76])
        self.eva_killer = bool(raw_data[77])
        self.target_relic = bool(raw_data[78])
        self.curse_immunity = bool(raw_data[79])
        self.insanely_tough = bool(raw_data[80])
        self.insane_damage = bool(raw_data[81])
        self.savage_blow = unit.SavageBlow.from_values(raw_data[82], raw_data[83])
        self.dodge = unit.Dodge.from_values(raw_data[84], raw_data[85])
        self.surge = unit.Surge.from_values(
            raw_data[86], raw_data[87], raw_data[88], raw_data[89]
        )
        self.toxic_immunity = bool(raw_data[90])
        self.surge_immunity = bool(raw_data[91])
        self.curse = unit.Curse.from_values(raw_data[92], raw_data[93])
        self.shield_pierce = unit.ShieldPierce.from_values(raw_data[95])
        self.target_aku = bool(raw_data[96])
        self.collossus_slayer = bool(raw_data[97])
        self.soul_strike = bool(raw_data[98])
        self.behemoth_slayer = bool(raw_data[105])
        self.behemoth_dodge = unit.BehemothDodge.from_values(
            raw_data[106], raw_data[107]
        )

    def to_raw_data(self) -> list[int]:
        return [
            self.hp,  # 0
            self.kbs,  # 1
            self.speed,  # 2
            self.attack_1.damage,  # 3
            self.attack_interval.pair_frames,  # 4
            self.range,  # 5
            self.cost,  # 6
            self.recharge_time.pair_frames,  # 7
            self.hitbox_pos,  # 8
            self.hitbox_width,  # 9
            int(self.target_red),  # 10
            self.unused,  # 11
            int(self.area_attack),  # 12
            self.attack_1.foreswing.frames,  # 13
            self.z_layers.min,  # 14
            self.z_layers.max,  # 15
            int(self.target_floating),  # 16
            int(self.target_black),  # 17
            int(self.target_metal),  # 18
            int(self.target_traitless),  # 19
            int(self.target_angel),  # 20
            int(self.target_alien),  # 21
            int(self.target_zombie),  # 22
            int(self.strong),  # 23
            self.knockback.prob.percent,  # 24
            self.freeze.prob.percent,  # 25
            self.freeze.time.frames,  # 26
            self.slow.prob.percent,  # 27
            self.slow.time.frames,  # 28
            int(self.resistant),  # 29
            int(self.massive_damage),  # 30
            self.crit.prob.percent,  # 31
            int(self.attacks_only),  # 32
            int(self.extra_money),  # 33
            int(self.base_destroyer),  # 34
            self.wave.prob.percent,  # 35
            self.wave.level,  # 36
            self.weaken.prob.percent,  # 37
            self.weaken.time.frames,  # 38
            self.weaken.multiplier,  # 39
            self.strengthen.hp_percent,  # 40
            self.strengthen.multiplier_percent,  # 41
            self.lethal_strike.prob.percent,  # 42
            int(self.is_metal),  # 43
            self.attack_1.long_distance_start,  # 44
            self.attack_1.long_distance_range,  # 45
            int(self.wave_immunity),  # 46
            int(self.wave_blocker),  # 47
            int(self.knockback_immunity),  # 48
            int(self.freeze_immunity),  # 49
            int(self.slow_immunity),  # 50
            int(self.weaken_immunity),  # 51
            int(self.zombie_killer),  # 52
            int(self.witch_killer),  # 53
            int(self.target_witch),  # 54
            self.attacks_before_state,  # 55
            int(self.shockwave_immune),  # 56
            self.time_before_death.frames,  # 57
            self.unit_state,  # 58
            self.attack_2.damage,  # 59
            self.attack_3.damage,  # 60
            self.attack_2.foreswing.frames,  # 61
            self.attack_3.foreswing.frames,  # 62
            int(self.attack_1.use_ability),  # 63
            int(self.attack_2.use_ability),  # 64
            int(self.attack_3.use_ability),  # 65
            self.spawn_anim_id,  # 66
            self.soul_anim.anim_type,  # 67
            int(self.custom_spawn_anim),  # 68
            int(not self.custom_soul_anim),  # 69
            self.barrier_breaker.prob.percent,  # 70
            self.warp.prob.percent,  # 71
            self.warp.time.frames,  # 72
            self.warp.min_distance,  # 73
            self.warp.max_distance,  # 74
            int(self.warp_blocker),  # 75
            int(self.target_eva),  # 76
            int(self.eva_killer),  # 77
            int(self.target_relic),  # 78
            int(self.curse_immunity),  # 79
            int(self.insanely_tough),  # 80
            int(self.insane_damage),  # 81
            self.savage_blow.prob.percent,  # 82
            self.savage_blow.multiplier,  # 83
            self.dodge.prob.percent,  # 84
            self.dodge.time.frames,  # 85
            self.surge.prob.percent,  # 86
            self.surge.start,  # 87
            self.surge.range,  # 88
            self.surge.level,  # 89
            int(self.toxic_immunity),  # 90
            int(self.surge_immunity),  # 91
            self.curse.prob.percent,  # 92
            self.curse.time.frames,  # 93
            int(self.wave.is_mini),  # 94
            self.shield_pierce.prob.percent,  # 95
            int(self.target_aku),  # 96
            int(self.collossus_slayer),  # 97
            int(self.soul_strike),  # 98
            int(self.attack_2.long_distance_flag),  # 99
            self.attack_2.long_distance_start,  # 100
            self.attack_2.long_distance_range,  # 101
            int(self.attack_3.long_distance_flag),  # 102
            self.attack_3.long_distance_start,  # 103
            self.attack_3.long_distance_range,  # 104
            int(self.behemoth_slayer),  # 105
            self.behemoth_dodge.prob.percent,  # 106
            self.behemoth_dodge.time.frames,  # 107
        ]

    def serialize(self) -> dict[str, Any]:
        return {
            "raw_data": self.to_raw_data(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int, form: FormType) -> "Stats":
        return Stats(
            cat_id,
            form,
            data["raw_data"],
        )

    def wipe(self):
        raw_data = []
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def has_targeted_effect(self) -> bool:
        to_check = [
            self.knockback.prob.percent,
            self.freeze.prob.percent,
            self.slow.prob.percent,
            self.weaken.prob.percent,
            self.warp.prob.percent,
            self.curse.prob.percent,
            self.dodge.prob.percent,
        ]
        return any(to_check)

    def import_enemy_stats(self, enemy_stats: "enemies.Stats"):
        self.wipe()
        self.hp = enemy_stats.hp
        self.kbs = enemy_stats.kbs
        self.speed = enemy_stats.speed
        self.attack_interval = enemy_stats.attack_interval
        self.range = enemy_stats.range
        self.cost = enemy_stats.money_drop // 4
        self.hitbox_pos = enemy_stats.hitbox_pos
        self.hitbox_width = enemy_stats.hitbox_width
        self.area_attack = enemy_stats.area_attack
        self.knockback = enemy_stats.knockback.copy()
        self.freeze = enemy_stats.freeze.copy()
        self.slow = enemy_stats.slow.copy()
        self.weaken = enemy_stats.weaken.copy()
        self.crit = enemy_stats.crit.copy()
        self.base_destroyer = enemy_stats.base_destroyer
        self.wave = enemy_stats.wave.copy()
        self.strengthen = enemy_stats.strengthen.copy()
        self.is_metal = enemy_stats.metal
        self.wave_immunity = enemy_stats.wave_immunity
        self.wave_blocker = enemy_stats.wave_blocker
        self.knockback_immunity = enemy_stats.knockback_immunity
        self.freeze_immunity = enemy_stats.freeze_immunity
        self.slow_immunity = enemy_stats.slow_immunity
        self.weaken_immunity = enemy_stats.weaken_immunity
        self.attacks_before_state = enemy_stats.attacks_before_state
        self.time_before_death = enemy_stats.time_before_death
        self.unit_state = enemy_stats.enemy_state
        self.attack_1 = enemy_stats.attack_1.copy()
        self.attack_2 = enemy_stats.attack_2.copy()
        self.attack_3 = enemy_stats.attack_3.copy()
        self.spawn_anim_id = enemy_stats.spawn_anim_id
        self.soul_anim = enemy_stats.soul_anim.copy()
        self.custom_spawn_anim = enemy_stats.custom_spawn_anim
        self.custom_soul_anim = enemy_stats.custom_soul_anim
        self.warp = enemy_stats.warp.copy()
        self.warp_blocker = enemy_stats.warp_blocker
        self.savage_blow = enemy_stats.savage_blow.copy()
        self.dodge = enemy_stats.dodge.copy()
        self.surge = enemy_stats.surge.copy()
        self.surge_immunity = enemy_stats.surge_immunity
        has_targeted_effect = self.has_targeted_effect()
        self.target_aku = has_targeted_effect
        self.target_alien = has_targeted_effect
        self.target_angel = has_targeted_effect
        self.target_black = has_targeted_effect
        self.target_floating = has_targeted_effect
        self.target_metal = has_targeted_effect
        self.target_red = has_targeted_effect
        self.target_relic = has_targeted_effect
        self.target_traitless = has_targeted_effect
        self.target_zombie = has_targeted_effect

    def copy(self) -> "Stats":
        return Stats(
            self.cat_id,
            self.form,
            self.to_raw_data(),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Stats):
            return False
        return self.to_raw_data() == other.to_raw_data()

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Anim:
    def __init__(self, cat_id: int, form: FormType, anim: "bc_anim.Anim"):
        self.cat_id = cat_id
        self.form = form
        self.anim = anim

    def serialize(self) -> dict[str, Any]:
        return {
            "anim": self.anim.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int, form: FormType) -> "Anim":
        return Anim(
            cat_id,
            form,
            bc_anim.Anim.deserialize(data["anim"]),
        )

    @staticmethod
    def get_cat_id_str(cat_id: int) -> str:
        return io.data.PaddedInt(cat_id, 3).to_str()

    @staticmethod
    def get_img_path(cat_id: int, form: FormType) -> str:
        cat_id_str = Anim.get_cat_id_str(cat_id)
        return f"{cat_id_str}_{form.value}.png"

    @staticmethod
    def get_imgcut_path(cat_id: int, form: FormType) -> str:
        return Anim.get_img_path(cat_id, form).replace(".png", ".imgcut")

    @staticmethod
    def get_mamodel_path(cat_id: int, form: FormType) -> str:
        return Anim.get_img_path(cat_id, form).replace(".png", ".mamodel")

    @staticmethod
    def get_maanim_path(
        cat_id: int, form: FormType, anim_type: "bc_anim.AnimType"
    ) -> str:
        anim_type_str = io.data.PaddedInt(anim_type.value, 2).to_str()
        return Anim.get_img_path(cat_id, form).replace(
            ".png", f"{anim_type_str}.maanim"
        )

    @staticmethod
    def get_maanim_paths(cat_id: int, form: FormType) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in bc_anim.AnimType:
            maanim_paths.append(Anim.get_maanim_path(cat_id, form, anim_type))
        return maanim_paths

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", cat_id: int, form: FormType
    ) -> Optional["Anim"]:
        img_path = Anim.get_img_path(cat_id, form)
        imgcut_path = Anim.get_imgcut_path(cat_id, form)
        mamodel_path = Anim.get_mamodel_path(cat_id, form)
        maanim_paths = Anim.get_maanim_paths(cat_id, form)
        anim = bc_anim.Anim.from_paths(
            game_data, img_path, imgcut_path, mamodel_path, maanim_paths
        )
        return Anim(cat_id, form, anim)

    def to_game_data(self, game_data: "pack.GamePacks"):
        img_path = Anim.get_img_path(self.cat_id, self.form)
        imgcut_path = Anim.get_imgcut_path(self.cat_id, self.form)
        mamodel_path = Anim.get_mamodel_path(self.cat_id, self.form)
        maanim_paths = Anim.get_maanim_paths(self.cat_id, self.form)
        self.anim.to_game_data(
            game_data, img_path, imgcut_path, mamodel_path, maanim_paths
        )

    def set_cat_id(self, cat_id: int):
        self.cat_id = cat_id
        self.anim.set_cat_id(cat_id, self.form.value)

    def import_enemy_anim(self, enemy_anim: "enemies.Anim"):
        self.anim.imgcut = enemy_anim.anim.imgcut.copy()
        self.anim.mamodel = enemy_anim.anim.mamodel.copy()
        self.anim.maanims = [maanim.copy() for maanim in enemy_anim.anim.maanims]
        for maanim in self.anim.maanims:
            maanim.name
        self.anim.mamodel.fix_collision()
        self.anim.flip_x()
        self.anim.set_cat_id(self.cat_id, self.form.value)

    def copy(self) -> "Anim":
        return Anim(
            self.cat_id,
            self.form,
            self.anim.copy(),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Anim):
            return False
        return self.anim == other.anim

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Form:
    def __init__(
        self,
        cat_id: int,
        form: FormType,
        stats: "Stats",
        name: str,
        description: list[str],
        anim: "Anim",
        upgrade_icon: "io.bc_image.BCImage",
        deploy_icon: "io.bc_image.BCImage",
    ):
        self.cat_id = cat_id
        self.form = form
        self.stats = stats
        self.name = name
        self.description = description
        self.anim = anim
        self.upgrade_icon = upgrade_icon
        self.deploy_icon = deploy_icon

    def serialize(self) -> dict[str, Any]:
        return {
            "stats": self.stats.serialize(),
            "name": self.name,
            "description": self.description,
            "anim": self.anim.serialize(),
            "upgrade_icon": self.upgrade_icon.serialize(),
            "deploy_icon": self.deploy_icon.serialize(),
        }

    def format_deploy_icon(self):
        if self.deploy_icon.width == 128 and self.deploy_icon.height == 128:
            return
        base_image = io.bc_image.BCImage.from_size(128, 128)
        base_image.paste(self.deploy_icon, 9, 21)
        self.deploy_icon = base_image

    def format_upgrade_icon(self):
        if self.upgrade_icon.width == 85 and self.upgrade_icon.height == 32:
            self.upgrade_icon.scale(3.5)

        base_image = io.bc_image.BCImage.from_size(512, 128)
        base_image.paste(self.upgrade_icon, 13, 1)

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

    def format_icons(self):
        self.format_deploy_icon()
        self.format_upgrade_icon()

    @staticmethod
    def deserialize(
        data: dict[str, Any],
        cat_id: int,
        form: FormType,
    ) -> "Form":
        return Form(
            cat_id,
            form,
            Stats.deserialize(data["stats"], cat_id, form),
            data["name"],
            data["description"],
            Anim.deserialize(data["anim"], cat_id, form),
            io.bc_image.BCImage.deserialize(data["upgrade_icon"]),
            io.bc_image.BCImage.deserialize(data["deploy_icon"]),
        )

    @staticmethod
    def get_icons_game_data(
        game_data: "pack.GamePacks", cat_id: int, form: FormType
    ) -> Optional[tuple["io.bc_image.BCImage", "io.bc_image.BCImage"]]:
        cat_id_str = io.data.PaddedInt(cat_id, 3).to_str()
        upgrade_name = f"udi{cat_id_str}_{form.value}.png"
        deploy_name = f"uni{cat_id_str}_{form.value}00.png"
        upgrade_icon = game_data.find_file(upgrade_name)
        deploy_icon = game_data.find_file(deploy_name)
        if upgrade_icon is None or deploy_icon is None:
            return None
        return (
            io.bc_image.BCImage(upgrade_icon.dec_data),
            io.bc_image.BCImage(deploy_icon.dec_data),
        )

    def icons_to_game_data(
        self,
        game_data: "pack.GamePacks",
    ):
        cat_id_str = io.data.PaddedInt(self.cat_id, 3).to_str()
        upgrade_name = f"udi{cat_id_str}_{self.form.value}.png"
        deploy_name = f"uni{cat_id_str}_{self.form.value}00.png"
        game_data.set_file(upgrade_name, self.upgrade_icon.to_data())
        game_data.set_file(deploy_name, self.deploy_icon.to_data())

    def set_cat_id(self, cat_id: int):
        self.cat_id = cat_id
        self.stats.cat_id = cat_id
        self.anim.set_cat_id(cat_id)

    def import_enemy(self, enemy: "enemies.Enemy"):
        self.name = enemy.name
        self.description = enemy.description[1:]
        self.anim.import_enemy_anim(enemy.anim)
        self.stats.import_enemy_stats(enemy.stats)

    def copy(self) -> "Form":
        return Form(
            self.cat_id,
            self.form,
            self.stats.copy(),
            self.name,
            self.description.copy(),
            self.anim.copy(),
            self.upgrade_icon.copy(),
            self.deploy_icon.copy(),
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Form):
            return False
        return (
            self.cat_id == other.cat_id
            and self.form == other.form
            and self.stats == other.stats
            and self.name == other.name
            and self.description == other.description
            and self.anim == other.anim
            and self.upgrade_icon == other.upgrade_icon
            and self.deploy_icon == other.deploy_icon
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class UnlockSourceType(enum.Enum):
    XP = 0
    GACHA = 1


class GatchaRarity(enum.Enum):
    NONE = 0
    RARE = 1
    SUPER_RARE = 2
    UBER_RARE = 3
    LEGEND_RARE = 4


class Rarity(enum.Enum):
    NORMAL = 0
    SPECIAL = 1
    RARE = 2
    SUPER_RARE = 3
    UBER_RARE = 4
    LEGEND_RARE = 5


class UnitBuyData:
    def __init__(self, cat_id: int, raw_data: list[int]):
        self.cat_id = cat_id
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def extend(self, raw_data: list[int]) -> list[int]:
        length = 63
        raw_data = raw_data + [0] * (length - len(raw_data))
        return raw_data

    def assign(self, raw_data: list[int]):
        self.stage_unlock = raw_data[0]
        self.purchase_cost = raw_data[1]
        self.upgrade_costs = raw_data[2:12]
        self.unlock_source = raw_data[12]
        self.rarity = Rarity(raw_data[13])
        self.position_order = raw_data[14]
        self.chapter_unlock = raw_data[15]
        self.sell_price = raw_data[16]
        self.gatya_rarity = GatchaRarity(raw_data[17])
        self.original_max_level = raw_data[18]
        self.unknown_19 = raw_data[19]
        self.force_true_form_level = raw_data[20]
        self.second_form_levels = raw_data[21], raw_data[22]
        self.true_form_id = raw_data[23]
        self.unknown_24 = raw_data[24]
        self.third_form_levels = raw_data[25], raw_data[26]
        self.evolve_cost = raw_data[27]
        self.evolve_items = unit.EvolveItems.from_unit_buy_list(raw_data)
        self.unknown_48 = raw_data[48]
        self.max_upgrade_level_no_catseye = raw_data[49]
        self.max_upgrade_level_catseye = raw_data[50]
        self.max_plus_upgrade_level = raw_data[51]
        self.unknown_52 = raw_data[52]
        self.unknown_53 = raw_data[53]
        self.unknown_54 = raw_data[54]
        self.unknown_55 = raw_data[55]
        self.evolve_count = raw_data[56]
        self.game_version = raw_data[57]
        self.np_sell_price = raw_data[58]
        self.unknown_59 = raw_data[59]
        self.unknown_60 = raw_data[60]
        self.unknown_61 = raw_data[61]
        self.unknown_62 = raw_data[62]

    def to_raw_data(self) -> list[int]:
        return [
            self.stage_unlock,
            self.purchase_cost,
            *self.upgrade_costs,
            self.unlock_source,
            self.rarity.value,
            self.position_order,
            self.chapter_unlock,
            self.sell_price,
            self.gatya_rarity.value,
            self.original_max_level,
            self.unknown_19,
            self.force_true_form_level,
            *self.second_form_levels,
            self.true_form_id,
            self.unknown_24,
            *self.third_form_levels,
            self.evolve_cost,
            *self.evolve_items.to_list(),
            self.unknown_48,
            self.max_upgrade_level_no_catseye,
            self.max_upgrade_level_catseye,
            self.max_plus_upgrade_level,
            self.unknown_52,
            self.unknown_53,
            self.unknown_54,
            self.unknown_55,
            self.evolve_count,
            self.game_version,
            self.np_sell_price,
            self.unknown_59,
            self.unknown_60,
            self.unknown_61,
            self.unknown_62,
        ]

    def serialize(self) -> dict[str, Any]:
        return {
            "raw_data": self.to_raw_data(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int) -> "UnitBuyData":
        return UnitBuyData(cat_id, data["raw_data"])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnitBuyData):
            return False
        return self.to_raw_data() == other.to_raw_data()

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class UnitBuy:
    def __init__(self, unit_buy_data: dict[int, UnitBuyData]):
        self.unit_buy_data = unit_buy_data

    def serialize(self) -> dict[str, Any]:
        return {
            "unit_buy_data": {
                cat_id: unit_buy_data.serialize()
                for cat_id, unit_buy_data in self.unit_buy_data.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "UnitBuy":
        return UnitBuy(
            {
                cat_id: UnitBuyData.deserialize(unit_buy_data, cat_id)
                for cat_id, unit_buy_data in data["unit_buy_data"].items()
            }
        )

    @staticmethod
    def get_file_name() -> str:
        return "unitbuy.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "UnitBuy":
        file = game_data.find_file(UnitBuy.get_file_name())
        if file is None:
            return UnitBuy.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        unit_buy_data: dict[int, UnitBuyData] = {}
        for i, line in enumerate(csv.lines):
            unit_buy_data[i] = UnitBuyData(i, io.data.Data.data_list_int_list(line))
        return UnitBuy(unit_buy_data)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(UnitBuy.get_file_name())
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        for i in range(len(csv.lines)):
            if i not in self.unit_buy_data:
                continue
            csv.set_line(i, self.unit_buy_data[i].to_raw_data())

        game_data.set_file(UnitBuy.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        self.unit_buy_data[cat.cat_id] = cat.unit_buy_data

    @staticmethod
    def create_empty() -> "UnitBuy":
        return UnitBuy({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnitBuy):
            return False
        return self.unit_buy_data == other.unit_buy_data

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Talent:
    def __init__(self, cat_id: int, raw_data: list[int]):
        self.cat_id = cat_id
        self.raw_data = raw_data

    def serialize(self) -> dict[str, Any]:
        return {
            "raw_data": self.raw_data,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int) -> "Talent":
        return Talent(cat_id, data["raw_data"])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Talent):
            return False
        return self.raw_data == other.raw_data

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Talents:
    def __init__(self, talents: dict[int, Talent]):
        self.talents = talents

    def serialize(self) -> dict[str, Any]:
        return {
            "talents": {
                cat_id: talent.serialize() for cat_id, talent in self.talents.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Talents":
        return Talents(
            {
                cat_id: Talent.deserialize(talent_data, cat_id)
                for cat_id, talent_data in data["talents"].items()
            }
        )

    @staticmethod
    def get_file_name() -> str:
        return "SkillAcquisition.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Talents":
        file = game_data.find_file(Talents.get_file_name())
        if file is None:
            return Talents.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        talents: dict[int, Talent] = {}
        for line in csv.lines[1:]:
            cat_id = line[0].to_int()
            talents[cat_id] = Talent(cat_id, io.data.Data.data_list_int_list(line[1:]))

        return Talents(talents)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(Talents.get_file_name())
        if file is None:
            return None

        remanining_cats = self.talents.copy()
        csv = io.bc_csv.CSV(file.dec_data)
        for i, line in enumerate(csv.lines[1:]):
            cat_id = line[0].to_int()
            if cat_id not in self.talents:
                continue
            d_line = [cat_id]
            d_line.extend(self.talents[cat_id].raw_data)
            csv.set_line(i + 1, d_line)
            del remanining_cats[cat_id]

        for cat_id, talent in remanining_cats.items():
            a_line = [cat_id]
            a_line.extend(talent.raw_data)
            csv.add_line(a_line)

        game_data.set_file(Talents.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        if cat.talent is None:
            return
        self.talents[cat.cat_id] = cat.talent

    @staticmethod
    def create_empty() -> "Talents":
        return Talents({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Talents):
            return False
        return self.talents == other.talents

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class NyankoPictureBookData:
    def __init__(
        self,
        cat_id: int,
        obtainable: bool,
        limited: bool,
        total_forms: int,
        unknown: int,
        scale_0: int,
        scale_1: int,
        scale_2: int,
        scale_3: int,
        other: list[int],
    ):
        self.cat_id = cat_id
        self.obtainable = obtainable
        self.limited = limited
        self.total_forms = total_forms
        self.unknown = unknown
        self.scale_0 = scale_0
        self.scale_1 = scale_1
        self.scale_2 = scale_2
        self.scale_3 = scale_3
        self.other = other

    def serialize(self) -> dict[str, Any]:
        return {
            "obtainable": self.obtainable,
            "limited": self.limited,
            "total_forms": self.total_forms,
            "unknown": self.unknown,
            "scale_0": self.scale_0,
            "scale_1": self.scale_1,
            "scale_2": self.scale_2,
            "scale_3": self.scale_3,
            "other": self.other,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int) -> "NyankoPictureBookData":
        return NyankoPictureBookData(
            cat_id,
            data["obtainable"],
            data["limited"],
            data["total_forms"],
            data["unknown"],
            data["scale_0"],
            data["scale_1"],
            data["scale_2"],
            data["scale_3"],
            data["other"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NyankoPictureBookData):
            return False
        return self.serialize() == other.serialize()

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class NyankoPictureBook:
    def __init__(self, data: dict[int, NyankoPictureBookData]):
        self.data = data

    def serialize(self) -> dict[str, Any]:
        return {
            "data": {cat_id: data.serialize() for cat_id, data in self.data.items()}
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "NyankoPictureBook":
        return NyankoPictureBook(
            {
                cat_id: NyankoPictureBookData.deserialize(data, cat_id)
                for cat_id, data in data["data"].items()
            }
        )

    @staticmethod
    def get_file_name() -> str:
        return "nyankoPictureBookData.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "NyankoPictureBook":
        file = game_data.find_file(NyankoPictureBook.get_file_name())
        if file is None:
            return NyankoPictureBook.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        data: dict[int, NyankoPictureBookData] = {}
        for cat_id, line in enumerate(csv.lines):
            data[cat_id] = NyankoPictureBookData(
                cat_id,
                line[0].to_bool(),
                line[1].to_bool(),
                line[2].to_int(),
                line[3].to_int(),
                line[4].to_int(),
                line[5].to_int(),
                line[6].to_int(),
                line[7].to_int(),
                io.data.Data.data_list_int_list(line[8:]),
            )
        return NyankoPictureBook(data)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(NyankoPictureBook.get_file_name())
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        for data in self.data.values():
            line: list[Any] = []
            line.append(data.obtainable)
            line.append(data.limited)
            line.append(data.total_forms)
            line.append(data.unknown)
            line.append(data.scale_0)
            line.append(data.scale_1)
            line.append(data.scale_2)
            line.append(data.scale_3)
            line.extend(data.other)
            csv.set_line(data.cat_id, line)

        game_data.set_file(NyankoPictureBook.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        self.data[cat.cat_id] = cat.nyanko_picture_book_data

    @staticmethod
    def create_empty() -> "NyankoPictureBook":
        return NyankoPictureBook({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NyankoPictureBook):
            return False
        return self.data == other.data

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class EvolveText:
    def __init__(self, text: dict[int, list[str]]):
        self.text = text

    def serialize(self) -> dict[str, Any]:
        return {"text": {cat_id: text for cat_id, text in self.text.items()}}

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "EvolveText":
        return EvolveText({cat_id: text for cat_id, text in data["text"].items()})

    @staticmethod
    def get_file_name(cc: "country_code.CountryCode") -> str:
        return f"unitevolve_{cc.get_language()}.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "EvolveText":
        file = game_data.find_file(EvolveText.get_file_name(game_data.country_code))
        if file is None:
            return EvolveText.create_empty()

        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        text: dict[int, list[str]] = {}
        for cat_id, line in enumerate(csv.lines):
            text[cat_id] = io.data.Data.data_list_string_list(line)
        return EvolveText(text)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(EvolveText.get_file_name(game_data.country_code))
        if file is None:
            return None

        csv = io.bc_csv.CSV(
            file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        for cat_id, line in self.text.items():
            csv.set_line(cat_id, line)

        game_data.set_file(
            EvolveText.get_file_name(game_data.country_code), csv.to_data()
        )

    def set(self, cat: "Cat"):
        self.text[cat.cat_id] = cat.evolve_text

    @staticmethod
    def create_empty() -> "EvolveText":
        return EvolveText({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EvolveText):
            return False
        return self.text == other.text

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class Cat:
    def __init__(
        self,
        cat_id: int,
        forms: dict[FormType, Form],
        unit_buy_data: UnitBuyData,
        talent: Optional["Talent"],
        nyanko_picture_book_data: NyankoPictureBookData,
        evolve_text: list[str],
    ):
        if isinstance(cat_id, str):
            raise ValueError("cat_id must be an int")
        self.cat_id = cat_id
        self.forms = forms
        self.unit_buy_data = unit_buy_data
        self.talent = talent
        self.nyanko_picture_book_data = nyanko_picture_book_data
        self.evolve_text = evolve_text

    def serialize(self) -> dict[str, Any]:
        return {
            "forms": {
                form.form.value: form.serialize() for form in self.forms.values()
            },
            "unit_buy_data": self.unit_buy_data.serialize(),
            "talent": self.talent.serialize() if self.talent is not None else None,
            "nyanko_picture_book_data": self.nyanko_picture_book_data.serialize(),
            "evolve_text": self.evolve_text,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cat_id: int) -> "Cat":
        return Cat(
            cat_id,
            {
                FormType(form): Form.deserialize(form_data, cat_id, FormType(form))
                for form, form_data in data["forms"].items()
            },
            UnitBuyData.deserialize(data["unit_buy_data"], cat_id),
            Talent.deserialize(data["talent"], cat_id)
            if data["talent"] is not None
            else None,
            NyankoPictureBookData.deserialize(data["nyanko_picture_book_data"], cat_id),
            data["evolve_text"],
        )

    @staticmethod
    def get_stat_file_name(cat_id: int):
        return f"unit{io.data.PaddedInt(cat_id+1, 3)}.csv"

    @staticmethod
    def get_name_file_name(cat_id: int, cc: "country_code.CountryCode"):
        return f"Unit_Explanation{cat_id+1}_{cc.get_language()}.csv"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
        cat_id: int,
        unit_buy: UnitBuy,
        talents: Talents,
        nyanko_picture_book: NyankoPictureBook,
        evolve_text: EvolveText,
    ) -> Optional["Cat"]:
        stat_file = game_data.find_file(Cat.get_stat_file_name(cat_id))
        name_file = game_data.find_file(
            Cat.get_name_file_name(cat_id, game_data.country_code)
        )
        if stat_file is None:
            return None
        stat_csv = stat_file.dec_data.to_csv()
        if name_file is None:
            name_csv = io.bc_csv.CSV(
                delimeter=io.bc_csv.Delimeter.from_country_code_res(
                    game_data.country_code
                ),
                remove_empty=False,
            )
        else:
            name_csv = name_file.dec_data.to_csv(
                delimeter=io.bc_csv.Delimeter.from_country_code_res(
                    game_data.country_code
                ),
                remove_empty=False,
            )
        unit_buy_data = unit_buy.unit_buy_data.get(cat_id)
        talent = talents.talents.get(cat_id)
        nyanko_picture_book_data = nyanko_picture_book.data.get(cat_id)
        evt = evolve_text.text.get(cat_id)
        if unit_buy_data is None or nyanko_picture_book_data is None or evt is None:
            return None
        forms: dict[FormType, Form] = {}
        total_forms = nyanko_picture_book_data.total_forms
        form_count = 0
        for form in FormType:
            if form_count >= total_forms:
                break
            try:
                stats = Stats(
                    cat_id,
                    form,
                    io.data.Data.data_list_int_list(stat_csv.get_row(form.get_index())),
                )
            except IndexError:
                continue
            try:
                row = name_csv.get_row(form.get_index())
            except IndexError:
                continue
            name = row[0].to_str()
            description = io.data.Data.data_list_string_list(row[1:])
            anim = Anim.from_game_data(game_data, cat_id, form)
            if anim is None:
                continue
            icons = Form.get_icons_game_data(game_data, cat_id, form)
            if icons is None:
                continue
            upgrade_icon, deploy_icon = icons
            forms[form] = Form(
                cat_id, form, stats, name, description, anim, upgrade_icon, deploy_icon
            )
            form_count += 1
        return Cat(cat_id, forms, unit_buy_data, talent, nyanko_picture_book_data, evt)

    def to_game_data(self, game_data: "pack.GamePacks"):
        stat_file = game_data.find_file(Cat.get_stat_file_name(self.cat_id))
        name_file = game_data.find_file(
            Cat.get_name_file_name(self.cat_id, game_data.country_code)
        )
        if stat_file is None or name_file is None:
            return None
        stat_csv = stat_file.dec_data.to_csv()
        name_csv = name_file.dec_data.to_csv(
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code)
        )
        for form_type, form in self.forms.items():
            stat_csv.set_line(
                form_type.get_index(),
                io.data.Data.int_list_data_list(form.stats.to_raw_data()),
            )
            row = [io.data.Data(form.name)]
            row.extend(io.data.Data.string_list_data_list(form.description))
            name_csv.set_line(form_type.get_index(), row)
            form.anim.to_game_data(game_data)
            form.icons_to_game_data(game_data)

        game_data.set_file(Cat.get_stat_file_name(self.cat_id), stat_csv.to_data())
        game_data.set_file(
            Cat.get_name_file_name(self.cat_id, game_data.country_code),
            name_csv.to_data(),
        )

    def get_form(self, form: Union[FormType, int]) -> Optional[Form]:
        if isinstance(form, int):
            form = FormType.from_index(form)
        return self.forms.get(form)

    def set_form(self, form: Union[FormType, int], value: Form):
        if isinstance(form, int):
            form = FormType.from_index(form)
        value.form = form
        value.set_cat_id(self.cat_id)
        self.forms[form] = value

    def set_cat_id(self, cat_id: int):
        self.cat_id = cat_id
        for form in self.forms.values():
            form.set_cat_id(cat_id)
        self.unit_buy_data.cat_id = cat_id
        if self.talent is not None:
            self.talent.cat_id = cat_id
        self.nyanko_picture_book_data.cat_id = cat_id

    def __eq__(self, other: object):
        if not isinstance(other, Cat):
            return False
        return (
            self.cat_id == other.cat_id
            and self.forms == other.forms
            and self.unit_buy_data == other.unit_buy_data
            and self.talent == other.talent
            and self.nyanko_picture_book_data == other.nyanko_picture_book_data
            and self.evolve_text == other.evolve_text
        )

    def __ne__(self, other: object):
        return not self == other


class Cats:
    def __init__(self, cats: dict[int, Cat]):
        self.cats = cats

    def serialize(self) -> dict[str, Any]:
        return {
            "cats": {cat.cat_id: cat.serialize() for cat in self.cats.values()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Cats":
        return Cats(
            {cat: Cat.deserialize(data["cats"][cat], int(cat)) for cat in data["cats"]},
        )

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks", cat_ids: Optional[list[int]] = None
    ) -> "Cats":
        cats: dict[int, Cat] = {}
        unit_buy = UnitBuy.from_game_data(game_data)
        talents = Talents.from_game_data(game_data)
        nyan = NyankoPictureBook.from_game_data(game_data)
        evov_text = EvolveText.from_game_data(game_data)
        total_cats = len(nyan.data)
        if cat_ids is None:
            cat_ids = list(range(total_cats))
        for cat_id in cat_ids:
            cat = Cat.from_game_data(
                game_data, cat_id, unit_buy, talents, nyan, evov_text
            )
            if cat is None:
                continue
            cats[cat_id] = cat
        return Cats(cats)

    def to_game_data(self, game_data: "pack.GamePacks"):
        unit_buy = UnitBuy({})
        talents = Talents({})
        nyan = NyankoPictureBook({})
        evov_text = EvolveText({})
        for cat in self.cats.values():
            cat.to_game_data(game_data)
            unit_buy.set(cat)
            talents.set(cat)
            nyan.set(cat)
            evov_text.set(cat)
        unit_buy.to_game_data(game_data)
        talents.to_game_data(game_data)
        nyan.to_game_data(game_data)
        evov_text.to_game_data(game_data)

    def get_cat(self, cat_id: int) -> Optional[Cat]:
        return self.cats.get(cat_id)

    def set_cat(self, cat: Cat):
        self.cats[cat.cat_id] = cat

    @staticmethod
    def get_cats_json_file_name() -> "io.path.Path":
        return io.path.Path("catbase").add("cats.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        cats_json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(Cats.get_cats_json_file_name(), cats_json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Cats":
        cats_json = zip.get_file(Cats.get_cats_json_file_name())
        if cats_json is None:
            return Cats.create_empty()
        return Cats.deserialize(io.json_file.JsonFile.from_data(cats_json).get_json())

    @staticmethod
    def create_empty() -> "Cats":
        return Cats({})

    def import_cats(self, other: "Cats", game_data: "pack.GamePacks"):
        gd_cats = Cats.from_game_data(game_data)
        all_keys = set(self.cats.keys())
        all_keys.update(other.cats.keys())
        all_keys.update(gd_cats.cats.keys())
        for cat_id in all_keys:
            other_cat = other.get_cat(cat_id)
            gd_cat = gd_cats.get_cat(cat_id)
            if other_cat is None:
                continue
            if gd_cat is not None:
                if gd_cat != other_cat:
                    self.cats[cat_id] = gd_cat
            else:
                self.cats[cat_id] = other_cat
