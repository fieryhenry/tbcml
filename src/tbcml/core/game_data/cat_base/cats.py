import enum
from typing import Any, Optional, Union

from tbcml import core


class CatFormType(enum.Enum):
    """Represents the different forms a cat has."""

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


class CatStats:
    """Represents the stats of a cat."""

    hp: Optional[int]
    """The HP of the cat.Index 0."""
    kbs: Optional[int]
    """The number of knockbacks the cat has. Index 1."""
    speed: Optional[int]
    """The movement speed of the cat, real value is 2x what is stored. Index 2."""
    attack_interval: Optional["core.Frames"]
    """The interval between attacks of the cat, real value is 2x what is stored. Index 4."""
    range: Optional[int]
    """The attack range of the cat. real value is 4x what is stored. Index 5."""
    cost: Optional[int]
    """The cost of the cat to deploy. Index 6."""
    recharge_time: Optional["core.Frames"]
    """The time it takes for the cat to recharge after being used, real value is 2x what is stored. Index 7."""
    collision_start: Optional[int]
    """The X coordinate of the start of the collision box of the cat. Index 8."""
    collision_width: Optional[int]
    """The width of the collision box, real value is 4x what is stored. Seemingly unused? Index 9."""
    target_red: Optional[bool]
    """Whether the cat has the target red trait. Index 10."""
    unused: Optional[int]
    """Unused. Index 11."""
    area_attack: Optional[bool]
    """Whether the cat has the area attack ability. Index 12."""
    z_layers: "core.ZLayers"
    """The Z layers of the cat. Index 14 min layer and index 15 max layer."""
    target_floating: Optional[bool]
    """Whether the cat has the target floating trait. Index 16."""
    target_black: Optional[bool]
    """Whether the cat has the target black trait. Index 17."""
    target_metal: Optional[bool]
    """Whether the cat has the target metal trait. Index 18."""
    target_traitless: Optional[bool]
    """Whether the cat has the target traitless trait. Index 19."""
    target_angel: Optional[bool]
    """Whether the cat has the target angel trait. Index 20."""
    target_alien: Optional[bool]
    """Whether the cat has the target alien trait. Index 21."""
    target_zombie: Optional[bool]
    """Whether the cat has the target zombie trait. Index 22."""
    strong: Optional[bool]
    """Whether the cat has the strong against ability. Index 23."""
    knockback: "core.Knockback"
    """The probability of knockback. Index 24."""
    freeze: "core.Freeze"
    """The probability and duration of a freeze attack. Index 25 and 26."""
    slow: "core.Slow"
    """The probability and duration of a slow attack. Index 27 and 28."""
    resistant: Optional[bool]
    """Whether the cat has the resistant against ability. Index 29."""
    massive_damage: Optional[bool]
    """Whether the cat has the massive damage ability. Index 30."""
    crit: "core.Crit"
    """The probability of a crit attack. Index 31."""
    attacks_only: Optional[bool]
    """Whether the cat has the attacks only ability. Index 32."""
    extra_money: Optional[bool]
    """Whether the cat has the extra money ability. Index 33."""
    base_destroyer: Optional[bool]
    """Whether the cat has the base destroyer ability. Index 34."""
    wave: "core.Wave"
    """The wave attack of the cat.
    Probability: Index 35
    Level: Index 36
    IsMini: Index 94
    """
    weaken: "core.Weaken"
    """The weaken attack of the cat.
    Probability: Index 37
    Duration: Index 38
    Percentage: Index 39
    """
    strengthen: "core.Strengthen"
    """The strengthen ability of the cat.
    HP percentage to activate: Index 40
    HP percentage to strengthen: Index 41
    """
    lethal_strike: "core.LethalStrike"
    """The probability of a lethal strike attack. Index 42."""
    is_metal: Optional[bool]
    """Whether the cat is metal. Index 43."""
    wave_immunity: Optional[bool]
    """Whether the cat has the wave immunity ability. Index 46."""
    wave_blocker: Optional[bool]
    """Whether the cat has the wave blocker ability. Index 47."""
    knockback_immunity: Optional[bool]
    """Whether the cat has the knockback immunity ability. Index 48."""
    freeze_immunity: Optional[bool]
    """Whether the cat has the freeze immunity ability. Index 49."""
    slow_immunity: Optional[bool]
    """Whether the cat has the slow immunity ability. Index 50."""
    weaken_immunity: Optional[bool]
    """Whether the cat has the weaken immunity ability. Index 51."""
    zombie_killer: Optional[bool]
    """Whether the cat has the zombie killer ability. Index 52."""
    witch_killer: Optional[bool]
    """Whether the cat has the witch killer ability. Index 53."""
    target_witch: Optional[bool]
    """Whether the cat has the target witch trait. Index 54."""
    attack_state: "core.AttackState"
    """The attack state of the cat.
    Attacks before state change: Index 55
    State: Index 58
    """
    time_before_death: Optional["core.Frames"]
    """The time before the cat dies after being knocked back. Index 57."""

    attack_1: "core.Attack"
    """The first attack of the cat.
    Attack: Index 3
    Foreswing: Index 13
    Use Ability: Index 63
    LongDistanceFlag: True
    LongDistanceStartRange: Index 44
    LongDistanceRangeRange: Index 45"""
    attack_2: "core.Attack"
    """The second attack of the cat.
    Attack: Index 59
    Foreswing: Index 61
    Use Ability: Index 64
    LogDistanceFlag: Index 99
    LongDistanceStartRange: Index 100
    LongDistanceRangeRange: Index 101"""
    attack_3: "core.Attack"
    """The third attack of the cat.
    Attack: Index 60
    Foreswing: Index 62
    Use Ability: Index 65
    LongDistanceFlag: Index 102
    LongDistanceStartRange: Index 103
    LongDistanceRangeRange: Index 104"""
    spawn_anim: "core.SpawnAnim"
    """The spawn animation of the cat.
    ModelID: Index 66
    HasEntryMaanim: Index 68
    """
    soul_anim: "core.SoulAnim"
    """The soul animation of the cat.
    ModelID: Index 67
    HasDeathMaanim: Index 69
    """
    barrier_breaker: "core.BarrierBreak"
    """The barrier break ability of the cat.
    Probability: Index 70
    """
    warp: "core.Warp"
    """The warp ability of the cat.
    Probability: Index 71
    duration: Index 72
    min range: Index 73
    max range: Index 74
    """
    warp_blocker: Optional[bool]
    """Whether the cat has the warp blocker ability. Index 75."""
    target_eva: Optional[bool]
    """Whether the cat has the target eva trait. Index 76."""
    eva_killer: Optional[bool]
    """Whether the cat has the eva killer ability. Index 77."""
    target_relic: Optional[bool]
    """Whether the cat has the target relic trait. Index 78."""
    curse_immunity: Optional[bool]
    """Whether the cat has the curse immunity ability. Index 79."""
    insanely_tough: Optional[bool]
    """Whether the cat has the insanely tough ability. Index 80."""
    insane_damage: Optional[bool]
    """Whether the cat has the insane damage ability. Index 81."""
    savage_blow: "core.SavageBlow"
    """The savage blow ability of the cat.
    Probability: Index 82
    Damage Addition: Index 83
    """
    dodge: "core.Dodge"
    """The dodge ability of the cat.
    Probability: Index 84
    Duration: Index 85
    """
    surge: "core.Surge"
    """The surge ability of the cat.
    Probability: Index 86
    start range: Index 87
    range range: Index 88
    level: Index 89
    """
    toxic_immunity: Optional[bool]
    """Whether the cat has the toxic immunity ability. Index 90."""
    surge_immunity: Optional[bool]
    """Whether the cat has the surge immunity ability. Index 91."""
    curse: "core.Curse"
    """The curse ability of the cat.
    Probability: Index 92
    Duration: Index 93
    """
    shield_pierce: "core.ShieldPierce"
    """The shield pierce ability of the cat.
    Probability: Index 95
    """
    target_aku: Optional[bool]
    """Whether the cat has the target aku trait. Index 96."""
    collossus_slayer: Optional[bool]
    """Whether the cat has the collossus slayer ability. Index 97."""
    soul_strike: Optional[bool]
    """Whether the cat has the soul strike ability. Index 98."""
    behemoth_slayer: Optional[bool]
    """Whether the cat has the behemoth slayer ability. Index 105."""
    behemoth_dodge: "core.BehemothDodge"
    """The behemoth dodge ability of the cat.
    Probability: Index 106
    Duration: Index 107
    """

    def __init__(self, cat_id: int, form: CatFormType, raw_data: list[Optional[int]]):
        """Initialize a new Stats object.

        Args:
            cat_id (int): The ID of the cat.
            form (FormType): The form of the cat.
            raw_data (list[int]): The raw stats data.
        """
        self.cat_id = cat_id
        self.form = form
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def extend(self, raw_data: list[Optional[int]]) -> list[Optional[int]]:
        """Extend the raw stats data to the max length.

        Args:
            raw_data (list[int]): The raw stats data.

        Returns:
            list[int]: The extended raw stats data.
        """
        length = 109
        amount = length - len(raw_data)
        required = (
            [55, -1],
            [57, -1],
            [63, 1],
            [66, -1],
        )
        original_length = len(raw_data)

        raw_data = raw_data + [None] * amount
        for index, value in required:
            if index < original_length:
                continue
            raw_data[index] = value

        return raw_data

    def assign(self, raw_data: list[Optional[int]]):
        self.hp = raw_data[0]
        self.kbs = raw_data[1]
        self.speed = raw_data[2]
        self.attack_interval = core.Frames.from_pair_frames(raw_data[4])
        self.range = raw_data[5]
        self.cost = raw_data[6]
        self.recharge_time = core.Frames.from_pair_frames(raw_data[7])
        self.collision_start = raw_data[8]
        self.collision_width = raw_data[9]
        self.target_red = core.unit_bool(raw_data[10])
        self.unused = raw_data[11]
        self.area_attack = core.unit_bool(raw_data[12])
        self.z_layers = core.ZLayers.from_values(raw_data[14], raw_data[15])
        self.target_floating = core.unit_bool(raw_data[16])
        self.target_black = core.unit_bool(raw_data[17])
        self.target_metal = core.unit_bool(raw_data[18])
        self.target_traitless = core.unit_bool(raw_data[19])
        self.target_angel = core.unit_bool(raw_data[20])
        self.target_alien = core.unit_bool(raw_data[21])
        self.target_zombie = core.unit_bool(raw_data[22])
        self.strong = core.unit_bool(raw_data[23])
        self.knockback = core.Knockback.from_values(raw_data[24])
        self.freeze = core.Freeze.from_values(raw_data[25], raw_data[26])
        self.slow = core.Slow.from_values(raw_data[27], raw_data[28])
        self.resistant = core.unit_bool(raw_data[29])
        self.massive_damage = core.unit_bool(raw_data[30])
        self.crit = core.Crit.from_values(raw_data[31])
        self.attacks_only = core.unit_bool(raw_data[32])
        self.extra_money = core.unit_bool(raw_data[33])
        self.base_destroyer = core.unit_bool(raw_data[34])
        self.wave = core.Wave.from_values(raw_data[35], raw_data[36], raw_data[94])
        self.weaken = core.Weaken.from_values(raw_data[37], raw_data[38], raw_data[39])
        self.strengthen = core.Strengthen.from_values(raw_data[40], raw_data[41])
        self.lethal_strike = core.LethalStrike.from_values(raw_data[42])
        self.is_metal = core.unit_bool(raw_data[43])
        self.wave_immunity = core.unit_bool(raw_data[46])
        self.wave_blocker = core.unit_bool(raw_data[47])
        self.knockback_immunity = core.unit_bool(raw_data[48])
        self.freeze_immunity = core.unit_bool(raw_data[49])
        self.slow_immunity = core.unit_bool(raw_data[50])
        self.weaken_immunity = core.unit_bool(raw_data[51])
        self.zombie_killer = core.unit_bool(raw_data[52])
        self.witch_killer = core.unit_bool(raw_data[53])
        self.target_witch = core.unit_bool(raw_data[54])
        self.shockwave_immune = core.unit_bool(raw_data[56])
        self.time_before_death = core.Frames(raw_data[57]) if raw_data[57] else None
        self.attack_state = core.AttackState.from_values(raw_data[55], raw_data[58])
        self.attack_1 = core.Attack.from_values(
            raw_data[3],
            raw_data[13],
            raw_data[63],
            True,
            raw_data[44],
            raw_data[45],
        )
        self.attack_2 = core.Attack.from_values(
            raw_data[59],
            raw_data[61],
            raw_data[64],
            raw_data[99],
            raw_data[100],
            raw_data[101],
        )
        self.attack_3 = core.Attack.from_values(
            raw_data[60],
            raw_data[62],
            raw_data[65],
            raw_data[102],
            raw_data[103],
            raw_data[104],
        )
        self.spawn_anim = core.SpawnAnim.from_values(raw_data[66], raw_data[68])
        self.soul_anim = core.SoulAnim.from_values(raw_data[67], raw_data[69])
        self.barrier_breaker = core.BarrierBreak.from_values(raw_data[70])
        self.warp = core.Warp.from_values(
            raw_data[71], raw_data[72], raw_data[73], raw_data[74]
        )
        self.warp_blocker = core.unit_bool(raw_data[75])
        self.target_eva = core.unit_bool(raw_data[76])
        self.eva_killer = core.unit_bool(raw_data[77])
        self.target_relic = core.unit_bool(raw_data[78])
        self.curse_immunity = core.unit_bool(raw_data[79])
        self.insanely_tough = core.unit_bool(raw_data[80])
        self.insane_damage = core.unit_bool(raw_data[81])
        self.savage_blow = core.SavageBlow.from_values(raw_data[82], raw_data[83])
        self.dodge = core.Dodge.from_values(raw_data[84], raw_data[85])
        self.surge = core.Surge.from_values(
            raw_data[86], raw_data[87], raw_data[88], raw_data[89]
        )
        self.toxic_immunity = core.unit_bool(raw_data[90])
        self.surge_immunity = core.unit_bool(raw_data[91])
        self.curse = core.Curse.from_values(raw_data[92], raw_data[93])
        self.shield_pierce = core.ShieldPierce.from_values(raw_data[95])
        self.target_aku = core.unit_bool(raw_data[96])
        self.collossus_slayer = core.unit_bool(raw_data[97])
        self.soul_strike = core.unit_bool(raw_data[98])
        self.behemoth_slayer = core.unit_bool(raw_data[105])
        self.behemoth_dodge = core.BehemothDodge.from_values(
            raw_data[106], raw_data[107]
        )
        self.unknown_108 = raw_data[108]

    def to_raw_data(self) -> list[Optional[int]]:
        return [
            self.hp,  # 0
            self.kbs,  # 1
            self.speed,  # 2
            self.attack_1.damage,  # 3
            self.attack_interval.pair_frames
            if self.attack_interval is not None
            else None,  # 4
            self.range,  # 5
            self.cost,  # 6
            self.recharge_time.pair_frames
            if self.recharge_time is not None
            else None,  # 7
            self.collision_start,  # 8
            self.collision_width,  # 9
            core.unit_int(self.target_red),  # 10
            self.unused,  # 11
            core.unit_int(self.area_attack),  # 12
            self.attack_1.foreswing.frames
            if self.attack_1 and self.attack_1.foreswing
            else None,  # 13
            self.z_layers.min if self.z_layers else None,  # 14
            self.z_layers.max if self.z_layers else None,  # 15
            core.unit_int(self.target_floating),  # 16
            core.unit_int(self.target_black),  # 17
            core.unit_int(self.target_metal),  # 18
            core.unit_int(self.target_traitless),  # 19
            core.unit_int(self.target_angel),  # 20
            core.unit_int(self.target_alien),  # 21
            core.unit_int(self.target_zombie),  # 22
            core.unit_int(self.strong),  # 23
            self.knockback.prob.percent
            if self.knockback.prob is not None
            else None,  # 24
            self.freeze.prob.percent if self.freeze.prob is not None else None,  # 25
            self.freeze.time.frames
            if self.freeze and self.freeze.time is not None
            else None,  # 26
            self.slow.prob.percent
            if self.slow and self.slow.prob is not None
            else None,  # 27
            self.slow.time.frames
            if self.slow and self.slow.time is not None
            else None,  # 28
            core.unit_int(self.resistant),  # 29
            core.unit_int(self.massive_damage),  # 30
            self.crit.prob.percent if self.crit.prob is not None else None,  # 31
            core.unit_int(self.attacks_only),  # 32
            core.unit_int(self.extra_money),  # 33
            core.unit_int(self.base_destroyer),  # 34
            self.wave.prob.percent if self.wave.prob is not None else None,  # 35
            self.wave.level,  # 36
            self.weaken.prob.percent if self.weaken.prob is not None else None,  # 37
            self.weaken.time.frames if self.weaken.time is not None else None,  # 38
            self.weaken.multiplier,  # 39
            self.strengthen.hp_percent,  # 40
            self.strengthen.multiplier_percent,  # 41
            self.lethal_strike.prob.percent
            if self.lethal_strike.prob is not None
            else None,  # 42
            core.unit_int(self.is_metal),  # 43
            self.attack_1.long_distance_start,  # 44
            self.attack_1.long_distance_range,  # 45
            core.unit_int(self.wave_immunity),  # 46
            core.unit_int(self.wave_blocker),  # 47
            core.unit_int(self.knockback_immunity),  # 48
            core.unit_int(self.freeze_immunity),  # 49
            core.unit_int(self.slow_immunity),  # 50
            core.unit_int(self.weaken_immunity),  # 51
            core.unit_int(self.zombie_killer),  # 52
            core.unit_int(self.witch_killer),  # 53
            core.unit_int(self.target_witch),  # 54
            self.attack_state.attacks_before,  # 55
            core.unit_int(self.shockwave_immune),  # 56
            self.time_before_death.frames
            if self.time_before_death is not None
            else None,  # 57
            self.attack_state.state_id,  # 58
            self.attack_2.damage,  # 59
            self.attack_3.damage,  # 60
            self.attack_2.foreswing.frames
            if self.attack_2.foreswing is not None
            else None,  # 61
            self.attack_3.foreswing.frames
            if self.attack_3.foreswing is not None
            else None,  # 62
            core.unit_int(self.attack_1.use_ability),  # 63
            core.unit_int(self.attack_2.use_ability),  # 64
            core.unit_int(self.attack_3.use_ability),  # 65
            self.spawn_anim.model_id,  # 66
            self.soul_anim.model_id,  # 67
            core.unit_int(self.spawn_anim.has_entry_maanim),  # 68
            core.unit_int(self.soul_anim.has_death_maanim),  # 69
            self.barrier_breaker.prob.percent
            if self.barrier_breaker.prob is not None
            else None,  # 70
            self.warp.prob.percent if self.warp.prob is not None else None,  # 71
            self.warp.time.frames if self.warp.time is not None else None,  # 72
            self.warp.min_distance,  # 73
            self.warp.max_distance,  # 74
            core.unit_int(self.warp_blocker),  # 75
            core.unit_int(self.target_eva),  # 76
            core.unit_int(self.eva_killer),  # 77
            core.unit_int(self.target_relic),  # 78
            core.unit_int(self.curse_immunity),  # 79
            core.unit_int(self.insanely_tough),  # 80
            core.unit_int(self.insane_damage),  # 81
            self.savage_blow.prob.percent
            if self.savage_blow.prob is not None
            else None,  # 82
            self.savage_blow.multiplier,  # 83
            self.dodge.prob.percent if self.dodge.prob is not None else None,  # 84
            self.dodge.time.frames if self.dodge.time is not None else None,  # 85
            self.surge.prob.percent if self.surge.prob is not None else None,  # 86
            self.surge.start,  # 87
            self.surge.range,  # 88
            self.surge.level,  # 89
            core.unit_int(self.toxic_immunity),  # 90
            core.unit_int(self.surge_immunity),  # 91
            self.curse.prob.percent if self.curse.prob is not None else None,  # 92
            self.curse.time.frames if self.curse.time is not None else None,  # 93
            core.unit_int(self.wave.is_mini),  # 94
            self.shield_pierce.prob.percent
            if self.shield_pierce.prob is not None
            else None,  # 95
            core.unit_int(self.target_aku),  # 96
            core.unit_int(self.collossus_slayer),  # 97
            core.unit_int(self.soul_strike),  # 98
            core.unit_int(self.attack_2.long_distance_flag),  # 99
            self.attack_2.long_distance_start,  # 100
            self.attack_2.long_distance_range,  # 101
            core.unit_int(self.attack_3.long_distance_flag),  # 102
            self.attack_3.long_distance_start,  # 103
            self.attack_3.long_distance_range,  # 104
            core.unit_int(self.behemoth_slayer),  # 105
            self.behemoth_dodge.prob.percent
            if self.behemoth_dodge.prob is not None
            else None,  # 106
            self.behemoth_dodge.time.frames
            if self.behemoth_dodge.time is not None
            else None,  # 107
            self.unknown_108,  # 108
        ]

    def wipe(self):
        raw_data = []
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def has_targeted_effect(self) -> bool:
        to_check = [
            self.knockback.prob.percent if self.knockback.prob else None,
            self.freeze.prob.percent if self.freeze.prob else None,
            self.slow.prob.percent if self.slow.prob else None,
            self.weaken.prob.percent if self.weaken.prob else None,
            self.warp.prob.percent if self.warp.prob else None,
            self.curse.prob.percent if self.curse.prob else None,
            self.dodge.prob.percent if self.dodge.prob else None,
        ]
        return any(to_check)

    def copy(self) -> "CatStats":
        return CatStats(
            self.cat_id,
            self.form,
            self.to_raw_data(),
        )

    def import_enemy_stats(self, enemy_stats: "core.EnemyStats"):
        has_targeted_effect = enemy_stats.has_targeted_effect()
        self.wipe()
        self.hp = enemy_stats.hp
        self.kbs = enemy_stats.kbs
        self.speed = enemy_stats.speed
        self.attack_1 = enemy_stats.attack_1.copy()
        self.range = enemy_stats.range
        self.cost = (enemy_stats.money_drop or 0) // 2
        self.recharge_time = core.Frames(0)
        self.collision_start = enemy_stats.collision_start
        self.collision_width = enemy_stats.collision_width
        self.target_red = has_targeted_effect
        self.unused = enemy_stats.unused
        self.area_attack = enemy_stats.area_attack
        self.target_floating = has_targeted_effect
        self.target_black = has_targeted_effect
        self.target_metal = has_targeted_effect
        self.target_traitless = has_targeted_effect
        self.target_angel = has_targeted_effect
        self.target_alien = has_targeted_effect
        self.target_zombie = has_targeted_effect
        self.knockback = enemy_stats.knockback.copy()
        self.freeze = enemy_stats.freeze.copy()
        self.slow = enemy_stats.slow.copy()
        self.crit = enemy_stats.crit.copy()
        self.base_destroyer = enemy_stats.base_destroyer
        self.wave = enemy_stats.wave.copy()
        self.weaken = enemy_stats.weaken.copy()
        self.strengthen = enemy_stats.strengthen.copy()
        self.is_metal = enemy_stats.metal
        self.wave_immunity = enemy_stats.wave_immunity
        self.wave_blocker = enemy_stats.wave_blocker
        self.knockback_immunity = enemy_stats.knockback_immunity
        self.freeze_immunity = enemy_stats.freeze_immunity
        self.slow_immunity = enemy_stats.slow_immunity
        self.weaken_immunity = enemy_stats.weaken_immunity
        self.target_witch = has_targeted_effect
        self.attack_state = enemy_stats.attack_state.copy()
        self.time_before_death = (
            enemy_stats.time_before_death.copy()
            if enemy_stats.time_before_death is not None
            else None
        )
        self.attack_2 = enemy_stats.attack_2.copy()
        self.attack_3 = enemy_stats.attack_3.copy()
        self.spawn_anim = enemy_stats.spawn_anim.copy()
        self.soul_anim = enemy_stats.soul_anim.copy()
        self.warp = enemy_stats.warp.copy()
        self.warp_blocker = enemy_stats.warp_blocker
        self.target_eva = has_targeted_effect
        self.target_relic = has_targeted_effect
        self.savage_blow = enemy_stats.savage_blow.copy()
        self.dodge = enemy_stats.dodge.copy()
        self.surge = enemy_stats.surge.copy()
        self.surge_immunity = enemy_stats.surge_immunity
        self.curse = enemy_stats.curse.copy()
        self.target_aku = has_targeted_effect

    def apply_dict(self, dict_data: dict[str, Any]):
        raw_stats = dict_data.get("raw_stats")
        if raw_stats is not None:
            current_raw_stats = self.to_raw_data()
            mod_stats = core.ModEditDictHandler(raw_stats, current_raw_stats).get_dict(
                True
            )
            for stat_id, stat_value in mod_stats.items():
                current_raw_stats[stat_id] = core.ModEditValueHandler(
                    stat_value, current_raw_stats[stat_id]
                ).get_value()
            self.assign(current_raw_stats)

    def to_dict(self) -> dict[str, Any]:
        raw_stats = self.to_raw_data()
        data: dict[int, Any] = {}
        for stat_id, stat_value in enumerate(raw_stats):
            data[stat_id] = stat_value
        return {"raw_stats": data}

    @staticmethod
    def create_empty(cat_id: int, form: CatFormType) -> "CatStats":
        return CatStats(cat_id, form, [])


class CatModel:
    def __init__(self, cat_id: int, form: CatFormType, model: "core.Model"):
        self.cat_id = cat_id
        self.form = form
        self.model = model

    @staticmethod
    def get_cat_id_str(cat_id: int) -> str:
        return core.PaddedInt(cat_id, 3).to_str()

    @staticmethod
    def get_img_path(cat_id: int, form: CatFormType) -> str:
        cat_id_str = CatModel.get_cat_id_str(cat_id)
        return f"{cat_id_str}_{form.value}.png"

    @staticmethod
    def get_imgcut_path(cat_id: int, form: CatFormType) -> str:
        return CatModel.get_img_path(cat_id, form).replace(".png", ".imgcut")

    @staticmethod
    def get_mamodel_path(cat_id: int, form: CatFormType) -> str:
        return CatModel.get_img_path(cat_id, form).replace(".png", ".mamodel")

    @staticmethod
    def get_maanim_path(
        cat_id: int, form: CatFormType, anim_type: "core.AnimType"
    ) -> str:
        anim_type_str = core.PaddedInt(anim_type.value, 2).to_str()
        return CatModel.get_img_path(cat_id, form).replace(
            ".png", f"{anim_type_str}.maanim"
        )

    @staticmethod
    def get_maanim_paths(cat_id: int, form: CatFormType) -> list[str]:
        maanim_paths: list[str] = []
        for anim_type in core.AnimType:
            maanim_paths.append(CatModel.get_maanim_path(cat_id, form, anim_type))
        cat_id_str = CatModel.get_cat_id_str(cat_id)
        maanim_paths.append(f"{cat_id_str}_{form.value}_entry.maanim")
        maanim_paths.append(f"{cat_id_str}_{form.value}_soul.maanim")
        return maanim_paths

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks", cat_id: int, form: CatFormType
    ) -> Optional["CatModel"]:
        img_path = CatModel.get_img_path(cat_id, form)
        imgcut_path = CatModel.get_imgcut_path(cat_id, form)
        mamodel_path = CatModel.get_mamodel_path(cat_id, form)
        maanim_paths = CatModel.get_maanim_paths(cat_id, form)
        model = core.Model.load(
            mamodel_path, imgcut_path, img_path, maanim_paths, game_data
        )
        return CatModel(cat_id, form, model)

    def to_game_data(self, game_data: "core.GamePacks"):
        self.model.save(game_data)

    def set_cat_id(self, cat_id: int):
        self.cat_id = cat_id
        self.model.set_unit_id(cat_id)
        self.model.set_unit_form(self.form.value)

    def set_form(self, form: CatFormType):
        self.form = form
        self.model.set_unit_id(self.cat_id)
        self.model.set_unit_form(form.value)

    def copy(self) -> "CatModel":
        return CatModel(
            self.cat_id,
            self.form,
            self.model.copy(),
        )

    def apply_dict(self, dict_data: dict[str, Any]):
        model = dict_data.get("model")
        if model is not None:
            self.model.apply_dict(model)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model.to_dict(),
        }

    @staticmethod
    def create_empty(cat_id: int, form: CatFormType) -> "CatModel":
        return CatModel(cat_id, form, core.Model.create_empty())


class CatForm:
    def __init__(
        self,
        cat_id: int,
        form: CatFormType,
        stats: Optional["CatStats"] = None,
        name: Optional[str] = None,
        description: Optional[list[str]] = None,
        anim: Optional["CatModel"] = None,
        upgrade_icon: Optional["core.BCImage"] = None,
        deploy_icon: Optional["core.BCImage"] = None,
    ):
        self.cat_id = cat_id
        self.form = form
        self.stats = stats
        self.name = name
        self.description = description
        self.anim = anim
        self.upgrade_icon = upgrade_icon
        self.deploy_icon = deploy_icon

    def get_stats(self) -> "CatStats":
        if self.stats is None:
            self.stats = CatStats.create_empty(self.cat_id, self.form)
        return self.stats

    def get_name(self) -> str:
        if self.name is None:
            self.name = ""
        return self.name

    def get_description(self) -> list[str]:
        if self.description is None:
            self.description = []
        return self.description

    def get_anim(self) -> "CatModel":
        if self.anim is None:
            self.anim = CatModel.create_empty(self.cat_id, self.form)
        return self.anim

    def get_upgrade_icon(self) -> "core.BCImage":
        if self.upgrade_icon is None:
            self.upgrade_icon = core.BCImage.from_size(512, 128)
        return self.upgrade_icon

    def get_deploy_icon(self) -> "core.BCImage":
        if self.deploy_icon is None:
            self.deploy_icon = core.BCImage.from_size(128, 128)
        return self.deploy_icon

    def format_deploy_icon(self):
        deploy_icon = self.get_deploy_icon()
        if deploy_icon.width == 128 and deploy_icon.height == 128:
            return
        base_image = core.BCImage.from_size(128, 128)
        base_image.paste(deploy_icon, 9, 21)
        self.deploy_icon = base_image

    def format_upgrade_icon(self):
        upgrade_icon = self.get_upgrade_icon()
        if upgrade_icon.width == 85 and upgrade_icon.height == 32:
            upgrade_icon.scale(3.5, 3.5)

        base_image = core.BCImage.from_size(512, 128)
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

    def format_icons(self):
        self.format_deploy_icon()
        self.format_upgrade_icon()

    @staticmethod
    def get_icons_game_data(
        game_data: "core.GamePacks", cat_id: int, form: CatFormType
    ) -> Optional[tuple["core.BCImage", "core.BCImage"]]:
        cat_id_str = core.PaddedInt(cat_id, 3).to_str()
        upgrade_name = f"udi{cat_id_str}_{form.value}.png"
        deploy_name = f"uni{cat_id_str}_{form.value}00.png"
        upgrade_icon = game_data.find_file(upgrade_name)
        deploy_icon = game_data.find_file(deploy_name)
        if upgrade_icon is None or deploy_icon is None:
            return None
        return (
            core.BCImage(upgrade_icon.dec_data),
            core.BCImage(deploy_icon.dec_data),
        )

    def icons_to_game_data(
        self,
        game_data: "core.GamePacks",
    ):
        cat_id_str = core.PaddedInt(self.cat_id, 3).to_str()
        upgrade_name = f"udi{cat_id_str}_{self.form.value}.png"
        deploy_name = f"uni{cat_id_str}_{self.form.value}00.png"
        if self.upgrade_icon is not None:
            game_data.set_file(upgrade_name, self.upgrade_icon.to_data())
        if self.deploy_icon is not None:
            game_data.set_file(deploy_name, self.deploy_icon.to_data())

    def set_cat_id(self, cat_id: int, force: bool = False):
        original_cat_id = self.cat_id
        self.cat_id = cat_id
        if self.stats is not None:
            self.stats.cat_id = cat_id

        if original_cat_id != self.cat_id or force:
            if self.anim is None:
                raise ValueError("Cannot set cat id without anim being loaded")
            self.get_anim().set_cat_id(cat_id)

    def set_form(self, form: CatFormType, force: bool = False):
        original_form = self.form
        self.form = form
        if self.stats is not None:
            self.stats.form = form
        if original_form != self.form or force:
            if self.anim is None:
                raise ValueError("Cannot set form without anim being loaded")
            self.get_anim().set_form(form)

    def import_enemy(self, enemy: "core.Enemy"):
        if enemy.name is not None:
            self.name = enemy.name
        if enemy.description is not None:
            self.description = enemy.description[1:]
        # self.anim.import_enemy_anim(enemy.anim)
        if enemy.stats is not None:
            self.get_stats().import_enemy_stats(enemy.stats)

    def copy(self) -> "CatForm":
        return CatForm(
            self.cat_id,
            self.form,
            self.stats.copy() if self.stats is not None else None,
            self.name,
            self.description.copy() if self.description is not None else None,
            self.anim.copy() if self.anim is not None else None,
            self.upgrade_icon.copy() if self.upgrade_icon is not None else None,
            self.deploy_icon.copy() if self.deploy_icon is not None else None,
        )

    def apply_dict(self, dict_data: dict[str, Any]):
        name = dict_data.get("name")
        if name is not None:
            self.name = name
        description = dict_data.get("description")
        if description is not None:
            self.description = description
        stats = dict_data.get("stats")
        if stats is not None:
            self.get_stats().apply_dict(stats)
        anim = dict_data.get("anim")
        if anim is not None:
            self.get_anim().apply_dict(anim)
        upgrade_icon = dict_data.get("upgrade_icon")
        if upgrade_icon is not None:
            self.get_upgrade_icon().apply_dict(upgrade_icon)
        deploy_icon = dict_data.get("deploy_icon")
        if deploy_icon is not None:
            self.get_deploy_icon().apply_dict(deploy_icon)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "stats": self.stats.to_dict() if self.stats is not None else None,
            "anim": self.anim.to_dict() if self.anim is not None else None,
            "upgrade_icon": self.upgrade_icon.to_dict()
            if self.upgrade_icon is not None
            else None,
            "deploy_icon": self.deploy_icon.to_dict()
            if self.deploy_icon is not None
            else None,
        }

    @staticmethod
    def create_empty(cat_id: int, form: CatFormType) -> "CatForm":
        return CatForm(
            cat_id,
            form,
        )


class UnlockSourceType(enum.Enum):
    XP = 0
    GACHA = 1


class Rarity(enum.Enum):
    NORMAL = 0
    SPECIAL = 1
    RARE = 2
    SUPER_RARE = 3
    UBER_RARE = 4
    LEGEND_RARE = 5


class UnitBuyData:
    def __init__(self, cat_id: int, raw_data: list[Optional[int]]):
        self.cat_id = cat_id
        raw_data = self.extend(raw_data)
        self.assign(raw_data)

    def extend(self, raw_data: list[Optional[int]]) -> list[Optional[int]]:
        length = 63
        raw_data = raw_data + [None] * (length - len(raw_data))
        return raw_data

    def assign(self, raw_data: list[Optional[int]]):
        # tf = true form
        # ff = forth form
        self.stage_unlock = raw_data[0]
        self.purchase_cost = raw_data[1]
        self.upgrade_costs = raw_data[2:12]
        self.unlock_source = raw_data[12]
        self.rarity = Rarity(raw_data[13]) if raw_data[13] is not None else None
        self.position_order = raw_data[14]
        self.chapter_unlock = raw_data[15]
        self.sell_price = raw_data[16]
        self.gatya_rarity = (
            core.GatyaRarity(raw_data[17]) if raw_data[17] is not None else None
        )
        self.original_max_levels = raw_data[18], raw_data[19]
        self.force_true_form_level = raw_data[20]
        self.second_form_unlock_level = raw_data[21]
        self.unknown_22 = raw_data[22]
        self.tf_id = raw_data[23]
        self.ff_id = raw_data[24]
        self.evolve_level_tf = raw_data[25]
        self.evolve_level_ff = raw_data[26]
        self.evolve_cost_tf = raw_data[27]
        self.evolve_items_tf = core.EvolveItems.from_unit_buy_list(raw_data, 28)
        self.evolve_cost_ff = raw_data[38]
        self.evolve_items_ff = core.EvolveItems.from_unit_buy_list(raw_data, 39)
        self.max_upgrade_level_no_catseye = raw_data[49]
        self.max_upgrade_level_catseye = raw_data[50]
        self.max_plus_upgrade_level = raw_data[51]
        self.unknown_52 = raw_data[52]
        self.unknown_53 = raw_data[53]
        self.unknown_54 = raw_data[54]
        self.unknown_55 = raw_data[55]
        self.catseye_usage_pattern = raw_data[56]
        self.game_version = raw_data[57]
        self.np_sell_price = raw_data[58]
        self.unknown_59 = raw_data[59]
        self.unknown_60 = raw_data[60]
        self.egg_val = raw_data[61]
        self.egg_id = raw_data[62]

    def to_raw_data(self) -> list[Optional[int]]:
        return [
            self.stage_unlock,
            self.purchase_cost,
            *self.upgrade_costs,
            self.unlock_source,
            self.rarity.value if self.rarity is not None else None,
            self.position_order,
            self.chapter_unlock,
            self.sell_price,
            self.gatya_rarity.value if self.gatya_rarity is not None else None,
            *self.original_max_levels,
            self.force_true_form_level,
            self.second_form_unlock_level,
            self.unknown_22,
            self.tf_id,
            self.ff_id,
            self.evolve_level_tf,
            self.evolve_level_ff,
            self.evolve_cost_tf,
            *self.evolve_items_tf.to_list(),
            self.evolve_cost_ff,
            *self.evolve_items_ff.to_list(),
            self.max_upgrade_level_no_catseye,
            self.max_upgrade_level_catseye,
            self.max_plus_upgrade_level,
            self.unknown_52,
            self.unknown_53,
            self.unknown_54,
            self.unknown_55,
            self.catseye_usage_pattern,
            self.game_version,
            self.np_sell_price,
            self.unknown_59,
            self.unknown_60,
            self.egg_val,
            self.egg_id,
        ]

    def set_obtainable(self, obtainable: bool):
        if not obtainable:
            self.game_version = -1
        else:
            self.game_version = 0 if self.game_version == -1 else self.game_version

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
        self.max_upgrade_level_catseye = max_base
        self.max_plus_upgrade_level = max_plus
        if level_until_catsye_req is not None:
            self.max_upgrade_level_no_catseye = level_until_catsye_req
        if original_base_max is not None:
            self.original_max_levels = original_base_max, self.original_max_levels[1]
        if original_plus_max is not None:
            self.original_max_levels = self.original_max_levels[0], original_plus_max

    def reset_upgrade_costs(self):
        for i in range(len(self.upgrade_costs)):
            self.upgrade_costs[i] = 0

    def apply_dict(self, dict_data: dict[str, Any]):
        raw_data = dict_data.get("raw_data")
        if raw_data is not None:
            current_raw_data = self.to_raw_data()
            mod_raw_data = core.ModEditDictHandler(raw_data, current_raw_data).get_dict(
                convert_int=True
            )
            for stat_id, value in mod_raw_data.items():
                current_raw_data[stat_id] = core.ModEditValueHandler(
                    value, current_raw_data[stat_id]
                ).get_value()
            current_raw_data = self.extend(current_raw_data)
            self.assign(current_raw_data)

    @staticmethod
    def create_empty(cat_id: int) -> "UnitBuyData":
        return UnitBuyData(cat_id, [])

    def to_dict(self) -> dict[str, Any]:
        raw_data = self.to_raw_data()
        data: dict[int, Any] = {}
        for stat_id, value in enumerate(raw_data):
            data[stat_id] = value
        return {"raw_data": data}


class UnitBuy:
    def __init__(self, unit_buy_data: dict[int, UnitBuyData]):
        self.unit_buy_data = unit_buy_data

    @staticmethod
    def get_file_name() -> str:
        return "unitbuy.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "UnitBuy":
        if game_data.unit_buy is not None:
            return game_data.unit_buy
        file = game_data.find_file(UnitBuy.get_file_name())
        if file is None:
            return UnitBuy.create_empty()

        csv = core.CSV(file.dec_data)
        unit_buy_data: dict[int, UnitBuyData] = {}
        for i, line in enumerate(csv):
            unit_buy_data[i] = UnitBuyData(i, [int(x) for x in line])
        unit_buy = UnitBuy(unit_buy_data)
        game_data.unit_buy = unit_buy
        return unit_buy

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(UnitBuy.get_file_name())
        if file is None:
            return None

        csv = core.CSV(file.dec_data)
        remaining_cats = self.unit_buy_data.copy()
        for i in range(len(csv.lines)):
            if i not in self.unit_buy_data:
                continue
            for j, stat in enumerate(self.unit_buy_data[i].to_raw_data()):
                if j >= len(csv.lines[i]):
                    csv.lines[i].append(str(stat or 0))
                else:
                    if stat is not None:
                        csv.lines[i][j] = str(stat)
            remaining_cats.pop(i)

        for cat in remaining_cats.values():
            csv.lines.append([str(x or 0) for x in cat.to_raw_data()])

        game_data.set_file(UnitBuy.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        if cat.unit_buy_data is not None:
            self.unit_buy_data[cat.cat_id] = cat.unit_buy_data

    @staticmethod
    def create_empty() -> "UnitBuy":
        return UnitBuy({})

    def get_rarities(
        self,
        localizable: "core.Localizable",
    ) -> dict[int, str]:
        rarity_ids: set[int] = set()
        for cat in self.unit_buy_data.values():
            if cat.rarity is not None:
                rarity_ids.add(cat.rarity.value)

        rarity_names: list[str] = []

        for rarity_id in rarity_ids:
            name = localizable.get(f"rarity_name_{rarity_id+1}")
            if name is None:
                name = f"Rarity {rarity_id+1}"
            rarity_names.append(name)

        return {rarity_id: rarity_names[rarity_id] for rarity_id in rarity_ids}


class Talent:
    def __init__(self, cat_id: int, raw_data: list[int]):
        self.cat_id = cat_id
        self.raw_data = raw_data

    def apply_dict(self, dict_data: dict[str, Any]):
        raw_data = dict_data.get("raw_data")
        if raw_data is not None:
            self.raw_data = raw_data

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_data": self.raw_data,
        }


class Talents:
    def __init__(self, talents: dict[int, Talent]):
        self.talents = talents

    @staticmethod
    def get_file_name() -> str:
        return "SkillAcquisition.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "Talents":
        if game_data.talents is not None:
            return game_data.talents
        file = game_data.find_file(Talents.get_file_name())
        if file is None:
            return Talents.create_empty()

        csv = core.CSV(file.dec_data)
        talents: dict[int, Talent] = {}
        for line in csv.lines[1:]:
            cat_id = int(line[0])
            talents[cat_id] = Talent(cat_id, [int(x) for x in line[1:]])

        talent = Talents(talents)
        game_data.talents = talent
        return talent

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(Talents.get_file_name())
        if file is None:
            return None

        remanining_cats = self.talents.copy()
        csv = core.CSV(file.dec_data)
        for i, line in enumerate(csv.lines[1:]):
            cat_id = int(line[0])
            if cat_id not in self.talents:
                continue
            d_line = [str(cat_id)]
            d_line.extend([str(x) for x in self.talents[cat_id].raw_data])
            csv.lines[i + 1] = d_line
            del remanining_cats[cat_id]

        for cat_id, talent in remanining_cats.items():
            a_line = [str(cat_id)]
            a_line.extend([str(x) for x in talent.raw_data])
            csv.lines.append(a_line)

        game_data.set_file(Talents.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        if cat.talent is None:
            return
        self.talents[cat.cat_id] = cat.talent

    @staticmethod
    def create_empty() -> "Talents":
        return Talents({})


class NyankoPictureBookData:
    def __init__(
        self,
        cat_id: int,
        is_displayed_in_catguide: Optional[bool] = None,
        limited: Optional[bool] = None,
        total_forms: Optional[int] = None,
        hint_display_type: Optional[int] = None,
        scale_0: Optional[int] = None,
        scale_1: Optional[int] = None,
        scale_2: Optional[int] = None,
        scale_3: Optional[int] = None,
    ):
        self.cat_id = cat_id
        self.is_displayed_in_catguide = is_displayed_in_catguide
        self.limited = limited
        self.total_forms = total_forms
        self.hint_display_type = hint_display_type
        self.scale_0 = scale_0
        self.scale_1 = scale_1
        self.scale_2 = scale_2
        self.scale_3 = scale_3

    def set_is_displayed_in_catguide(self, is_displayed_in_catguide: bool):
        self.is_displayed_in_catguide = is_displayed_in_catguide

    def is_displayed_in_cat_guide(self) -> Optional[bool]:
        return self.is_displayed_in_catguide

    def apply_dict(self, dict_data: dict[str, Any]):
        is_displayed_in_catguide = dict_data.get("is_displayed_in_catguide")
        if is_displayed_in_catguide is not None:
            self.is_displayed_in_catguide = is_displayed_in_catguide
        limited = dict_data.get("limited")
        if limited is not None:
            self.limited = limited

        total_forms = dict_data.get("total_forms")
        if total_forms is not None:
            self.total_forms = total_forms

        hint_display_type = dict_data.get("hint_display_type")
        if hint_display_type is not None:
            self.hint_display_type = hint_display_type

        scale_0 = dict_data.get("scale_0")
        if scale_0 is not None:
            self.scale_0 = scale_0

        scale_1 = dict_data.get("scale_1")
        if scale_1 is not None:
            self.scale_1 = scale_1

        scale_2 = dict_data.get("scale_2")
        if scale_2 is not None:
            self.scale_2 = scale_2

        scale_3 = dict_data.get("scale_3")
        if scale_3 is not None:
            self.scale_3 = scale_3

    @staticmethod
    def create_empty(cat_id: int) -> "NyankoPictureBookData":
        return NyankoPictureBookData(cat_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_displayed_in_catguide": self.is_displayed_in_catguide,
            "limited": self.limited,
            "total_forms": self.total_forms,
            "hint_display_type": self.hint_display_type,
            "scale_0": self.scale_0,
            "scale_1": self.scale_1,
            "scale_2": self.scale_2,
            "scale_3": self.scale_3,
        }


class NyankoPictureBook:
    def __init__(self, data: dict[int, NyankoPictureBookData]):
        self.data = data

    @staticmethod
    def get_file_name() -> str:
        return "nyankoPictureBookData.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "NyankoPictureBook":
        if game_data.nyanko_picture_book is not None:
            return game_data.nyanko_picture_book
        file = game_data.find_file(NyankoPictureBook.get_file_name())
        if file is None:
            return NyankoPictureBook.create_empty()

        csv = core.CSV(file.dec_data)
        data: dict[int, NyankoPictureBookData] = {}
        for cat_id in range(len(csv.lines)):
            csv.init_getter(cat_id)
            data[cat_id] = NyankoPictureBookData(
                cat_id,
                csv.get_bool(),
                csv.get_bool(),
                csv.get_int(),
                csv.get_int(),
                csv.get_int(),
                csv.get_int(),
                csv.get_int(),
                csv.get_int(),
            )
        nypb = NyankoPictureBook(data)
        game_data.nyanko_picture_book = nypb
        return nypb

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(NyankoPictureBook.get_file_name())
        if file is None:
            return None

        csv = core.CSV(file.dec_data)
        for data in self.data.values():
            csv.init_setter(data.cat_id, 8)
            csv.set_str(data.is_displayed_in_catguide)
            csv.set_str(data.limited)
            csv.set_str(data.total_forms)
            csv.set_str(data.hint_display_type)
            csv.set_str(data.scale_0)
            csv.set_str(data.scale_1)
            csv.set_str(data.scale_2)
            csv.set_str(data.scale_3)

        game_data.set_file(NyankoPictureBook.get_file_name(), csv.to_data())

    def set(self, cat: "Cat"):
        if cat.nyanko_picture_book_data is not None:
            self.data[cat.cat_id] = cat.nyanko_picture_book_data

    @staticmethod
    def create_empty() -> "NyankoPictureBook":
        return NyankoPictureBook({})


class EvolveTextText:
    def __init__(self, evolve: int, text: list[str]):
        self.text = text
        self.evolve = evolve


class EvolveTextCat:
    def __init__(self, cat_id: int, text: dict[int, EvolveTextText]):
        self.cat_id = cat_id
        self.text = text

    def apply_dict(self, dict_data: dict[str, Any]):
        current_texts = self.text.copy()
        mod_texts = core.ModEditDictHandler(dict_data, current_texts).get_dict(
            convert_int=True
        )
        for evolve, text in mod_texts.items():
            current_text = self.text.get(evolve)
            if current_text is None:
                current_text = EvolveTextText(evolve, [])
            current_text.text = text
            self.text[evolve] = current_text

    @staticmethod
    def create_empty(cat_id: int) -> "EvolveTextCat":
        return EvolveTextCat(cat_id, {})

    def to_dict(self) -> dict[Any, Any]:
        return {evolve: text.text for evolve, text in self.text.items()}


class EvolveText:
    def __init__(self, text: dict[int, EvolveTextCat]):
        self.text = text

    @staticmethod
    def get_file_name(lang: str) -> str:
        return f"unitevolve_{lang}.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EvolveText":
        if game_data.evolve_text is not None:
            return game_data.evolve_text
        file = game_data.find_file(
            EvolveText.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return EvolveText.create_empty()

        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
            remove_comments=False,
            remove_empty=False,
        )
        text: dict[int, EvolveTextCat] = {}
        for cat_id, line in enumerate(csv):
            text[cat_id] = EvolveTextCat(cat_id, {})
            text[cat_id].text[0] = EvolveTextText(0, line[:3])
            text[cat_id].text[1] = EvolveTextText(1, line[4:7])
        evolve_text = EvolveText(text)
        game_data.evolve_text = evolve_text
        return evolve_text

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(
            EvolveText.get_file_name(game_data.localizable.get_lang())
        )
        if file is None:
            return None

        csv = core.CSV(
            file.dec_data,
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
            remove_comments=False,
            remove_empty=False,
        )
        for cat_id, line in self.text.items():
            first_evolve = line.text[0].text
            second_evolve = line.text[1].text
            padd_len_1 = max(0, 4 - len(first_evolve))
            padd_len_2 = max(0, 4 - len(second_evolve))
            csv.lines[cat_id] = (
                first_evolve
                + (["＠"] * padd_len_1)
                + second_evolve
                + (["＠"] * padd_len_2)
            )

        game_data.set_file(
            EvolveText.get_file_name(game_data.localizable.get_lang()), csv.to_data()
        )

    def set(self, cat: "Cat"):
        self.text[cat.cat_id] = cat.evolve_text or EvolveTextCat.create_empty(
            cat.cat_id
        )

    @staticmethod
    def create_empty() -> "EvolveText":
        return EvolveText({})

    @staticmethod
    def create_text_line(text: list[str]) -> dict[int, EvolveTextText]:
        first_evolve = text[:3]
        second_evolve = text[3:6]
        return {
            0: EvolveTextText(0, first_evolve),
            1: EvolveTextText(1, second_evolve),
        }


class Cat:
    def __init__(
        self,
        cat_id: int,
        forms: Optional[dict[CatFormType, CatForm]] = None,
        unit_buy_data: Optional[UnitBuyData] = None,
        talent: Optional["Talent"] = None,
        nyanko_picture_book_data: Optional[NyankoPictureBookData] = None,
        evolve_text: Optional[EvolveTextCat] = None,
    ):
        if isinstance(cat_id, str):
            raise ValueError("cat_id must be an int")
        self.cat_id = cat_id
        if forms is None:
            forms = {}
        self.forms = forms
        self.unit_buy_data = unit_buy_data
        self.talent = talent
        self.nyanko_picture_book_data = nyanko_picture_book_data
        self.evolve_text = evolve_text

    @staticmethod
    def get_stat_file_name(cat_id: int):
        return f"unit{core.PaddedInt(cat_id+1, 3)}.csv"

    @staticmethod
    def get_name_file_name(cat_id: int, lang: str):
        return f"Unit_Explanation{cat_id+1}_{lang}.csv"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        cat_id: int,
        unit_buy: UnitBuy,
        talents: Talents,
        nyanko_picture_book: NyankoPictureBook,
        evolve_text: EvolveText,
    ) -> Optional["Cat"]:
        stat_file = game_data.find_file(Cat.get_stat_file_name(cat_id))
        name_file = game_data.find_file(
            Cat.get_name_file_name(cat_id, game_data.localizable.get_lang())
        )
        if stat_file is None:
            return None
        stat_csv = stat_file.dec_data.to_csv()
        if name_file is None:
            name_csv = core.CSV(
                delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
                remove_empty=False,
            )
        else:
            name_csv = name_file.dec_data.to_csv(
                delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
                remove_empty=False,
            )
        unit_buy_data = unit_buy.unit_buy_data.get(cat_id)
        talent = talents.talents.get(cat_id)
        nyanko_picture_book_data = nyanko_picture_book.data.get(cat_id)
        evt = evolve_text.text.get(cat_id)
        if unit_buy_data is None or nyanko_picture_book_data is None:
            return None
        forms: dict[CatFormType, CatForm] = {}
        total_forms = nyanko_picture_book_data.total_forms or 0
        form_count = 0
        for form in CatFormType:
            if form_count >= total_forms:
                break
            try:
                stats = CatStats(
                    cat_id, form, [int(x) for x in stat_csv.lines[form.get_index()]]
                )
            except IndexError:
                continue
            try:
                row = name_csv.lines[(form.get_index())]
            except IndexError:
                continue
            name = row[0]
            description = row[1:]
            anim = CatModel.from_game_data(game_data, cat_id, form)
            if anim is None:
                continue
            icons = CatForm.get_icons_game_data(game_data, cat_id, form)
            if icons is None:
                continue
            upgrade_icon, deploy_icon = icons
            forms[form] = CatForm(
                cat_id, form, stats, name, description, anim, upgrade_icon, deploy_icon
            )
            form_count += 1
        return Cat(cat_id, forms, unit_buy_data, talent, nyanko_picture_book_data, evt)

    def to_game_data(self, game_data: "core.GamePacks"):
        stat_file = game_data.find_file(Cat.get_stat_file_name(self.cat_id))
        name_file = game_data.find_file(
            Cat.get_name_file_name(self.cat_id, game_data.localizable.get_lang())
        )
        if stat_file is None or name_file is None:
            return None
        stat_csv = stat_file.dec_data.to_csv()
        name_csv = name_file.dec_data.to_csv(
            delimeter=core.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        for form_type, form in self.forms.items():
            if form.stats is not None:
                if form_type.get_index() >= len(stat_csv.lines):
                    stat_csv.lines.append([])
                for i, stat in enumerate(form.stats.to_raw_data()):
                    if i >= len(stat_csv.lines[form_type.get_index()]):
                        stat_csv.lines[form_type.get_index()].append(str(stat or 0))
                    else:
                        if stat is not None:
                            stat_csv.lines[form_type.get_index()][i] = str(stat)

            row: list[str] = []

            if form.name is not None:
                row.append(form.name)
            else:
                if form_type.get_index() >= len(name_csv.lines):
                    name_csv.lines.append(["", ""])
                row.append(name_csv.lines[form_type.get_index()][0])

            if form.description is not None:
                row.extend(form.description)
            else:
                if form_type.get_index() >= len(name_csv.lines):
                    name_csv.lines.append(["", ""])
                row.extend(name_csv.lines[form_type.get_index()][1:])

            if form_type.get_index() >= len(name_csv.lines):
                diff = form_type.get_index() - len(name_csv.lines)
                for _ in range(diff + 1):
                    name_csv.lines.append([])
            name_csv.lines[form_type.get_index()] = row

            to_add = 4 - len(name_csv.lines[form_type.get_index()])
            if to_add > 0:
                name_csv.lines[form_type.get_index()].extend([""] * to_add)

            if form.anim is not None:
                form.anim.to_game_data(game_data)
            form.icons_to_game_data(game_data)

        game_data.set_file(Cat.get_stat_file_name(self.cat_id), stat_csv.to_data())
        game_data.set_file(
            Cat.get_name_file_name(self.cat_id, game_data.localizable.get_lang()),
            name_csv.to_data(),
        )

    def get_form(self, form: Union[CatFormType, int]) -> Optional[CatForm]:
        if isinstance(form, int):
            form = CatFormType.from_index(form)
        return self.forms.get(form)

    def set_form(self, form: Union[CatFormType, int], value: CatForm):
        if isinstance(form, int):
            form = CatFormType.from_index(form)
        new_form = value.copy()
        new_form.set_form(form)
        new_form.set_cat_id(self.cat_id)
        self.forms[form] = new_form
        if self.nyanko_picture_book_data is None:
            self.nyanko_picture_book_data = NyankoPictureBookData.create_empty(
                self.cat_id
            )

        return new_form

    def set_cat_id(self, cat_id: int):
        self.cat_id = cat_id
        for form in self.forms.values():
            form.set_cat_id(cat_id)
        if self.unit_buy_data is not None:
            self.unit_buy_data.cat_id = cat_id
        if self.talent is not None:
            self.talent.cat_id = cat_id
        if self.nyanko_picture_book_data is not None:
            self.nyanko_picture_book_data.cat_id = cat_id

    def set_is_displayed_in_catguide(self, is_displayed_in_catguide: bool):
        if self.unit_buy_data is None:
            self.unit_buy_data = UnitBuyData.create_empty(self.cat_id)
        self.unit_buy_data.set_obtainable(is_displayed_in_catguide)
        if self.nyanko_picture_book_data is None:
            self.nyanko_picture_book_data = NyankoPictureBookData.create_empty(
                self.cat_id
            )
        self.nyanko_picture_book_data.set_is_displayed_in_catguide(
            is_displayed_in_catguide
        )

    def is_displayed_in_catguide(self) -> bool:
        if self.unit_buy_data is None:
            self.unit_buy_data = UnitBuyData.create_empty(self.cat_id)
        if self.nyanko_picture_book_data is None:
            self.nyanko_picture_book_data = NyankoPictureBookData.create_empty(
                self.cat_id
            )
        return (
            self.unit_buy_data.is_obtainable()
            and self.nyanko_picture_book_data.is_displayed_in_cat_guide()
            or False
        )

    def apply_dict(self, dict_data: dict[str, Any]):
        forms = dict_data.get("forms")
        if forms is not None:
            current_forms = self.forms.copy()
            mod_forms = core.ModEditDictHandler(forms, current_forms).get_dict(
                convert_int=True
            )
            for form_type, form in mod_forms.items():
                form_type = CatFormType.from_index(int(form_type))
                current_form = self.get_form(form_type)
                if current_form is None:
                    current_form = CatForm.create_empty(self.cat_id, form_type)
                    current_form = self.set_form(form_type, current_form)
                current_form.apply_dict(form)

        unit_buy = dict_data.get("unit_buy")
        if unit_buy is not None:
            if self.unit_buy_data is None:
                self.unit_buy_data = UnitBuyData.create_empty(self.cat_id)
            self.unit_buy_data.apply_dict(unit_buy)
        talent = dict_data.get("talent")
        if talent is not None:
            if self.talent is None:
                self.talent = Talent(self.cat_id, [])
            self.talent.apply_dict(talent)

        nyanko_picture_book = dict_data.get("nyanko_picture_book")
        if nyanko_picture_book is not None:
            if self.nyanko_picture_book_data is None:
                self.nyanko_picture_book_data = NyankoPictureBookData.create_empty(
                    self.cat_id
                )
            self.nyanko_picture_book_data.apply_dict(nyanko_picture_book)

        evt = dict_data.get("evolve_text")
        if evt is not None:
            if self.evolve_text is None:
                self.evolve_text = EvolveTextCat.create_empty(self.cat_id)
            self.evolve_text.apply_dict(evt)

    @staticmethod
    def create_empty(cat_id: int) -> "Cat":
        return Cat(
            cat_id,
            {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "forms": {k.get_index(): v.to_dict() for k, v in self.forms.items()},
            "unit_buy": self.unit_buy_data.to_dict()
            if self.unit_buy_data is not None
            else None,
            "talent": self.talent.to_dict() if self.talent is not None else None,
            "nyanko_picture_book": self.nyanko_picture_book_data.to_dict()
            if self.nyanko_picture_book_data is not None
            else None,
            "evolve_text": self.evolve_text.to_dict()
            if self.evolve_text is not None
            else None,
        }

    def add_forth_form_cf_evolution(
        self,
        form: Optional[CatForm],
        evolve_items: "core.EvolveItems",
        evolve_id: int = 25000,
        evolve_cost: int = 100000,
        evolve_level: int = 40,
        evolve_text: Optional[list[str]] = None,
    ) -> Optional[CatForm]:
        if form is not None:
            form = self.set_form(CatFormType.FOURTH, form)
        unitbuy = self.unit_buy_data or UnitBuyData.create_empty(self.cat_id)
        unitbuy.evolve_items_ff = evolve_items
        unitbuy.ff_id = evolve_id
        unitbuy.evolve_cost_ff = evolve_cost
        unitbuy.evolve_level_ff = evolve_level
        self.unit_buy_data = unitbuy

        nypbd = self.nyanko_picture_book_data or NyankoPictureBookData.create_empty(
            self.cat_id
        )
        nypbd.total_forms = 4
        self.nyanko_picture_book_data = nypbd
        evov_text = self.evolve_text or EvolveTextCat.create_empty(self.cat_id)
        evov_text.text[1] = EvolveTextText(1, evolve_text or ["", "", ""])
        return form

    def add_third_form_cf_evolution(
        self,
        form: Optional[CatForm],
        evolve_items: "core.EvolveItems",
        evolve_id: int = 15000,
        evolve_cost: int = 100000,
        evolve_level: int = 30,
        evolve_text: Optional[list[str]] = None,
    ) -> Optional[CatForm]:
        if form is not None:
            form = self.set_form(CatFormType.THIRD, form)
        unitbuy = self.unit_buy_data or UnitBuyData.create_empty(self.cat_id)
        unitbuy.evolve_items_tf = evolve_items
        unitbuy.tf_id = evolve_id
        unitbuy.evolve_cost_tf = evolve_cost
        unitbuy.evolve_level_tf = evolve_level
        self.unit_buy_data = unitbuy

        nypbd = self.nyanko_picture_book_data or NyankoPictureBookData.create_empty(
            self.cat_id
        )
        nypbd.total_forms = 3
        self.nyanko_picture_book_data = nypbd
        evov_text = self.evolve_text or EvolveTextCat.create_empty(self.cat_id)
        evov_text.text[0] = EvolveTextText(0, evolve_text or ["", "", ""])
        return form

    def copy_form_to_form(
        self, from_form_type: CatFormType, to_form_type: CatFormType
    ) -> CatForm:
        from_form = self.get_form(from_form_type) or CatForm.create_empty(
            self.cat_id, from_form_type
        )

        new_form = self.set_form(to_form_type, from_form.copy())
        return new_form


class Cats(core.EditableClass):
    def __init__(
        self,
        cats: dict[int, Cat],
    ):
        self.data = cats
        super().__init__(self.data)

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks", cat_ids: Optional[list[int]] = None
    ) -> "Cats":
        if game_data.cats is not None:
            return game_data.cats
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

        cats_o = Cats(cats)
        game_data.cats = cats_o
        return cats_o

    def to_game_data(self, game_data: "core.GamePacks"):
        unit_buy = UnitBuy({})
        talents = Talents({})
        nyan = NyankoPictureBook({})
        evov_text = EvolveText({})
        for cat in self.data.values():
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
        return self.data.get(cat_id)

    def set_cat(self, cat: Cat):
        self.data[cat.cat_id] = cat

    @staticmethod
    def create_empty() -> "Cats":
        return Cats({})

    @staticmethod
    def get_total_cats(game_data: "core.GamePacks") -> int:
        return len(NyankoPictureBook.from_game_data(game_data).data)
