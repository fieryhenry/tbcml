import enum


class Frames:
    def __init__(self, frames: int):
        self.frames = frames

    @staticmethod
    def get_frame_rate() -> int:
        return 30

    @property
    def seconds(self) -> int:
        return self.frames // self.get_frame_rate()
    
    @property
    def pair_frames(self) -> int:
        return self.frames // 2

    @staticmethod
    def from_seconds(seconds: int) -> "Frames":
        return Frames(seconds * Frames.get_frame_rate())
    
    @staticmethod
    def from_pair_frames(pair_frames: int) -> "Frames":
        return Frames(pair_frames * 2)

    def __str__(self):
        return f"{self.frames} frames ({self.seconds} seconds)"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Frames":
        return Frames(self.frames)


class Prob:
    def __init__(self, percent: int):
        self.percent = percent

    def __str__(self):
        return f"{self.percent}%"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Prob":
        return Prob(self.percent)


class Knockback:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "Knockback":
        return Knockback(Prob(percent))

    def __str__(self):
        return f"Knockback: {self.prob}"

    def __repr__(self):
        return str(self)

    def copy(self) -> "Knockback":
        return Knockback(self.prob.copy())


class BarrierBreak:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "BarrierBreak":
        return BarrierBreak(Prob(percent))

    def __str__(self):
        return f"Barrier Break: {self.prob}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "BarrierBreak":
        return BarrierBreak(self.prob.copy())


class LethalStrike:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "LethalStrike":
        return LethalStrike(Prob(percent))

    def __str__(self):
        return f"Lethal Strike: {self.prob}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "LethalStrike":
        return LethalStrike(self.prob.copy())

class Burrow:
    def __init__(self, count: int, distance: int):
        self.count = count
        self.distance = distance
    
    @staticmethod
    def from_values(count: int, distance: int) -> "Burrow":
        return Burrow(count, distance)
    
    def __str__(self):
        return f"Burrow: {self.count} times, {self.distance} distance"
    
    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Burrow":
        return Burrow(self.count, self.distance)

class Revive:
    def __init__(self, count: int, time: Frames, hp_remain_percent: int):
        self.count = count
        self.time = time
        self.hp_remain_percent = hp_remain_percent
    
    @staticmethod
    def from_values(count: int, time: int, hp_remain_percent: int) -> "Revive":
        return Revive(count, Frames(time), hp_remain_percent)
    
    def __str__(self):
        return f"Revive: {self.count} times, {self.time}, {self.hp_remain_percent}% HP"
    
    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Revive":
        return Revive(self.count, self.time.copy(), self.hp_remain_percent)

class Barrier:
    def __init__(self, hp: int):
        self.hp = hp
    
    @staticmethod
    def from_values(hp: int) -> "Barrier":
        return Barrier(hp)
    
    def __str__(self):
        return f"Barrier: {self.hp} HP"
    
    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Barrier":
        return Barrier(self.hp)

class SurviveLethalStrike:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "SurviveLethalStrike":
        return SurviveLethalStrike(Prob(percent))

    def __str__(self):
        return f"Survive Lethal Strike: {self.prob}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "SurviveLethalStrike":
        return SurviveLethalStrike(self.prob.copy())

class Toxic:
    def __init__(self, prob: Prob, hp_percent: int):
        self.prob = prob
        self.hp_percent = hp_percent

    @staticmethod
    def from_values(prob: int, hp_percent: int) -> "Toxic":
        return Toxic(Prob(prob), hp_percent)
    
    def __str__(self):
        return f"{self.prob} chance to deal {self.hp_percent}% HP damage"
    
    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Toxic":
        return Toxic(self.prob.copy(), self.hp_percent)


class Crit:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "Crit":
        return Crit(Prob(percent))

    def __str__(self):
        return f"Crit: {self.prob}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Crit":
        return Crit(self.prob.copy())


class Freeze:
    def __init__(self, prob: Prob, time: Frames):
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Freeze":
        return Freeze(Prob(prob), Frames(time))

    def __str__(self):
        return f"{self.prob} chance to freeze for {self.time}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Freeze":
        return Freeze(self.prob.copy(), self.time.copy())


class Slow:
    def __init__(self, prob: Prob, time: Frames):
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Slow":
        return Slow(Prob(prob), Frames(time))

    def __str__(self):
        return f"{self.prob} chance to slow for {self.time}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Slow":
        return Slow(self.prob.copy(), self.time.copy())


class Wave:
    def __init__(self, prob: Prob, level: int, is_mini: bool):
        self.prob = prob
        self.level = level
        self.is_mini = is_mini

    @staticmethod
    def from_values(prob: int, level: int, is_mini: bool) -> "Wave":
        return Wave(Prob(prob), level, is_mini)

    def __str__(self):
        return f"{self.prob} chance to summon a level {self.level} {'mini' if self.is_mini else 'regular'} wave"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Wave":
        return Wave(self.prob.copy(), self.level, self.is_mini)


class Weaken:
    def __init__(self, prob: Prob, time: Frames, multiplier: int):
        self.prob = prob
        self.time = time
        self.multiplier = multiplier

    @staticmethod
    def from_values(prob: int, time: int, multiplier: int) -> "Weaken":
        return Weaken(Prob(prob), Frames(time), multiplier)

    def __str__(self):
        return f"{self.prob} chance to weaken for {self.time} by {self.multiplier}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Weaken":
        return Weaken(self.prob.copy(), self.time.copy(), self.multiplier)


class Strengthen:
    def __init__(self, hp: int, multiplier: int):
        self.hp = hp
        self.multiplier = multiplier

    @staticmethod
    def from_values(hp: int, multiplier: int) -> "Strengthen":
        return Strengthen(hp, multiplier)

    def __str__(self):
        return f"Strengthen: {self.hp} HP, {self.multiplier} multiplier"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Strengthen":
        return Strengthen(self.hp, self.multiplier)


class ZLayers:
    def __init__(self, min: int, max: int):
        self.min = min
        self.max = max

    @staticmethod
    def from_values(min: int, max: int) -> "ZLayers":
        return ZLayers(min, max)

    def __str__(self):
        return f"ZLayers: {self.min}-{self.max}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "ZLayers":
        return ZLayers(self.min, self.max)


class Attack:
    def __init__(
        self,
        damage: int,
        foreswing: Frames,
        use_ability: bool,
        long_distance_flag: bool,
        long_distance_start: int,
        long_distance_range: int,
    ):
        self.damage = damage
        self.foreswing = foreswing
        self.use_ability = use_ability
        self.long_distance_flag = long_distance_flag
        self.long_distance_start = long_distance_start
        self.long_distance_range = long_distance_range

    @staticmethod
    def from_values(
        damage: int,
        foreswing: int,
        use_ability: bool,
        long_distance_flag: bool,
        long_distance_start: int,
        long_distance_range: int,
    ) -> "Attack":
        return Attack(
            damage,
            Frames(foreswing),
            use_ability,
            long_distance_flag,
            long_distance_start,
            long_distance_range,
        )

    def set_ld(self, long_distance_start: int, long_distance_range: int):
        if long_distance_start == 0 and long_distance_range == 0:
            self.long_distance_flag = False
        else:
            self.long_distance_flag = True

        self.long_distance_start = long_distance_start
        self.long_distance_range = long_distance_range

    def __str__(self):
        return f"Damage: {self.damage}, Foreswing: {self.foreswing}, Use Ability: {self.use_ability}, Long Distance: {self.long_distance_flag}, Long Distance {self.long_distance_start}-{self.long_distance_range + self.long_distance_start}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Attack":
        return Attack(
            self.damage,
            self.foreswing.copy(),
            self.use_ability,
            self.long_distance_flag,
            self.long_distance_start,
            self.long_distance_range,
        )


class Warp:
    def __init__(self, prob: Prob, time: Frames, min_distance: int, max_distance: int):
        self.prob = prob
        self.time = time
        self.min_distance = min_distance
        self.max_distance = max_distance

    @staticmethod
    def from_values(
        prob: int, time: int, min_distance: int, max_distance: int
    ) -> "Warp":
        return Warp(Prob(prob), Frames(time), min_distance, max_distance)

    def __str__(self):
        return f"{self.prob} chance to warp for {self.time} by {self.min_distance}-{self.max_distance}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Warp":
        return Warp(
            self.prob.copy(),
            self.time.copy(),
            self.min_distance,
            self.max_distance,
        )


class SavageBlow:
    def __init__(self, prob: Prob, multiplier: int):
        self.prob = prob
        self.multiplier = multiplier

    @staticmethod
    def from_values(prob: int, multiplier: int) -> "SavageBlow":
        return SavageBlow(Prob(prob), multiplier)

    def __str__(self):
        return f"{self.prob} chance to savage blow by {self.multiplier}"

    def __repr__(self):
        return str(self)

    def copy(self) -> "SavageBlow":
        return SavageBlow(self.prob.copy(), self.multiplier)


class Dodge:
    def __init__(self, prob: Prob, time: Frames):
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Dodge":
        return Dodge(Prob(prob), Frames(time))

    def __str__(self):
        return f"{self.prob} chance to dodge for {self.time}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Dodge":
        return Dodge(self.prob.copy(), self.time.copy())


class Surge:
    def __init__(self, prob: Prob, start: int, range: int, level: int):
        self.prob = prob
        self.start = start
        self.range = range
        self.level = level

    @staticmethod
    def from_values(prob: int, start: int, range: int, level: int) -> "Surge":
        return Surge(Prob(prob), start, range, level)

    def __str__(self):
        return (
            f"{self.prob} chance to surge at level {self.level} by {self.start // 4}-{(self.range + self.start) // 4}"
        )

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Surge":
        return Surge(self.prob.copy(), self.start, self.range, self.level)

class Shield:
    def __init__(self, hp: int, percent_heal_kb: int):
        self.hp = hp
        self.percent_heal_kb = percent_heal_kb
    
    @staticmethod
    def from_values(hp: int, percent_heal_kb: int) -> "Shield":
        return Shield(hp, percent_heal_kb)
    
    def __str__(self):
        return f"Shield: {self.hp} HP, {self.percent_heal_kb}% KB heal"
    
    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Shield":
        return Shield(self.hp, self.percent_heal_kb)


class Curse:
    def __init__(self, prob: Prob, time: Frames):
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Curse":
        return Curse(Prob(prob), Frames(time))

    def __str__(self):
        return f"{self.prob} chance to curse for {self.time}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "Curse":
        return Curse(self.prob.copy(), self.time.copy())


class ShieldPierce:
    def __init__(self, prob: Prob):
        self.prob = prob

    @staticmethod
    def from_values(prob: int) -> "ShieldPierce":
        return ShieldPierce(Prob(prob))

    def __str__(self):
        return f"{self.prob} chance to pierce shield"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "ShieldPierce":
        return ShieldPierce(self.prob.copy())


class BehemothDodge:
    def __init__(self, prob: Prob, time: Frames):
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "BehemothDodge":
        return BehemothDodge(Prob(prob), Frames(time))

    def __str__(self):
        return f"{self.prob} chance to dodge for {self.time}"

    def __repr__(self):
        return str(self)
    
    def copy(self) -> "BehemothDodge":
        return BehemothDodge(self.prob.copy(), self.time.copy())


class SoulAnimType(enum.Enum):
    NONE = -1
    DEFAULT = 0
    UNCOLORED_MONEKO = 1
    GUDETAMA_EGG = 2
    GUDETAMA_PUDDING = 3
    ENEMY_NISETAMA_ARMY = 4
    NISETAMA_ARMY = 5
    NISETAMA_CAT_ARMY = 6
    CRAZED_MONEKO = 7
    ENEMY_EVA_ANGEL = 8
    ENEMY_GUDETAMA_EGG = 9
    BIG_LEGEND_RARE = 10
    SMALL_LEGEND_RARE = 11
    BIG_MIKU_COLLAB = 12
    SMALL_MIKU_COLLAB = 13
    EVA = 14
    UNUSED_EVA = 15
    COLORED_MONEKO = 16
    YONSHAKUDAMA_FIREWORK_ENEMY = 17
    WORLD_TRIGGER = 18


class SoulAnim:
    def __init__(self, anim_type: int):
        self.anim_type = anim_type
        try:
            self.soul_anim_type = SoulAnimType(anim_type)
        except ValueError:
            self.soul_anim_type = SoulAnimType.NONE

    def set(self, anim_type: int):
        self.anim_type = anim_type
        try:
            self.soul_anim_type = SoulAnimType(anim_type)
        except ValueError:
            self.soul_anim_type = SoulAnimType.NONE

    def __str__(self):
        return f"Soul anim type: {self.soul_anim_type}, {self.anim_type}"

    def __repr__(self):
        return str(self)
    
    def copy(self):
        return SoulAnim(self.anim_type)


class EvolveItem:
    def __init__(self, item_id: int, amount: int):
        self.item_id = item_id
        self.amount = amount
    
    def __str__(self):
        return f"{self.item_id}:{self.amount}"
    
    
class EvolveItems:
    def __init__(self, evolve_items: list[EvolveItem]):
        self.evolve_items = evolve_items

    @staticmethod
    def from_unit_buy_list(raw_data: list[int]):
        items: list[EvolveItem] = []
        for i in range(10):
            item_id = raw_data[28 + i * 2]
            amount = raw_data[29 + i * 2]
            items.append(EvolveItem(item_id, amount))
        return EvolveItems(items)

    def __str__(self):
        return f"Evolve items: {self.evolve_items}"
    
    def __repr__(self):
        return str(self)
    
    def to_list(self):
        items: list[int] = []
        for item in self.evolve_items:
            items.append(item.item_id)
            items.append(item.amount)
        return items