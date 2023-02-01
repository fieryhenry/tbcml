import enum
import random


class Frames:
    """Represents a number of frames, and provides methods for converting to and from seconds, and pair frames."""

    def __init__(self, frames: int):
        """Initializes a new Frames object.

        Args:
            frames (int): The number of frames.
        """
        self.frames = frames

    @staticmethod
    def get_frame_rate() -> int:
        """Gets the frame rate of the game.

        Returns:
            int: The frame rate of the game.
        """
        return 30

    @property
    def seconds(self) -> int:
        """Gets the number of seconds represented by the number of frames.

        Returns:
            int: The number of seconds represented by the number of frames.
        """
        return self.frames // self.get_frame_rate()

    @property
    def pair_frames(self) -> int:
        """Gets the number of pair frames represented by the number of frames. 1 pair frame = 2 frames.

        Returns:
            int: The number of pair frames represented by the number of frames.
        """
        return self.frames // 2

    @staticmethod
    def from_seconds(seconds: int) -> "Frames":
        """Creates a new Frames object from a number of seconds.

        Args:
            seconds (int): The number of seconds.

        Returns:
            Frames: The new Frames object.
        """
        return Frames(seconds * Frames.get_frame_rate())

    @staticmethod
    def from_pair_frames(pair_frames: int) -> "Frames":
        """Creates a new Frames object from a number of pair frames.

        Args:
            pair_frames (int): The number of pair frames.

        Returns:
            Frames: The new Frames object.
        """
        return Frames(pair_frames * 2)

    def __str__(self) -> str:
        """Gets a string representation of the Frames object.

        Returns:
            str: The string representation of the Frames object.
        """
        return f"{self.frames} frames ({self.seconds} seconds)"

    def __repr__(self) -> str:
        """Gets a string representation of the Frames object.

        Returns:
            str: The string representation of the Frames object.
        """
        return str(self)

    def copy(self) -> "Frames":
        """Creates a copy of the Frames object.

        Returns:
            Frames: The copy of the Frames object.
        """
        return Frames(self.frames)


class Prob:
    """Represents a probability as a percentage."""

    def __init__(self, percent: int):
        """Initializes a new Prob object.

        Args:
            percent (int): The probability as a percentage.
        """
        self.percent = percent

    def __str__(self) -> str:
        """Gets a string representation of the Prob object.

        Returns:
            str: The string representation of the Prob object.
        """
        return f"{self.percent}%"

    def __repr__(self) -> str:
        """Gets a string representation of the Prob object.

        Returns:
            str: The string representation of the Prob object.
        """
        return str(self)

    def copy(self) -> "Prob":
        """Creates a copy of the Prob object.

        Returns:
            Prob: The copy of the Prob object.
        """
        return Prob(self.percent)

    def proc(self) -> bool:
        """Determines if the probability is successful.

        Returns:
            bool: True if the probability is successful, False otherwise.
        """
        return random.randint(0, 100) <= self.percent


class Knockback:
    """Represents a knockback probability."""

    def __init__(self, prob: Prob):
        """Initializes a new Knockback object.

        Args:
            prob (Prob): The knockback probability.
        """
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "Knockback":
        """Creates a new Knockback object from a percentage.

        Args:
            percent (int): The knockback probability as a percentage.

        Returns:
            Knockback: The new Knockback object.
        """
        return Knockback(Prob(percent))

    def __str__(self) -> str:
        """Gets a string representation of the Knockback object.

        Returns:
            str: The string representation of the Knockback object.
        """
        return f"Knockback: {self.prob}"

    def __repr__(self) -> str:
        """Gets a string representation of the Knockback object.

        Returns:
            str: The string representation of the Knockback object.
        """
        return str(self)

    def copy(self) -> "Knockback":
        """Creates a copy of the Knockback object.

        Returns:
            Knockback: The copy of the Knockback object.
        """
        return Knockback(self.prob.copy())


class BarrierBreak:
    """Represents a barrier break probability."""

    def __init__(self, prob: Prob):
        """Initializes a new BarrierBreak object.

        Args:
            prob (Prob): The barrier break probability.
        """
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "BarrierBreak":
        """Creates a new BarrierBreak object from a percentage.

        Args:
            percent (int): The barrier break probability as a percentage.

        Returns:
            BarrierBreak: The new BarrierBreak object.
        """
        return BarrierBreak(Prob(percent))

    def __str__(self) -> str:
        """Gets a string representation of the BarrierBreak object.

        Returns:
            str: The string representation of the BarrierBreak object.
        """
        return f"Barrier Break: {self.prob}"

    def __repr__(self) -> str:
        """Gets a string representation of the BarrierBreak object.

        Returns:
            str: The string representation of the BarrierBreak object.
        """
        return str(self)

    def copy(self) -> "BarrierBreak":
        """Creates a copy of the BarrierBreak object.

        Returns:
            BarrierBreak: The copy of the BarrierBreak object.
        """
        return BarrierBreak(self.prob.copy())


class LethalStrike:
    """Represents a lethal strike probability."""

    def __init__(self, prob: Prob):
        """Initializes a new LethalStrike object.

        Args:
            prob (Prob): The lethal strike probability.
        """
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "LethalStrike":
        """Creates a new LethalStrike object from a percentage.

        Args:
            percent (int): The lethal strike probability as a percentage.

        Returns:
            LethalStrike: The new LethalStrike object.
        """
        return LethalStrike(Prob(percent))

    def __str__(self) -> str:
        """Gets a string representation of the LethalStrike object.

        Returns:
            str: The string representation of the LethalStrike object.
        """
        return f"Lethal Strike: {self.prob}"

    def __repr__(self) -> str:
        """Gets a string representation of the LethalStrike object.

        Returns:
            str: The string representation of the LethalStrike object.
        """
        return str(self)

    def copy(self) -> "LethalStrike":
        """Creates a copy of the LethalStrike object.

        Returns:
            LethalStrike: The copy of the LethalStrike object.
        """
        return LethalStrike(self.prob.copy())


class Burrow:
    """Represents a burrow ability."""

    def __init__(self, count: int, distance: int):
        """Initializes a new Burrow object.

        Args:
            count (int): The number of times the unit can burrow.
            distance (int): The distance the unit can burrow.
        """
        self.count = count
        self.distance = distance

    @staticmethod
    def from_values(count: int, distance: int) -> "Burrow":
        """Creates a new Burrow object from values.

        Args:
            count (int): The number of times the unit can burrow.
            distance (int): The distance the unit can burrow.

        Returns:
            Burrow: The new Burrow object.
        """
        return Burrow(count, distance)

    def __str__(self) -> str:
        """Gets a string representation of the Burrow object.

        Returns:
            str: The string representation of the Burrow object.
        """
        return f"Burrow: {self.count} times, {self.distance} distance"

    def __repr__(self) -> str:
        """Gets a string representation of the Burrow object.

        Returns:
            str: The string representation of the Burrow object.
        """
        return str(self)

    def copy(self) -> "Burrow":
        """Creates a copy of the Burrow object.

        Returns:
            Burrow: The copy of the Burrow object.
        """
        return Burrow(self.count, self.distance)


class Revive:
    """Represents a revive ability."""

    def __init__(
        self,
        count: int,
        time: Frames,
        hp_remain_percent: int,
    ):
        """Initializes a new Revive object.

        Args:
            count (int): The number of times the unit can revive.
            time (Frames): The time it takes to revive.
            hp_remain_percent (int): The percentage of HP the unit has after reviving.
        """
        self.count = count
        self.time = time
        self.hp_remain_percent = hp_remain_percent

    @staticmethod
    def from_values(count: int, time: int, hp_remain_percent: int) -> "Revive":
        """Creates a new Revive object from values.

        Args:
            count (int): The number of times the unit can revive.
            time (int): The time it takes to revive in frames.
            hp_remain_percent (int): The percentage of HP the unit has after reviving.

        Returns:
            Revive: The new Revive object.
        """
        return Revive(count, Frames(time), hp_remain_percent)

    def __str__(self) -> str:
        """Gets a string representation of the Revive object.

        Returns:
            str: The string representation of the Revive object.
        """
        return f"Revive: {self.count} times, {self.time}, {self.hp_remain_percent}% HP"

    def __repr__(self) -> str:
        """Gets a string representation of the Revive object.

        Returns:
            str: The string representation of the Revive object.
        """
        return str(self)

    def copy(self) -> "Revive":
        """Creates a copy of the Revive object.

        Returns:
            Revive: The copy of the Revive object.
        """
        return Revive(self.count, self.time.copy(), self.hp_remain_percent)


class Barrier:
    """Represents a barrier ability."""

    def __init__(self, hp: int):
        """Initializes a new Barrier object.

        Args:
            hp (int): The amount of HP the barrier has.
        """
        self.hp = hp

    @staticmethod
    def from_values(hp: int) -> "Barrier":
        """Creates a new Barrier object from values.

        Args:
            hp (int): The amount of HP the barrier has.

        Returns:
            Barrier: The new Barrier object.
        """
        return Barrier(hp)

    def __str__(self) -> str:
        """Gets a string representation of the Barrier object.

        Returns:
            str: The string representation of the Barrier object.
        """
        return f"Barrier: {self.hp} HP"

    def __repr__(self) -> str:
        """Gets a string representation of the Barrier object.

        Returns:
            str: The string representation of the Barrier object.
        """
        return str(self)

    def copy(self) -> "Barrier":
        """Creates a copy of the Barrier object.

        Returns:
            Barrier: The copy of the Barrier object.
        """
        return Barrier(self.hp)


class SurviveLethalStrike:
    """Represents a survive lethal strike ability."""

    def __init__(self, prob: Prob):
        """Initializes a new SurviveLethalStrike object.

        Args:
            prob (Prob): The probability of surviving a lethal strike.
        """
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "SurviveLethalStrike":
        """Creates a new SurviveLethalStrike object from values.

        Args:
            percent (int): The probability of surviving a lethal strike.

        Returns:
            SurviveLethalStrike: The new SurviveLethalStrike object.
        """
        return SurviveLethalStrike(Prob(percent))

    def __str__(self) -> str:
        """Gets a string representation of the SurviveLethalStrike object.

        Returns:
            str: The string representation of the SurviveLethalStrike object.
        """
        return f"Survive Lethal Strike: {self.prob}"

    def __repr__(self) -> str:
        """Gets a string representation of the SurviveLethalStrike object.

        Returns:
            str: The string representation of the SurviveLethalStrike object.
        """
        return str(self)

    def copy(self) -> "SurviveLethalStrike":
        """Creates a copy of the SurviveLethalStrike object.

        Returns:
            SurviveLethalStrike: The copy of the SurviveLethalStrike object.
        """
        return SurviveLethalStrike(self.prob.copy())


class Toxic:
    """Represents a toxic ability."""

    def __init__(self, prob: Prob, hp_percent: int):
        """Initializes a new Toxic object.

        Args:
            prob (Prob): The probability of the toxic ability.
            hp_percent (int): The percentage of HP damage the toxic ability deals.
        """
        self.prob = prob
        self.hp_percent = hp_percent

    @staticmethod
    def from_values(prob: int, hp_percent: int) -> "Toxic":
        """Creates a new Toxic object from values.

        Args:
            prob (int): The probability of the toxic ability.
            hp_percent (int): The percentage of HP damage the toxic ability deals.

        Returns:
            Toxic: The new Toxic object.
        """
        return Toxic(Prob(prob), hp_percent)

    def __str__(self) -> str:
        """Gets a string representation of the Toxic object.

        Returns:
            str: The string representation of the Toxic object.
        """
        return f"{self.prob} chance to deal {self.hp_percent}% HP damage"

    def __repr__(self) -> str:
        """Gets a string representation of the Toxic object.

        Returns:
            str: The string representation of the Toxic object.
        """
        return str(self)

    def copy(self) -> "Toxic":
        """Creates a copy of the Toxic object.

        Returns:
            Toxic: The copy of the Toxic object.
        """
        return Toxic(self.prob.copy(), self.hp_percent)


class Crit:
    """Represents a crit ability."""

    def __init__(self, prob: Prob):
        """Initializes a new Crit object.

        Args:
            prob (Prob): The probability of the crit ability.
        """
        self.prob = prob

    @staticmethod
    def from_values(percent: int) -> "Crit":
        """Creates a new Crit object from values.

        Args:
            percent (int): The probability of the crit ability.

        Returns:
            Crit: The new Crit object.
        """
        return Crit(Prob(percent))

    def __str__(self) -> str:
        """Gets a string representation of the Crit object.

        Returns:
            str: The string representation of the Crit object.
        """
        return f"Crit: {self.prob}"

    def __repr__(self) -> str:
        """Gets a string representation of the Crit object.

        Returns:
            str: The string representation of the Crit object.
        """
        return str(self)

    def copy(self) -> "Crit":
        """Creates a copy of the Crit object.

        Returns:
            Crit: The copy of the Crit object.
        """
        return Crit(self.prob.copy())


class Freeze:
    """Represents a freeze ability."""

    def __init__(self, prob: Prob, time: Frames):
        """Initializes a new Freeze object.

        Args:
            prob (Prob): The probability of the freeze ability.
            time (Frames): The duration of the freeze ability.
        """
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Freeze":
        """Creates a new Freeze object from values.

        Args:
            prob (int): The probability of the freeze ability.
            time (int): The duration of the freeze ability.

        Returns:
            Freeze: The new Freeze object.
        """
        return Freeze(Prob(prob), Frames(time))

    def __str__(self) -> str:
        """Gets a string representation of the Freeze object.

        Returns:
            str: The string representation of the Freeze object.
        """
        return f"{self.prob} chance to freeze for {self.time}"

    def __repr__(self) -> str:
        """Gets a string representation of the Freeze object.

        Returns:
            str: The string representation of the Freeze object.
        """
        return str(self)

    def copy(self) -> "Freeze":
        """Creates a copy of the Freeze object.

        Returns:
            Freeze: The copy of the Freeze object.
        """
        return Freeze(self.prob.copy(), self.time.copy())


class Slow:
    """Represents a slow ability."""

    def __init__(self, prob: Prob, time: Frames):
        """Initializes a new Slow object.

        Args:
            prob (Prob): The probability of the slow ability.
            time (Frames): The duration of the slow ability.
        """
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Slow":
        """Creates a new Slow object from values.

        Args:
            prob (int): The probability of the slow ability.
            time (int): The duration of the slow ability.

        Returns:
            Slow: The new Slow object.
        """
        return Slow(Prob(prob), Frames(time))

    def __str__(self) -> str:
        """Gets a string representation of the Slow object.

        Returns:
            str: The string representation of the Slow object.
        """
        return f"{self.prob} chance to slow for {self.time}"

    def __repr__(self) -> str:
        """Gets a string representation of the Slow object.

        Returns:
            str: The string representation of the Slow object.
        """
        return str(self)

    def copy(self) -> "Slow":
        """Creates a copy of the Slow object.

        Returns:
            Slow: The copy of the Slow object.
        """
        return Slow(self.prob.copy(), self.time.copy())


class Wave:
    """Represents a wave ability."""

    def __init__(self, prob: Prob, level: int, is_mini: bool):
        """Initializes a new Wave object.

        Args:
            prob (Prob): The probability of the wave ability.
            level (int): The level of the wave ability.
            is_mini (bool): Whether the wave is a mini wave.
        """
        self.prob = prob
        self.level = level
        self.is_mini = is_mini

    @staticmethod
    def from_values(prob: int, level: int, is_mini: bool) -> "Wave":
        """Creates a new Wave object from values.

        Args:
            prob (int): The probability of the wave ability.
            level (int): The level of the wave ability.
            is_mini (bool): Whether the wave is a mini wave.

        Returns:
            Wave: The new Wave object.
        """
        return Wave(Prob(prob), level, is_mini)

    def __str__(self) -> str:
        """Gets a string representation of the Wave object.

        Returns:
            str: The string representation of the Wave object.
        """
        return f"{self.prob} chance to summon a level {self.level} {'mini' if self.is_mini else 'regular'} wave"

    def __repr__(self) -> str:
        """Gets a string representation of the Wave object.

        Returns:
            str: The string representation of the Wave object.
        """
        return str(self)

    def copy(self) -> "Wave":
        """Creates a copy of the Wave object.

        Returns:
            Wave: The copy of the Wave object.
        """
        return Wave(self.prob.copy(), self.level, self.is_mini)


class Weaken:
    """Represents a weaken ability."""

    def __init__(self, prob: Prob, time: Frames, weaken_percent: int):
        """Initializes a new Weaken object.

        Args:
            prob (Prob): The probability of the weaken ability.
            time (Frames): The duration of the weaken ability.
            weaken_percent (int): How much the weaken ability weakens the target.
        """
        self.prob = prob
        self.time = time
        self.multiplier = weaken_percent

    @staticmethod
    def from_values(prob: int, time: int, weaken_percent: int) -> "Weaken":
        """Creates a new Weaken object from values.

        Args:
            prob (int): The probability of the weaken ability.
            time (int): The duration of the weaken ability.
            weaken_percent (int): How much the weaken ability weakens the target to.

        Returns:
            Weaken: The new Weaken object.
        """
        return Weaken(Prob(prob), Frames(time), weaken_percent)

    def __str__(self) -> str:
        """Gets a string representation of the Weaken object.

        Returns:
            str: The string representation of the Weaken object.
        """
        return f"{self.prob} chance to weaken for {self.time} to {self.multiplier}%"

    def __repr__(self) -> str:
        """Gets a string representation of the Weaken object.

        Returns:
            str: The string representation of the Weaken object.
        """
        return str(self)

    def copy(self) -> "Weaken":
        """Creates a copy of the Weaken object.

        Returns:
            Weaken: The copy of the Weaken object.
        """
        return Weaken(self.prob.copy(), self.time.copy(), self.multiplier)


class Strengthen:
    """Represents a strengthen ability."""

    def __init__(self, hp_percent: int, multiplier_percent: int):
        """Initializes a new Strengthen object.

        Args:
            hp_percent (int): At what percent of the target's HP the strengthen ability activates.
            multiplier_percent (int): How much the strengthen ability strengthens the target.
        """
        self.hp_percent = hp_percent
        self.multiplier_percent = multiplier_percent

    @staticmethod
    def from_values(hp_percent: int, multiplier_percent: int) -> "Strengthen":
        """Creates a new Strengthen object from values.

        Args:
            hp_percent (int): At what percent of the target's HP the strengthen ability activates.
            multiplier_percent (int): How much the strengthen ability strengthens the target.

        Returns:
            Strengthen: The new Strengthen object.
        """
        return Strengthen(hp_percent, multiplier_percent)

    def __str__(self) -> str:
        """Gets a string representation of the Strengthen object.

        Returns:
            str: The string representation of the Strengthen object.
        """
        return f"Strengthen at {self.hp_percent}% HP by {self.multiplier_percent}%"

    def __repr__(self) -> str:
        """Gets a string representation of the Strengthen object.

        Returns:
            str: The string representation of the Strengthen object.
        """
        return str(self)

    def copy(self) -> "Strengthen":
        """Creates a copy of the Strengthen object.

        Returns:
            Strengthen: The copy of the Strengthen object.
        """
        return Strengthen(self.hp_percent, self.multiplier_percent)


class ZLayers:
    """Represents a ZLayer range."""

    def __init__(self, min: int, max: int):
        """Initializes a new ZLayers object.

        Args:
            min (int): Minimum z layer.
            max (int): Maximum z layer.
        """
        self.min = min
        self.max = max

    @staticmethod
    def from_values(min: int, max: int) -> "ZLayers":
        """Creates a new ZLayers object from values.

        Args:
            min (int): Minimum z layer.
            max (int): Maximum z layer.

        Returns:
            ZLayers: The new ZLayers object.
        """
        return ZLayers(min, max)

    def __str__(self) -> str:
        """Gets a string representation of the ZLayers object.

        Returns:
            str: The string representation of the ZLayers object.
        """
        return f"ZLayers: {self.min}-{self.max}"

    def __repr__(self) -> str:
        """Gets a string representation of the ZLayers object.

        Returns:
            str: The string representation of the ZLayers object.
        """
        return str(self)

    def copy(self) -> "ZLayers":
        """Creates a copy of the ZLayers object.

        Returns:
            ZLayers: The copy of the ZLayers object.
        """
        return ZLayers(self.min, self.max)


class Attack:
    """Represents an attack."""

    def __init__(
        self,
        damage: int,
        foreswing: Frames,
        use_ability: bool,
        long_distance_flag: bool,
        long_distance_start: int,
        long_distance_range: int,
    ):
        """Initializes a new Attack object.

        Args:
            damage (int): Base damage of the attack.
            foreswing (Frames): The number of frames before the attack hits.
            use_ability (bool): Whether or not the attack uses any of the character's abilities.
            long_distance_flag (bool): Whether or not the attack is a long distance attack.
            long_distance_start (int): The start range of the long distance attack.
            long_distance_range (int): The range of the long distance attack. The end range is long_distance_start + long_distance_range.
        """
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
        """Creates a new Attack object from values.

        Args:
            damage (int): The base damage of the attack.
            foreswing (int): The number of frames before the attack hits.
            use_ability (bool): Whether or not the attack uses any of the character's abilities.
            long_distance_flag (bool): Whether or not the attack is a long distance attack.
            long_distance_start (int): The start range of the long distance attack.
            long_distance_range (int): The range of the long distance attack. The end range is long_distance_start + long_distance_range.

        Returns:
            Attack: The new Attack object.
        """
        return Attack(
            damage,
            Frames(foreswing),
            use_ability,
            long_distance_flag,
            long_distance_start,
            long_distance_range,
        )

    def set_ld(self, long_distance_start: int, long_distance_range: int):
        """Sets the long distance values of the attack.

        Args:
            long_distance_start (int): Start range of the long distance attack.
            long_distance_range (int): Range of the long distance attack. The end range is long_distance_start + long_distance_range.
        """
        if long_distance_start == 0 and long_distance_range == 0:
            self.long_distance_flag = False
        else:
            self.long_distance_flag = True

        self.long_distance_start = long_distance_start
        self.long_distance_range = long_distance_range

    def __str__(self) -> str:
        """Gets a string representation of the Attack object.

        Returns:
            str: The string representation of the Attack object.
        """
        return f"Damage: {self.damage}, Foreswing: {self.foreswing}, Use Ability: {self.use_ability}, Long Distance: {self.long_distance_flag}, Long Distance {self.long_distance_start}-{self.long_distance_range + self.long_distance_start}"

    def __repr__(self) -> str:
        """Gets a string representation of the Attack object.

        Returns:
            str: The string representation of the Attack object.
        """
        return str(self)

    def copy(self) -> "Attack":
        """Creates a copy of the Attack object.

        Returns:
            Attack: The copy of the Attack object.
        """
        return Attack(
            self.damage,
            self.foreswing.copy(),
            self.use_ability,
            self.long_distance_flag,
            self.long_distance_start,
            self.long_distance_range,
        )


class Warp:
    """Represents a warp."""

    def __init__(self, prob: Prob, time: Frames, min_distance: int, max_distance: int):
        """Initializes a new Warp object.

        Args:
            prob (Prob): The probability of the warp.
            time (Frames): The number of frames the warp lasts.
            min_distance (int): The minimum distance the warp can move the unit.
            max_distance (int): The maximum distance the warp can move the unit.
        """
        self.prob = prob
        self.time = time
        self.min_distance = min_distance
        self.max_distance = max_distance

    @staticmethod
    def from_values(
        prob: int,
        time: int,
        min_distance: int,
        max_distance: int,
    ) -> "Warp":
        """Creates a new Warp object from values.

        Args:
            prob (int): The probability of the warp.
            time (int): The number of frames the warp lasts.
            min_distance (int): The minimum distance the warp can move the unit.
            max_distance (int): The maximum distance the warp can move the unit.

        Returns:
            Warp: The new Warp object.
        """
        return Warp(Prob(prob), Frames(time), min_distance, max_distance)

    def __str__(self) -> str:
        """Gets a string representation of the Warp object.

        Returns:
            str: The string representation of the Warp object.
        """
        return f"{self.prob} chance to warp for {self.time} by {self.min_distance}-{self.max_distance}"

    def __repr__(self) -> str:
        """Gets a string representation of the Warp object.

        Returns:
            str: The string representation of the Warp object.
        """
        return str(self)

    def copy(self) -> "Warp":
        """Creates a copy of the Warp object.

        Returns:
            Warp: The copy of the Warp object.
        """
        return Warp(
            self.prob.copy(),
            self.time.copy(),
            self.min_distance,
            self.max_distance,
        )


class SavageBlow:
    """Represents a savage blow."""

    def __init__(
        self,
        prob: Prob,
        added_percentage_multiplier: int,
    ):
        """Initializes a new SavageBlow object.

        Args:
            prob (Prob): The probability of the savage blow.
            added_percentage_multiplier (int): The multiplier as a percentage to add to the damage. For example, 50 would add 50% to the damage.
        """
        self.prob = prob
        self.multiplier = added_percentage_multiplier

    @staticmethod
    def from_values(prob: int, multiplier: int) -> "SavageBlow":
        """Creates a new SavageBlow object from values.

        Args:
            prob (int): The probability of the savage blow.
            multiplier (int): The multiplier as a percentage to add to the damage. For example, 50 would add 50% to the damage.

        Returns:
            SavageBlow: The new SavageBlow object.
        """
        return SavageBlow(Prob(prob), multiplier)

    def __str__(self) -> str:
        """Gets a string representation of the SavageBlow object.

        Returns:
            str: The string representation of the SavageBlow object.
        """
        return f"{self.prob} chance to savage blow for +{self.multiplier}%"

    def __repr__(self) -> str:
        """Gets a string representation of the SavageBlow object.

        Returns:
            str: The string representation of the SavageBlow object.
        """
        return str(self)

    def copy(self) -> "SavageBlow":
        """Creates a copy of the SavageBlow object.

        Returns:
            SavageBlow: The copy of the SavageBlow object.
        """
        return SavageBlow(self.prob.copy(), self.multiplier)


class Dodge:
    """Represents a dodge."""

    def __init__(self, prob: Prob, time: Frames):
        """Initializes a new Dodge object.

        Args:
            prob (Prob): The probability of the dodge.
            time (Frames): The number of frames the dodge lasts.
        """
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(prob: int, time: int) -> "Dodge":
        """Creates a new Dodge object from values.

        Args:
            prob (int): The probability of the dodge.
            time (int): The number of frames the dodge lasts.

        Returns:
            Dodge: The new Dodge object.
        """
        return Dodge(Prob(prob), Frames(time))

    def __str__(self) -> str:
        """Gets a string representation of the Dodge object.

        Returns:
            str: The string representation of the Dodge object.
        """
        return f"{self.prob} chance to dodge for {self.time}"

    def __repr__(self) -> str:
        """Gets a string representation of the Dodge object.

        Returns:
            str: The string representation of the Dodge object.
        """
        return str(self)

    def copy(self) -> "Dodge":
        return Dodge(self.prob.copy(), self.time.copy())


class Surge:
    """Represents a surge attack."""

    def __init__(
        self,
        prob: Prob,
        start: int,
        range: int,
        level: int,
    ):
        """Initializes a new Surge object.

        Args:
            prob (Prob): The probability of the surge.
            start (int): The start range of the surge.
            range (int): The range of the surge. The end range is start + range.
            level (int): The level of the surge. Each level increases the duration by 20 frames.
        """
        self.prob = prob
        self.start = start
        self.range = range
        self.level = level

    @staticmethod
    def from_values(
        prob: int,
        start: int,
        range: int,
        level: int,
    ) -> "Surge":
        """Creates a new Surge object from values.

        Args:
            prob (int): The probability of the surge.
            start (int): The start range of the surge.
            range (int): The range of the surge. The end range is start + range.
            level (int): The level of the surge. Each level increases the duration by 20 frames.

        Returns:
            Surge: The new Surge object.
        """
        return Surge(Prob(prob), start, range, level)

    def __str__(self) -> str:
        """Gets a string representation of the Surge object.

        Returns:
            str: The string representation of the Surge object.
        """
        return f"{self.prob} chance to surge at level {self.level} by {self.start // 4}-{(self.range + self.start) // 4}"

    def __repr__(self) -> str:
        """Gets a string representation of the Surge object.

        Returns:
            str: The string representation of the Surge object.
        """
        return str(self)

    def copy(self) -> "Surge":
        """Creates a copy of the Surge object.

        Returns:
            Surge: The copy of the Surge object.
        """
        return Surge(self.prob.copy(), self.start, self.range, self.level)

    def get_time(self) -> Frames:
        """Gets the duration of the surge.

        Returns:
            Frames: The duration of the surge.
        """
        return Frames(self.level * 20)


class Shield:
    """Represents an aku shield."""

    def __init__(
        self,
        hp: int,
        percent_heal_kb: int,
    ):
        """Initializes a new Shield object.

        Args:
            hp (int): HP of the shield.
            percent_heal_kb (int): The percentage of sheild hp to heal on KB.
        """
        self.hp = hp
        self.percent_heal_kb = percent_heal_kb

    @staticmethod
    def from_values(hp: int, percent_heal_kb: int) -> "Shield":
        """Creates a new Shield object from values.

        Args:
            hp (int): HP of the shield.
            percent_heal_kb (int): The percentage of sheild hp to heal on KB.

        Returns:
            Shield: The new Shield object.
        """
        return Shield(hp, percent_heal_kb)

    def __str__(self) -> str:
        """Gets a string representation of the Shield object.

        Returns:
            str: The string representation of the Shield object.
        """
        return f"Shield: {self.hp} HP, {self.percent_heal_kb}% KB heal"

    def __repr__(self) -> str:
        """Gets a string representation of the Shield object.

        Returns:
            str: The string representation of the Shield object.
        """
        return str(self)

    def copy(self) -> "Shield":
        """Creates a copy of the Shield object.

        Returns:
            Shield: The copy of the Shield object.
        """
        return Shield(self.hp, self.percent_heal_kb)


class Curse:
    """Represents a curse attack."""

    def __init__(
        self,
        prob: Prob,
        time: Frames,
    ):
        """Initializes a new Curse object.

        Args:
            prob (Prob): The probability of the curse.
            time (Frames): The duration of the curse.
        """
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(
        prob: int,
        time: int,
    ) -> "Curse":
        """Creates a new Curse object from values.

        Args:
            prob (int): The probability of the curse.
            time (int): The duration of the curse.

        Returns:
            Curse: The new Curse object.
        """
        return Curse(Prob(prob), Frames(time))

    def __str__(self) -> str:
        """Gets a string representation of the Curse object.

        Returns:
            str: The string representation of the Curse object.
        """
        return f"{self.prob} chance to curse for {self.time}"

    def __repr__(self) -> str:
        """Gets a string representation of the Curse object.

        Returns:
            str: The string representation of the Curse object.
        """
        return str(self)

    def copy(self) -> "Curse":
        """Creates a copy of the Curse object.

        Returns:
            Curse: The copy of the Curse object.
        """
        return Curse(self.prob.copy(), self.time.copy())


class ShieldPierce:
    """Represents a shield pierce ability."""

    def __init__(self, prob: Prob):
        """Initializes a new ShieldPierce object.

        Args:
            prob (Prob): The probability of the piercing an aku shield.
        """
        self.prob = prob

    @staticmethod
    def from_values(prob: int) -> "ShieldPierce":
        """Creates a new ShieldPierce object from values.

        Args:
            prob (int): The probability of the piercing an aku shield.

        Returns:
            ShieldPierce: The new ShieldPierce object.
        """
        return ShieldPierce(Prob(prob))

    def __str__(self) -> str:
        """Gets a string representation of the ShieldPierce object.

        Returns:
            str: The string representation of the ShieldPierce object.
        """
        return f"{self.prob} chance to pierce shield"

    def __repr__(self) -> str:
        """Gets a string representation of the ShieldPierce object.

        Returns:
            str: The string representation of the ShieldPierce object.
        """
        return str(self)

    def copy(self) -> "ShieldPierce":
        """Creates a copy of the ShieldPierce object.

        Returns:
            ShieldPierce: The copy of the ShieldPierce object.
        """
        return ShieldPierce(self.prob.copy())


class BehemothDodge:
    """Represents a behemoth dodge ability."""

    def __init__(
        self,
        prob: Prob,
        time: Frames,
    ):
        """Initializes a new BehemothDodge object.

        Args:
            prob (Prob): The probability of dodging a behemoth attack.
            time (Frames): The duration of the dodge.
        """
        self.prob = prob
        self.time = time

    @staticmethod
    def from_values(
        prob: int,
        time: int,
    ) -> "BehemothDodge":
        """Creates a new BehemothDodge object from values.

        Args:
            prob (int): The probability of dodging a behemoth attack.
            time (int): The duration of the dodge.

        Returns:
            BehemothDodge: The new BehemothDodge object.
        """
        return BehemothDodge(Prob(prob), Frames(time))

    def __str__(self) -> str:
        """Gets a string representation of the BehemothDodge object.

        Returns:
            str: The string representation of the BehemothDodge object.
        """
        return f"{self.prob} chance to dodge for {self.time}"

    def __repr__(self) -> str:
        """Gets a string representation of the BehemothDodge object.

        Returns:
            str: The string representation of the BehemothDodge object.
        """
        return str(self)

    def copy(self) -> "BehemothDodge":
        """Creates a copy of the BehemothDodge object.

        Returns:
            BehemothDodge: The copy of the BehemothDodge object.
        """
        return BehemothDodge(self.prob.copy(), self.time.copy())


class SoulAnimType(enum.Enum):
    """Represents the type of a soul animation."""

    NONE = -1
    """No soul animation."""
    DEFAULT = 0
    """The default soul animation."""
    UNCOLORED_MONEKO = 1
    """The uncolored moneko soul animation."""
    GUDETAMA_EGG = 2
    """The gudetama egg soul animation."""
    GUDETAMA_PUDDING = 3
    """The gudetama pudding soul animation."""
    ENEMY_NISETAMA_ARMY = 4
    """The enemy nisetama army soul animation."""
    NISETAMA_ARMY = 5
    """The nisetama army soul animation."""
    NISETAMA_CAT_ARMY = 6
    """The nisetama cat army soul animation."""
    CRAZED_MONEKO = 7
    """The crazed moneko soul animation."""
    ENEMY_EVA_ANGEL = 8
    """The enemy eva angel soul animation."""
    ENEMY_GUDETAMA_EGG = 9
    """The enemy gudetama egg soul animation."""
    BIG_LEGEND_RARE = 10
    """The big legend rare soul animation."""
    SMALL_LEGEND_RARE = 11
    """The small legend rare soul animation."""
    BIG_MIKU_COLLAB = 12
    """The big miku collab soul animation."""
    SMALL_MIKU_COLLAB = 13
    """The small miku collab soul animation."""
    EVA = 14
    """The eva soul animation."""
    UNUSED_EVA = 15
    """The unused eva soul animation."""
    COLORED_MONEKO = 16
    """The colored moneko soul animation."""
    YONSHAKUDAMA_FIREWORK_ENEMY = 17
    """The yonshakudama firework enemy soul animation."""
    WORLD_TRIGGER = 18
    """The world trigger soul animation."""


class SoulAnim:
    """Represents a soul animation."""

    def __init__(self, anim_type: int):
        """Initializes a new SoulAnim object.

        Args:
            anim_type (int): The type of the soul animation.
        """
        self.anim_type = anim_type
        try:
            self.soul_anim_type = SoulAnimType(anim_type)
        except ValueError:
            self.soul_anim_type = SoulAnimType.NONE

    def set(self, anim_type: int):
        """Sets the type of the soul animation.

        Args:
            anim_type (int): The type of the soul animation.
        """
        self.anim_type = anim_type
        try:
            self.soul_anim_type = SoulAnimType(anim_type)
        except ValueError:
            self.soul_anim_type = SoulAnimType.NONE

    def __str__(self) -> str:
        """Gets a string representation of the SoulAnim object.

        Returns:
            str: The string representation of the SoulAnim object.
        """
        return f"Soul anim type: {self.soul_anim_type}, {self.anim_type}"

    def __repr__(self) -> str:
        """Gets a string representation of the SoulAnim object.

        Returns:
            str: The string representation of the SoulAnim object.
        """
        return str(self)

    def copy(self) -> "SoulAnim":
        """Creates a copy of the SoulAnim object.

        Returns:
            SoulAnim: The copy of the SoulAnim object.
        """
        return SoulAnim(self.anim_type)


class EvolveItem:
    """Represents an item used to evolve a unit."""

    def __init__(
        self,
        item_id: int,
        amount: int,
    ):
        """Initializes a new EvolveItem object.

        Args:
            item_id (int): The ID of the item.
            amount (int): The amount of the item.
        """
        self.item_id = item_id
        self.amount = amount

    def __str__(self) -> str:
        """Gets a string representation of the EvolveItem object.

        Returns:
            str: The string representation of the EvolveItem object.
        """
        return f"{self.item_id}:{self.amount}"

    def __repr__(self) -> str:
        """Gets a string representation of the EvolveItem object.

        Returns:
            str: The string representation of the EvolveItem object.
        """
        return str(self)


class EvolveItems:
    """Represents the items used to evolve a unit."""

    def __init__(self, evolve_items: list[EvolveItem]):
        """Initializes a new EvolveItems object.

        Args:
            evolve_items (list[EvolveItem]): The items used to evolve a unit.
        """
        self.evolve_items = evolve_items

    @staticmethod
    def from_unit_buy_list(raw_data: list[int]) -> "EvolveItems":
        """Creates a new EvolveItems object from a row from unitbuy.csv.

        Args:
            raw_data (list[int]): The row from unitbuy.csv.

        Returns:
            EvolveItems: The EvolveItems object.
        """
        items: list[EvolveItem] = []
        for i in range(10):
            item_id = raw_data[28 + i * 2]
            amount = raw_data[29 + i * 2]
            items.append(EvolveItem(item_id, amount))
        return EvolveItems(items)

    def __str__(self) -> str:
        """Gets a string representation of the EvolveItems object.

        Returns:
            str: The string representation of the EvolveItems object.
        """
        return f"Evolve items: {self.evolve_items}"

    def __repr__(self) -> str:
        """Gets a string representation of the EvolveItems object.

        Returns:
            str: The string representation of the EvolveItems object.
        """
        return str(self)

    def to_list(self) -> list[int]:
        """Gets a list representation of the EvolveItems object.

        Returns:
            list[int]: The list representation of the EvolveItems object.
        """
        items: list[int] = []
        for item in self.evolve_items:
            items.append(item.item_id)
            items.append(item.amount)
        return items
