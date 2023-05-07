"""Module for handling the screen shake effects in battle. This feature was added in version 11.8.0"""
import enum
from tbcml.core.game_data import pack
from tbcml.core import io


class ShakeLocation(enum.Enum):
    """At what location the shake effect should be applied to."""

    BASE_HIT = 0
    """The shake effect is applied when the cat base is hit."""
    BOSS_WAVE = 1
    """The shake effect is applied when an ending main story boss appears (e.g The Face, Nyandam, etc)"""


class ShakeEffect:
    def __init__(
        self,
        shake_location: ShakeLocation,
        start_distance: int,
        end_distance: int,
        frames: int,
        events_until_next_shake: int,
        reset_frame: int,
        priority: int,
    ):
        """Initializes a new Screenshake Effect.

        Args:
            shake_location (ShakeLocation): At what points the shake effect should occur.
            start_distance (int): The starting camera distance of the shake effect.
            end_distance (int): The ending camera distance of the shake effect.
            frames (int): The number of frames the shake effect should last (30 frames = 1 second) (The time taken for the camera to move from start_distance to end_distance)
            events_until_next_shake (int): The number of events that must occur before the shake effect can occur again.
            reset_frame (int): ???
            priority (int): ???
        """

        self.shake_location = shake_location
        self.start_distance = start_distance
        self.end_distance = end_distance
        self.frames = frames
        self.events_until_next_shake = events_until_next_shake
        self.reset_frame = reset_frame
        self.priority = priority


class ShakeEffects:
    def __init__(self, effects: dict[int, ShakeEffect]):
        """Initializes a new ShakeEffects object. This object is a collection of ShakeEffects.

        Args:
            effects (dict[int, ShakeEffect]): The ShakeEffects to add to the ShakeEffects object.
        """
        self.effects = effects

    @staticmethod
    def get_file_name() -> str:
        """Gets the name of the in-game file that contains the ShakeEffects.

        Returns:
            str: The name of the in-game file that contains the ShakeEffects.
        """
        return "battleshake_setting.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "ShakeEffects":
        """Loads the ShakeEffects from the game data.

        Args:
            game_data (pack.GamePacks): The game data to load the ShakeEffects from.

        Returns:
            ShakeEffects: The ShakeEffects loaded from the game data.
        """
        file = game_data.find_file(ShakeEffects.get_file_name())
        if file is None:
            return ShakeEffects.create_empty()
        csv = io.bc_csv.CSV(file.dec_data)
        effects: dict[int, ShakeEffect] = {}
        for i, line in enumerate(csv.lines):
            shake_location = ShakeLocation(int(line[0]))
            start_distance = int(line[1])
            end_distance = int(line[2])
            frames = int(line[3])
            events_until_next_shake = int(line[4])
            reset_frame = int(line[5])
            priority = int(line[6])
            effects[i] = ShakeEffect(
                shake_location,
                start_distance,
                end_distance,
                frames,
                events_until_next_shake,
                reset_frame,
                priority,
            )
        return ShakeEffects(effects)

    def to_game_data(self, game_data: "pack.GamePacks"):
        """Writes the ShakeEffects to the game data.

        Args:
            game_data (pack.GamePacks): The game data to write the ShakeEffects to.
        """
        file = game_data.find_file(self.get_file_name())
        if file is None:
            return
        csv = io.bc_csv.CSV(file.dec_data)
        remaing_effects = self.effects.copy()
        for i, line in enumerate(csv.lines):
            try:
                effect = self.effects[i]
            except KeyError:
                continue
            line[0] = str(effect.shake_location.value)
            line[1] = str(effect.start_distance)
            line[2] = str(effect.end_distance)
            line[3] = str(effect.frames)
            line[4] = str(effect.events_until_next_shake)
            line[5] = str(effect.reset_frame)
            line[6] = str(effect.priority)
            csv.lines[i] = line
            remaing_effects.pop(i)

        for i, effect in remaing_effects.items():
            a_line = [
                str(effect.shake_location.value),
                str(effect.start_distance),
                str(effect.end_distance),
                str(effect.frames),
                str(effect.events_until_next_shake),
                str(effect.reset_frame),
                str(effect.priority),
            ]
            csv.lines.append(a_line)

        game_data.set_file(self.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "ShakeEffects":
        """Creates an empty ShakeEffects object.

        Returns:
            ShakeEffects: The empty ShakeEffects object.
        """
        return ShakeEffects({})
