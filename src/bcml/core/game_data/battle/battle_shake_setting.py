"""Module for handling the screen shake effects in battle. This feature was added in version 11.8.0"""
import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class ShakeLocation(enum.Enum):
    """At what location the shake effect should be applied to.

    Attributes:
        BASE_HIT: The shake effect is applied when the cat base is hit.
        BOSS_WAVE: The shake effect is applied when an ending main story boss appears (e.g The Face, Nyandam, etc)
    """

    BASE_HIT = 0
    BOSS_WAVE = 1


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

    def serialize(self) -> dict[str, Any]:
        """Serializes the ShakeEffect into a dictionary that can be written to a json file.

        Returns:
            dict[str, Any]: The serialized ShakeEffect.
        """
        return {
            "shake_location": self.shake_location.value,
            "start_distance": self.start_distance,
            "end_distance": self.end_distance,
            "frames": self.frames,
            "events_until_next_shake": self.events_until_next_shake,
            "reset_frame": self.reset_frame,
            "priority": self.priority,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ShakeEffect":
        """Deserializes a ShakeEffect from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize from.

        Returns:
            ShakeEffect: The deserialized ShakeEffect.
        """
        return ShakeEffect(
            ShakeLocation(data["shake_location"]),
            data["start_distance"],
            data["end_distance"],
            data["frames"],
            data["events_until_next_shake"],
            data["reset_frame"],
            data["priority"],
        )


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
    def from_game_data(game_data: "pack.GamePacks") -> Optional["ShakeEffects"]:
        """Loads the ShakeEffects from the game data.

        Args:
            game_data (pack.GamePacks): The game data to load the ShakeEffects from.

        Returns:
            ShakeEffects: The ShakeEffects loaded from the game data.
        """
        file = game_data.find_file(ShakeEffects.get_file_name())
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        effects: dict[int, ShakeEffect] = {}
        for i, line in enumerate(csv.lines):
            shake_location = ShakeLocation(line[0].to_int())
            start_distance = line[1].to_int()
            end_distance = line[2].to_int()
            frames = line[3].to_int()
            events_until_next_shake = line[4].to_int()
            reset_frame = line[5].to_int()
            priority = line[6].to_int()
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
            line[0].set(effect.shake_location.value)
            line[1].set(effect.start_distance)
            line[2].set(effect.end_distance)
            line[3].set(effect.frames)
            line[4].set(effect.events_until_next_shake)
            line[5].set(effect.reset_frame)
            line[6].set(effect.priority)
            csv.set_line(i, line)
            remaing_effects.pop(i)

        for i, effect in remaing_effects.items():
            line = [
                effect.shake_location.value,
                effect.start_distance,
                effect.end_distance,
                effect.frames,
                effect.events_until_next_shake,
                effect.reset_frame,
                effect.priority,
            ]
            csv.add_line(line)

        game_data.set_file(self.get_file_name(), csv.to_data())

    def serialize(self) -> dict[str, Any]:
        """Serializes the ShakeEffects into a dictionary that can be written to a json file.

        Returns:
            dict[str, Any]: The serialized ShakeEffects.
        """        
        return {
            "effects": {i: effect.serialize() for i, effect in self.effects.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ShakeEffects":
        """Deserializes a ShakeEffects from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize from.

        Returns:
            ShakeEffects: The deserialized ShakeEffects.
        """        
        return ShakeEffects(
            {
                i: ShakeEffect.deserialize(effect)
                for i, effect in data["effects"].items()
            }
        )

    @staticmethod
    def create_empty() -> "ShakeEffects":
        """Creates an empty ShakeEffects object.

        Returns:
            ShakeEffects: The empty ShakeEffects object.
        """        
        return ShakeEffects({})

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        """Gets the path of the json file that contains the ShakeEffects in the mod zip.

        Returns:
            io.path.Path: The path of the json file that contains the ShakeEffects in the mod zip.
        """        
        return io.path.Path("battle").add("battle_shake_setting.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        """Adds the ShakeEffects to the mod zip.

        Args:
            zip (io.zip.Zip): The mod zip to add the ShakeEffects to.
        """        
        json = io.json_file.JsonFile.from_json(self.serialize())
        path = self.get_zip_json_file_path()
        zip.add_file(path, json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["ShakeEffects"]:
        """Loads the ShakeEffects from the mod zip.

        Args:
            zip (io.zip.Zip): The mod zip to load the ShakeEffects from.

        Returns:
            ShakeEffects: The ShakeEffects loaded from the mod zip.
        """        
        path = ShakeEffects.get_zip_json_file_path()
        file = zip.get_file(path)
        if file is None:
            return None
        json = io.json_file.JsonFile.from_data(file)
        return ShakeEffects.deserialize(json.json)

    def import_shake_effects(self, other: "ShakeEffects"):
        """Loads the ShakeEffects from another ShakeEffects object.

        Args:
            other (ShakeEffects): The ShakeEffects to load from.
        """        
        self.effects.update(other.effects)
