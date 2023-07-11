"""Module for handling the screen shake effects in battle. This feature was added in version 11.8.0"""
from typing import Any, Optional
from tbcml import core


class ShakeEffect:
    """A screen shake effect. This feature was added in version 11.8.0"""

    def __init__(
        self,
        id: int,
        start_distance: Optional[int] = None,
        end_distance: Optional[int] = None,
        frames: Optional[int] = None,
        events_until_next_shake: Optional[int] = None,
        reset_frame: Optional[int] = None,
        priority: Optional[int] = None,
    ):
        """Initializes a new Screenshake Effect.

        Args:
            id (int): The ID of the ShakeEffect.
            start_distance (int): The starting camera distance of the shake effect.
            end_distance (int): The ending camera distance of the shake effect.
            frames (int): The number of frames the shake effect should last (30 frames = 1 second) (The time taken for the camera to move from start_distance to end_distance)
            events_until_next_shake (int): The number of events that must occur before the shake effect can occur again.
            reset_frame (int): ???
            priority (int): ???
        """
        self.id = id
        self.start_distance = start_distance
        self.end_distance = end_distance
        self.frames = frames
        self.events_until_next_shake = events_until_next_shake
        self.reset_frame = reset_frame
        self.priority = priority

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies the data from a dictionary to the ShakeEffect.

        Args:
            dict_data (dict[str, Any]): The dictionary to apply the data from.
        """
        self.start_distance = dict_data.get("start_distance", self.start_distance)
        self.end_distance = dict_data.get("end_distance", self.end_distance)
        self.frames = dict_data.get("frames", self.frames)
        self.events_until_next_shake = dict_data.get(
            "events_until_next_shake", self.events_until_next_shake
        )
        self.reset_frame = dict_data.get("reset_frame", self.reset_frame)
        self.priority = dict_data.get("priority", self.priority)

    @staticmethod
    def create_empty(id: int) -> "ShakeEffect":
        """Creates an empty ShakeEffect.

        Returns:
            ShakeEffect: An empty ShakeEffect.
        """
        return ShakeEffect(id)


class ShakeEffects(core.EditableClass):
    def __init__(self, effects: dict[int, ShakeEffect]):
        """Initializes a new ShakeEffects object. This object is a collection of ShakeEffects.

        Args:
            effects (dict[int, ShakeEffect]): The ShakeEffects to add to the ShakeEffects object.
        """
        self.data = effects
        super().__init__(effects)

    @staticmethod
    def get_file_name() -> str:
        """Gets the name of the in-game file that contains the ShakeEffects.

        Returns:
            str: The name of the in-game file that contains the ShakeEffects.
        """
        return "battleshake_setting.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "ShakeEffects":
        """Loads the ShakeEffects from the game data.

        Args:
            game_data (core.GamePacks): The game data to load the ShakeEffects from.

        Returns:
            ShakeEffects: The ShakeEffects loaded from the game data.
        """
        if game_data.shake_effects is not None:
            return game_data.shake_effects
        file = game_data.find_file(ShakeEffects.get_file_name())
        if file is None:
            return ShakeEffects.create_empty()
        csv = core.CSV(file.dec_data)
        effects: dict[int, ShakeEffect] = {}
        for i in range(len(csv.lines)):
            csv.init_getter(i)
            id = csv.get_int()
            start_distance = csv.get_int()
            end_distance = csv.get_int()
            frames = csv.get_int()
            events_until_next_shake = csv.get_int()
            reset_frame = csv.get_int()
            priority = csv.get_int()
            effects[id] = ShakeEffect(
                id,
                start_distance,
                end_distance,
                frames,
                events_until_next_shake,
                reset_frame,
                priority,
            )
        effects_o = ShakeEffects(effects)
        game_data.shake_effects = effects_o
        return effects_o

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the ShakeEffects to the game data.

        Args:
            game_data (core.GamePacks): The game data to write the ShakeEffects to.
        """
        file = game_data.find_file(self.get_file_name())
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        for effect in self.data.values():
            csv.init_setter(effect.id, 7, index_line_index=0)
            csv.set_str(effect.id)
            csv.set_str(effect.start_distance)
            csv.set_str(effect.end_distance)
            csv.set_str(effect.frames)
            csv.set_str(effect.events_until_next_shake)
            csv.set_str(effect.reset_frame)
            csv.set_str(effect.priority)

        game_data.set_file(self.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "ShakeEffects":
        """Creates an empty ShakeEffects object.

        Returns:
            ShakeEffects: The empty ShakeEffects object.
        """
        return ShakeEffects({})
