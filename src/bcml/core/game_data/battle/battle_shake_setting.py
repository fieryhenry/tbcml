import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class ShakeLocation(enum.Enum):
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
        self.shake_location = shake_location
        self.start_distance = start_distance
        self.end_distance = end_distance
        self.frames = frames
        self.events_until_next_shake = events_until_next_shake
        self.reset_frame = reset_frame
        self.priority = priority
    
    def serialize(self) -> dict[str, Any]:
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
        self.effects = effects
    
    @staticmethod
    def get_file_name() -> str:
        return "battleshake_setting.csv"
    
    @staticmethod
    def from_game_data(game_data: "pack.GamePacks"):
        file = game_data.find_file(ShakeEffects.get_file_name())
        if file is None:
            raise FileNotFoundError(f"{ShakeEffects.get_file_name()} not found")
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
            line = [effect.shake_location.value, effect.start_distance, effect.end_distance, effect.frames, effect.events_until_next_shake, effect.reset_frame, effect.priority]
            csv.add_line(line)

        game_data.set_file(self.get_file_name(), csv.to_data())
    
    def serialize(self) -> dict[str, Any]:
        return {
            "effects": {i: effect.serialize() for i, effect in self.effects.items()},
        }
    
    @staticmethod
    def deserialize(data: dict[str, Any]) -> "ShakeEffects":
        return ShakeEffects(
            {i: ShakeEffect.deserialize(effect) for i, effect in data["effects"].items()}
        )
    
    @staticmethod
    def create_empty() -> "ShakeEffects":
        return ShakeEffects({})
    
    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        return io.path.Path("battle").add("battle_shake_setting.json")
    
    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        path = self.get_zip_json_file_path()
        zip.add_file(path, json.to_data())
    
    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["ShakeEffects"]:
        path = ShakeEffects.get_zip_json_file_path()
        file = zip.get_file(path)
        if file is None:
            return None
        json = io.json_file.JsonFile.from_data(file)
        return ShakeEffects.deserialize(json.json)
    
    def import_shake_effects(self, other: "ShakeEffects"):
        self.effects.update(other.effects)