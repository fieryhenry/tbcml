from bcml.core.game_data import pack
from bcml.core import io
from typing import Any, Optional
from bcml.core.game_data.battle import battle_shake_setting, bg, chara_group

class Battle:
    def __init__(self, shake_effects: "battle_shake_setting.ShakeEffects", bgs: "bg.Bgs", groups: "chara_group.CharaGroups"):
        self.shake_effects = shake_effects
        self.bgs = bgs
        self.groups = groups
    
    def serialize(self) -> dict[str, Any]:
        return {
            "battle_shake_setting": self.shake_effects.serialize(),
            "bg": self.bgs.serialize(),
            "chara_group": self.groups.serialize(),
        }
    
    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Battle":
        return Battle(
            battle_shake_setting.ShakeEffects.deserialize(data["battle_shake_setting"]),
            bg.Bgs.deserialize(data["bg"]),
            chara_group.CharaGroups.deserialize(data["chara_group"]),
        )
    
    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["Battle"]:
        shake_effects = battle_shake_setting.ShakeEffects.from_game_data(game_data)
        if shake_effects is None:
            return None
        bgs = bg.Bgs.from_game_data(game_data)
        if bgs is None:
            return None
        groups = chara_group.CharaGroups.from_game_data(game_data)
        if groups is None:
            return None
        return Battle(
            shake_effects,
            bgs,
            groups,
        )
    
    def to_game_data(self, game_data: "pack.GamePacks"):
        self.shake_effects.to_game_data(game_data)
        self.bgs.to_game_data(game_data)
        self.groups.to_game_data(game_data)
    
    def add_to_zip(self, zip: "io.zip.Zip"):
        self.shake_effects.add_to_zip(zip)
        self.bgs.add_to_zip(zip)
        self.groups.add_to_zip(zip)
    
    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["Battle"]:
        shake_effects = battle_shake_setting.ShakeEffects.from_zip(zip)
        if shake_effects is None:
            return None
        bgs = bg.Bgs.from_zip(zip)
        if bgs is None:
            return None
        groups = chara_group.CharaGroups.from_zip(zip)
        if groups is None:
            return None
        return Battle(
            shake_effects,
            bgs,
            groups,
        )
    
    @staticmethod
    def create_empty() -> "Battle":
        return Battle(
            battle_shake_setting.ShakeEffects.create_empty(),
            bg.Bgs.create_empty(),
            chara_group.CharaGroups.create_empty(),
        )
    
    def import_battle(self, other: "Battle"):
        self.shake_effects.import_shake_effects(other.shake_effects)
        self.bgs.import_bgs(other.bgs)
        self.groups.import_chara_groups(other.groups)