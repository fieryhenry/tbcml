"""Contains the Battle class, which contains all battle-related data."""
from tbcml.core.game_data import pack
from tbcml.core.game_data.battle import battle_shake_setting, bg, chara_group


class Battle:
    def __init__(
        self,
        shake_effects: "battle_shake_setting.ShakeEffects",
        bgs: "bg.Bgs",
        groups: "chara_group.CharaGroups",
    ):
        """Initializes a Battle object.

        Args:
            shake_effects (battle_shake_setting.ShakeEffects): Screen shake effects.
            bgs (bg.Bgs): Backgrounds.
            groups (chara_group.CharaGroups): Character groups (Used for battle conditions).
        """
        self.shake_effects = shake_effects
        self.bgs = bgs
        self.groups = groups

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Battle":
        """Creates a Battle object from the game data.

        Args:
            game_data (pack.GamePacks): The game data to create the Battle object from.

        Returns:
            Battle: The Battle object.
        """
        shake_effects = battle_shake_setting.ShakeEffects.from_game_data(game_data)
        bgs = bg.Bgs.from_game_data(game_data)
        groups = chara_group.CharaGroups.from_game_data(game_data)
        return Battle(
            shake_effects,
            bgs,
            groups,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        """Writes the Battle object to the game data.

        Args:
            game_data (pack.GamePacks): The game data to write to.
        """
        self.shake_effects.to_game_data(game_data)
        self.bgs.to_game_data(game_data)
        self.groups.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Battle":
        """Creates an empty Battle object.

        Returns:
            Battle: The empty Battle object.
        """
        return Battle(
            battle_shake_setting.ShakeEffects.create_empty(),
            bg.Bgs.create_empty(),
            chara_group.CharaGroups.create_empty(),
        )
