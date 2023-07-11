"""Module for base ability data."""
from typing import Any, Optional
from tbcml import core


class BaseAbilityData:
    """Class for base ability data."""

    def __init__(
        self,
        sell_price: Optional[int] = None,
        gatya_rarity: Optional["core.GatyaRarity"] = None,
        max_base_level: Optional[int] = None,
        max_plus_level: Optional[int] = None,
        chapter_1_to_2_max_level: Optional[int] = None,
    ):
        """Class for base ability data.

        Args:
            sell_price (Optional[int], optional): Sell price of the base ability. Defaults to None.
            gatya_rarity (Optional[core.GatyaRarity], optional): Gatya rarity of the base ability. Defaults to None.
            max_base_level (Optional[int], optional): The max base level of the base ability. Defaults to None.
            max_plus_level (Optional[int], optional): The max plus level of the base ability. Defaults to None.
            chapter_1_to_2_max_level (Optional[int], optional): The max level of the base ability from chapter 1 to 2. Defaults to None.
        """
        self.sell_price = sell_price
        self.gatya_rarity = gatya_rarity
        self.max_base_level = max_base_level
        self.max_plus_level = max_plus_level
        self.chapter_1_to_2_max_level = chapter_1_to_2_max_level

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dict to the base ability data.

        Args:
            dict_data (dict[str, Any]): The dict to apply.
        """
        self.sell_price = dict_data.get("sell_price", self.sell_price)
        gatya_rarity = dict_data.get("gatya_rarity")
        if gatya_rarity is not None:
            self.gatya_rarity = core.GatyaRarity(gatya_rarity)
        self.max_base_level = dict_data.get("max_base_level", self.max_base_level)
        self.max_plus_level = dict_data.get("max_plus_level", self.max_plus_level)
        self.chapter_1_to_2_max_level = dict_data.get(
            "chapter_1_to_2_max_level", self.chapter_1_to_2_max_level
        )

    @staticmethod
    def create_empty() -> "BaseAbilityData":
        """Create an empty base ability data.

        Returns:
            BaseAbilityData: The empty base ability data.
        """
        return BaseAbilityData()


class BaseAbility:
    """Class for base ability."""

    def __init__(
        self,
        ability_id: int,
        upgrade_icon: Optional["core.BCImage"] = None,
        upgrade_icon_max: Optional["core.BCImage"] = None,
        data: Optional[BaseAbilityData] = None,
    ):
        """Class for base ability.

        Args:
            ability_id (int): The ID of the base ability.
            upgrade_icon (Optional[core.BCImage], optional): The upgrade icon of the base ability. Defaults to None.
            upgrade_icon_max (Optional[core.BCImage], optional): The upgrade icon of the base ability at max level. Defaults to None.
            data (Optional[BaseAbilityData], optional): The data of the base ability. Defaults to None.
        """
        self.ability_id = ability_id
        self.upgrade_icon = upgrade_icon
        self.upgrade_icon_max = upgrade_icon_max
        self.data = data

    def get_upgrade_icon(self) -> "core.BCImage":
        """Get the upgrade icon of the base ability.

        Returns:
            core.BCImage: The upgrade icon of the base ability.
        """
        if self.upgrade_icon is None:
            self.upgrade_icon = core.BCImage.from_size(512, 128)
        return self.upgrade_icon

    def get_upgrade_icon_max(self) -> "core.BCImage":
        """Get the upgrade icon max of the base ability.

        Returns:
            core.BCImage: The upgrade icon max of the base ability.
        """
        if self.upgrade_icon_max is None:
            self.upgrade_icon_max = core.BCImage.from_size(512, 128)
        return self.upgrade_icon_max

    def get_data(self) -> BaseAbilityData:
        """Get the data of the base ability.

        Returns:
            BaseAbilityData: The data of the base ability.
        """
        if self.data is None:
            self.data = BaseAbilityData.create_empty()
        return self.data

    def apply_dict(self, dict_data: dict[str, Any]):
        """Apply a dict to the base ability.

        Args:
            dict_data (dict[str, Any]): The dict to apply.
        """
        self.ability_id = dict_data.get("ability_id", self.ability_id)
        upgrade_icon = dict_data.get("upgrade_icon")
        if upgrade_icon is not None:
            self.get_upgrade_icon().apply_dict(upgrade_icon)
        upgrade_icon_max = dict_data.get("upgrade_icon_max")
        if upgrade_icon_max is not None:
            self.get_upgrade_icon_max().apply_dict(upgrade_icon_max)
        data = dict_data.get("data")
        if data is not None:
            self.get_data().apply_dict(data)

    @staticmethod
    def get_upgrade_icon_file_name(id: int, lang: str) -> str:
        """Get the upgrade icon file name of the base ability.

        Args:
            id (int): The ability ID of the base ability.
            lang (str): The language of the upgrade icon.

        Returns:
            str: The upgrade icon file name of the base ability.
        """
        return f"udi{core.PaddedInt(id, 3)}_s_{lang}.png"

    @staticmethod
    def get_upgrade_icon_max_file_name(id: int, lang: str) -> str:
        """Get the upgrade icon max file name of the base ability.

        Args:
            id (int): The ability ID of the base ability.
            lang (str): The language of the upgrade icon max.

        Returns:
            str: The upgrade icon max file name of the base ability.
        """

        return f"udi{core.PaddedInt(id, 3)}_sg_{lang}.png"

    @staticmethod
    def from_game_data(
        ability_id: int,
        game_data: "core.GamePacks",
        data: Optional[BaseAbilityData] = None,
    ) -> "BaseAbility":
        """Create a base ability from game data.

        Args:
            ability_id (int): The ability ID of the base ability.
            game_data (core.GamePacks): The game data.
            data (Optional[BaseAbilityData], optional): The data of the base ability. Defaults to None.

        Returns:
            BaseAbility: The base ability.
        """
        upgrade_icon_file = game_data.find_file(
            BaseAbility.get_upgrade_icon_file_name(
                ability_id, game_data.localizable.get_lang()
            )
        )
        upgrade_icon_max_file = game_data.find_file(
            BaseAbility.get_upgrade_icon_max_file_name(
                ability_id, game_data.localizable.get_lang()
            )
        )

        upgrade_icon = None
        upgrade_icon_max = None

        if upgrade_icon_file is not None:
            upgrade_icon = core.BCImage(upgrade_icon_file.dec_data)
        if upgrade_icon_max_file is not None:
            upgrade_icon_max = core.BCImage(upgrade_icon_max_file.dec_data)

        return BaseAbility(ability_id, upgrade_icon, upgrade_icon_max, data)

    def to_game_data(self, game_data: "core.GamePacks"):
        """Convert the base ability to game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        upgrade_icon_file_name = BaseAbility.get_upgrade_icon_file_name(
            self.ability_id, game_data.localizable.get_lang()
        )
        upgrade_icon_max_file_name = BaseAbility.get_upgrade_icon_max_file_name(
            self.ability_id, game_data.localizable.get_lang()
        )

        if self.upgrade_icon is not None:
            game_data.set_file(upgrade_icon_file_name, self.upgrade_icon.to_data())
        if self.upgrade_icon_max is not None:
            game_data.set_file(
                upgrade_icon_max_file_name, self.upgrade_icon_max.to_data()
            )

    @staticmethod
    def create_empty(ability_id: int) -> "BaseAbility":
        """Create an empty base ability.

        Args:
            ability_id (int): The ability ID of the base ability.

        Returns:
            BaseAbility: The empty base ability.
        """
        return BaseAbility(ability_id)


class BaseAbilities(core.EditableClass):
    """A collection of base abilities."""

    def __init__(self, abilities: dict[int, BaseAbility]):
        self.data = abilities
        super().__init__(abilities)

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "BaseAbilities":
        """Create a collection of base abilities from game data.

        Args:
            game_data (core.GamePacks): The game data.

        Returns:
            BaseAbilities: The collection of base abilities.
        """
        if game_data.base_abilities is not None:
            return game_data.base_abilities
        file = game_data.find_file("AbilityData.csv")
        if file is None:
            return BaseAbilities.create_empty()
        csv = core.CSV(file.dec_data)
        abilitise: dict[int, BaseAbility] = {}
        for i in range(len(csv.lines)):
            csv.init_getter(i)
            xp = csv.get_int()
            gatya_rarity = csv.get_int()
            max_base_level = csv.get_int()
            max_plus_level = csv.get_int()
            chapter_1_to_2_max_level = csv.get_int()
            data = BaseAbilityData(
                xp,
                core.GatyaRarity(gatya_rarity),
                max_base_level,
                max_plus_level,
                chapter_1_to_2_max_level,
            )
            abilitise[i] = BaseAbility.from_game_data(i, game_data, data)
        abilities = BaseAbilities(abilitise)
        game_data.base_abilities = abilities
        return abilities

    def to_game_data(self, game_data: "core.GamePacks"):
        """Convert the collection of base abilities to game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file = game_data.find_file(self.get_ability_data_file_name())
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        for ability in self.data.values():
            if ability.data is None:
                continue
            csv.init_setter(ability.ability_id, 5)
            csv.set_str(ability.data.sell_price)
            csv.set_str(ability.data.gatya_rarity)
            csv.set_str(ability.data.max_base_level)
            csv.set_str(ability.data.max_plus_level)
            csv.set_str(ability.data.chapter_1_to_2_max_level)

        game_data.set_file(self.get_ability_data_file_name(), csv.to_data())

        for ability in self.data.values():
            ability.to_game_data(game_data)

    @staticmethod
    def get_ability_data_file_name() -> str:
        """Get the file name of the base ability data.

        Returns:
            str: The file name of the base ability data.
        """
        return "AbilityData.csv"

    @staticmethod
    def create_empty() -> "BaseAbilities":
        """Create an empty collection of base abilities.

        Returns:
            BaseAbilities: The empty collection of base abilities.
        """
        return BaseAbilities({})
