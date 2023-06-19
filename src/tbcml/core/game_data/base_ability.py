import enum
from typing import Any
from tbcml import core


class Probability(enum.Enum):
    NORMAL = 0
    RARE = 1
    SUPER_RARE = 2
    E_RARE = 3  # e could mean special?


class BaseAbilityData:
    def __init__(
        self,
        sell_price: int,
        probability: Probability,
        max_base_level: int,
        max_plus_level: int,
        chapter_1_to_2_max_level: int,
    ):
        self.sell_price = sell_price
        self.probability = probability
        self.max_base_level = max_base_level
        self.max_plus_level = max_plus_level
        self.chapter_1_to_2_max_level = chapter_1_to_2_max_level

    def apply_dict(self, dict_data: dict[str, Any]):
        self.sell_price = dict_data.get("sell_price", self.sell_price)
        probability = dict_data.get("probability")
        if probability is not None:
            self.probability = Probability(probability)
        self.max_base_level = dict_data.get("max_base_level", self.max_base_level)
        self.max_plus_level = dict_data.get("max_plus_level", self.max_plus_level)
        self.chapter_1_to_2_max_level = dict_data.get(
            "chapter_1_to_2_max_level", self.chapter_1_to_2_max_level
        )

    @staticmethod
    def create_empty() -> "BaseAbilityData":
        return BaseAbilityData(
            0,
            Probability.NORMAL,
            0,
            0,
            0,
        )


class BaseAbility:
    def __init__(self, ability_id: int, data: BaseAbilityData):
        self.ability_id = ability_id
        self.data = data

    def apply_dict(self, dict_data: dict[str, Any]):
        self.ability_id = dict_data.get("ability_id", self.ability_id)
        data = dict_data.get("data")
        if data is not None:
            self.data.apply_dict(data)

    @staticmethod
    def create_empty(ability_id: int) -> "BaseAbility":
        return BaseAbility(
            ability_id,
            BaseAbilityData.create_empty(),
        )


class BaseAbilities:
    def __init__(self, abilities: dict[int, BaseAbility]):
        self.abilities = abilities

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "BaseAbilities":
        if game_data.base_abilities is not None:
            return game_data.base_abilities
        file = game_data.find_file("AbilityData.csv")
        if file is None:
            return BaseAbilities.create_empty()
        csv = core.CSV(file.dec_data)
        abilitise: dict[int, BaseAbility] = {}
        for i, line in enumerate(csv):
            line = csv.read_line()
            if line is None:
                continue
            xp = int(line[0])
            probability = int(line[1])
            max_base_level = int(line[2])
            max_plus_level = int(line[3])
            chapter_1_to_2_max_level = int(line[4])
            data = BaseAbilityData(
                xp,
                Probability(probability),
                max_base_level,
                max_plus_level,
                chapter_1_to_2_max_level,
            )
            abilitise[i] = BaseAbility(i, data)

        abilities = BaseAbilities(abilitise)
        game_data.base_abilities = abilities
        return abilities

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(self.get_file_name())
        if file is None:
            raise FileNotFoundError(f"{self.get_file_name()} not found")
        csv = core.CSV(file.dec_data)
        remaining_abilities = self.abilities.copy()
        for i, line in enumerate(csv):
            line = csv.read_line()
            if line is None:
                continue
            try:
                ability = self.abilities[i]
            except KeyError:
                continue
            line[0] = str(ability.data.sell_price)
            line[1] = str(ability.data.probability.value)
            line[2] = str(ability.data.max_base_level)
            line[3] = str(ability.data.max_plus_level)
            line[4] = str(ability.data.chapter_1_to_2_max_level)
            csv.lines[i] = line
            del remaining_abilities[i]

        for ability in remaining_abilities.values():
            line = [
                str(ability.data.sell_price),
                str(ability.data.probability.value),
                str(ability.data.max_base_level),
                str(ability.data.max_plus_level),
                str(ability.data.chapter_1_to_2_max_level),
            ]
            csv.lines.append(line)

        game_data.set_file(self.get_file_name(), csv.to_data())

    @staticmethod
    def get_file_name() -> str:
        return "AbilityData.csv"

    def apply_dict(self, dict_data: dict[str, Any]):
        abilities = dict_data.get("abilities")
        if abilities is not None:
            current_abilities = self.abilities.copy()
            modded_abilities = core.ModEditDictHandler(
                abilities, current_abilities
            ).get_dict(convert_int=True)
            for ability_id, modded_ability in modded_abilities.items():
                ability = current_abilities.get(ability_id)
                if ability is None:
                    ability = BaseAbility.create_empty(ability_id)
                    current_abilities[ability_id] = ability
                ability.apply_dict(modded_ability)
            self.abilities = current_abilities

    @staticmethod
    def create_empty() -> "BaseAbilities":
        return BaseAbilities({})

    @staticmethod
    def apply_mod_to_game_data(mod: "core.Mod", game_data: "core.GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (core.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        abilities_data = mod.mod_edits.get("abilities")
        if abilities_data is None:
            return
        abilities = BaseAbilities.from_game_data(game_data)
        abilities.apply_dict(mod.mod_edits)
        abilities.to_game_data(game_data)
