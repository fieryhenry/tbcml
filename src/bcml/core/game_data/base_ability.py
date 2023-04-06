import enum
from bcml.core.game_data import pack
from bcml.core import io


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


class BaseAbility:
    def __init__(self, ability_id: int, data: BaseAbilityData):
        self.ability_id = ability_id
        self.data = data


class BaseAbilities:
    def __init__(self, abilities: dict[int, BaseAbility]):
        self.abilities = abilities

    @staticmethod
    def from_game_data(game_data: pack.GamePacks) -> "BaseAbilities":
        file = game_data.find_file("AbilityData.csv")
        if file is None:
            return BaseAbilities.create_empty()
        csv = io.bc_csv.CSV(file.dec_data)
        abilitise: dict[int, BaseAbility] = {}
        for i, line in enumerate(csv):
            line = csv.read_line()
            if line is None:
                continue
            xp = line[0].to_int()
            probability = line[1].to_int()
            max_base_level = line[2].to_int()
            max_plus_level = line[3].to_int()
            chapter_1_to_2_max_level = line[4].to_int()
            data = BaseAbilityData(
                xp,
                Probability(probability),
                max_base_level,
                max_plus_level,
                chapter_1_to_2_max_level,
            )
            abilitise[i] = BaseAbility(i, data)

        return BaseAbilities(abilitise)

    def to_game_data(self, game_data: pack.GamePacks):
        file = game_data.find_file(self.get_file_name())
        if file is None:
            raise FileNotFoundError(f"{self.get_file_name()} not found")
        csv = io.bc_csv.CSV(file.dec_data)
        remaining_abilities = self.abilities.copy()
        for i, line in enumerate(csv):
            line = csv.read_line()
            if line is None:
                continue
            try:
                ability = self.abilities[i]
            except KeyError:
                continue
            line[0].set(ability.data.sell_price)
            line[1].set(ability.data.probability.value)
            line[2].set(ability.data.max_base_level)
            line[3].set(ability.data.max_plus_level)
            line[4].set(ability.data.chapter_1_to_2_max_level)
            csv.set_line(i, line)
            del remaining_abilities[i]

        for ability in remaining_abilities.values():
            line = [
                ability.data.sell_price,
                ability.data.probability.value,
                ability.data.max_base_level,
                ability.data.max_plus_level,
                ability.data.chapter_1_to_2_max_level,
            ]
            csv.add_line(line)

        game_data.set_file(self.get_file_name(), csv.to_data())

    @staticmethod
    def get_file_name() -> str:
        return "AbilityData.csv"

    @staticmethod
    def create_empty() -> "BaseAbilities":
        return BaseAbilities({})
