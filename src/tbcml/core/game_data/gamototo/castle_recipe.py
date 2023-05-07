import enum
from typing import Optional
from tbcml.core.game_data import pack
from tbcml.core import io, anim


class CastleRecipeUnlock:
    def __init__(
        self,
        castle_id: int,
        unknown_1: int,
        unknown_2: int,
        max_level: int,
        local_index: int,
    ):
        self.castle_id = castle_id
        self.unknown_1 = unknown_1
        self.unknown_2 = unknown_2
        self.max_level = max_level
        self.local_index = local_index


class CastleRecipeUnlockSet:
    def __init__(
        self, castle_id: int, castle_recipe_unlocks: dict[int, CastleRecipeUnlock]
    ):
        self.castle_recipe_unlocks = castle_recipe_unlocks
        self.castle_id = castle_id


class BaseItem(enum.Enum):
    BRICKS = 0
    FEATHERS = 1
    COAL = 2
    SPROCKETS = 3
    GOLD = 4
    METEORITE = 5
    BEAST_BONES = 6
    AMMONITE = 7


class Recipe:
    def __init__(
        self,
        level: int,
        time_hours: int,
        engineers: int,
        bricks: int,
        feathers: int,
        coal: int,
        sprockets: int,
        gold: int,
        meteorite: int,
        beast_bones: int,
        ammonite: int,
    ):
        self.level = level
        self.time_hours = time_hours
        self.engineers = engineers
        self.bricks = bricks
        self.feathers = feathers
        self.coal = coal
        self.sprockets = sprockets
        self.gold = gold
        self.meteorite = meteorite
        self.beast_bones = beast_bones
        self.ammonite = ammonite

    def clear_materials(self):
        self.bricks = 0
        self.feathers = 0
        self.coal = 0
        self.sprockets = 0
        self.gold = 0
        self.meteorite = 0
        self.beast_bones = 0
        self.ammonite = 0


class CastleRecipe:
    def __init__(
        self,
        recipies: dict[int, Recipe],
        castle_type: int,
        recipe_id: int,
        dev_level: int,
        stage_unlocked: int,
        user_rank_unlocked: int,
        attack_level: int,
        charge_level: int,
        unlock_set: CastleRecipeUnlockSet,
        name: str,
        description: list[str],
        name_texture: "anim.texture.Texture",
    ):
        self.recipe_id = recipe_id
        self.dev_level = dev_level
        self.stage_unlocked = stage_unlocked
        self.user_rank_unlocked = user_rank_unlocked
        self.attack_level = attack_level
        self.charge_level = charge_level
        self.castle_type = castle_type
        self.recipies = recipies
        self.unlock_set = unlock_set
        self.name = name
        self.description = description
        self.name_texture = name_texture

    @staticmethod
    def get_file_name_recipe(castle_type: int) -> str:
        return f"CastleRecipe_{io.data.PaddedInt(castle_type, 3)}.csv"

    @staticmethod
    def get_name_png_file_name(castle_type: int) -> str:
        return f"castleCustom_name_{io.data.PaddedInt(castle_type, 2)}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
        castle_type: int,
        recipe_id: int,
        dev_level: int,
        stage_unlocked: int,
        user_rank_unlocked: int,
        attack_level: int,
        charge_level: int,
        unlock_set: CastleRecipeUnlockSet,
        name: str,
        description: list[str],
        name_texture: "anim.texture.Texture",
    ) -> "CastleRecipe":
        file_name = CastleRecipe.get_file_name_recipe(castle_type)
        file = game_data.find_file(file_name)
        if file is None:
            raise FileNotFoundError(f"{file_name} not found")
        csv = io.bc_csv.CSV(file.dec_data)
        recipies: dict[int, Recipe] = {}
        for i, line in enumerate(csv.lines):
            recipies[i] = Recipe(
                i,
                int(line[0]),
                int(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
                int(line[6]),
                int(line[7]),
                int(line[8]),
                int(line[9]),
            )

        return CastleRecipe(
            recipies,
            castle_type,
            recipe_id,
            dev_level,
            stage_unlocked,
            user_rank_unlocked,
            attack_level,
            charge_level,
            unlock_set,
            name,
            description,
            name_texture,
        )

    def to_game_data(
        self,
        castle_type: int,
        game_data: "pack.GamePacks",
    ) -> None:
        file_name = CastleRecipe.get_file_name_recipe(castle_type)
        file = game_data.find_file(file_name)
        if file is None:
            raise FileNotFoundError(f"{file_name} not found")
        csv = io.bc_csv.CSV(file.dec_data)
        remaining_recipies = set(self.recipies.keys())
        for i, line in enumerate(csv.lines):
            try:
                recipie = self.recipies[i]
            except KeyError:
                continue
            line[0] = str(recipie.time_hours)
            line[1] = str(recipie.engineers)
            line[2] = str(recipie.bricks)
            line[3] = str(recipie.feathers)
            line[4] = str(recipie.coal)
            line[5] = str(recipie.sprockets)
            line[6] = str(recipie.gold)
            line[7] = str(recipie.meteorite)
            line[8] = str(recipie.beast_bones)
            line[9] = str(recipie.ammonite)
            csv.lines[i] = line
            remaining_recipies.remove(i)

        for i in remaining_recipies:
            recipie = self.recipies[i]
            line = [
                str(recipie.time_hours),
                str(recipie.engineers),
                str(recipie.bricks),
                str(recipie.feathers),
                str(recipie.coal),
                str(recipie.sprockets),
                str(recipie.gold),
                str(recipie.meteorite),
                str(recipie.beast_bones),
                str(recipie.ammonite),
            ]
            csv.lines.append(line)

        game_data.set_file(file_name, csv.to_data())

        name_png_file_name = CastleRecipe.get_name_png_file_name(castle_type)
        game_data.set_file(name_png_file_name, self.name_texture.image.to_data())


class CastleRecipies:
    def __init__(self, recipies: dict[int, CastleRecipe]):
        self.recipies = recipies

    def get_recipe(self) -> Optional[CastleRecipe]:
        recipie_lst = list(self.recipies.values())
        try:
            return recipie_lst[0]
        except IndexError:
            return None

    @staticmethod
    def get_unlock_file_name() -> str:
        return "CastleRecipeUnlock.csv"

    @staticmethod
    def get_unlock_data_file_name() -> str:
        return "CastleRecipeUnlockData.csv"

    @staticmethod
    def get_description_file_name() -> str:
        return "CastleRecipeDescriptions.csv"

    @staticmethod
    def get_name_imgcut_file_name() -> str:
        return "castleCustom_name_ALL.imgcut"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CastleRecipies":
        description_csv_file = game_data.find_file(
            CastleRecipies.get_description_file_name()
        )
        if description_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_description_file_name()} not found"
            )

        description_csv = io.bc_csv.CSV(
            description_csv_file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        names: dict[int, str] = {}
        descriptions: dict[int, list[str]] = {}
        for line in description_csv.lines:
            castle_id = int(line[0])
            name = line[1]
            description = line[2:]
            names[castle_id] = name
            descriptions[castle_id] = description

        unlock_csv_file = game_data.find_file(CastleRecipies.get_unlock_file_name())
        if unlock_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_unlock_file_name()} not found"
            )

        unlock_csv = io.bc_csv.CSV(unlock_csv_file.dec_data)

        unlock_data_csv_file = game_data.find_file(
            CastleRecipies.get_unlock_data_file_name()
        )
        if unlock_data_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_unlock_data_file_name()} not found"
            )

        unlock_data_csv = io.bc_csv.CSV(unlock_data_csv_file.dec_data)

        unlock_sets: dict[int, CastleRecipeUnlockSet] = {}
        i = 0
        while i < len(unlock_csv.lines):
            castle_recipe_unlocks: dict[int, CastleRecipeUnlock] = {}
            j = 0
            id = int(unlock_csv.lines[i + j][0])
            while int(unlock_csv.lines[i + j][0]) == id:
                castle_id = int(unlock_csv.lines[i + j][0])
                unknown_1 = int(unlock_csv.lines[i + j][1])
                unknown_2 = int(unlock_csv.lines[i + j][2])
                max_level = int(unlock_csv.lines[i + j][3])
                castle_recipe_unlocks[j] = CastleRecipeUnlock(
                    castle_id, unknown_1, unknown_2, max_level, j
                )
                j += 1
            castle_type = id
            unlock_sets[castle_type] = CastleRecipeUnlockSet(id, castle_recipe_unlocks)
            i += 1

        castle_recipies: dict[int, CastleRecipe] = {}
        for i, line in enumerate(unlock_data_csv.lines[1:]):
            castle_type = int(line[0])
            recipe_id = int(line[1])
            dev_level = int(line[2])
            stage_unlocked = int(line[3])
            user_rank_unlocked = int(line[4])
            attack_level = int(line[5])
            charge_level = int(line[6])
            name_imgcut = anim.texture.Texture.load(
                CastleRecipe.get_name_png_file_name(castle_type),
                CastleRecipies.get_name_imgcut_file_name(),
                game_data,
            )
            castle_recipies[castle_type] = CastleRecipe.from_game_data(
                game_data,
                castle_type,
                recipe_id,
                dev_level,
                stage_unlocked,
                user_rank_unlocked,
                attack_level,
                charge_level,
                unlock_sets[castle_type],
                names[castle_type],
                descriptions[castle_type],
                name_imgcut,
            )
        return CastleRecipies(castle_recipies)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        description_csv_file = game_data.find_file(
            CastleRecipies.get_description_file_name()
        )
        if description_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_description_file_name()} not found"
            )

        description_csv = io.bc_csv.CSV(
            description_csv_file.dec_data,
            delimeter=io.bc_csv.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )

        unlock_csv_file = game_data.find_file(CastleRecipies.get_unlock_file_name())
        if unlock_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_unlock_file_name()} not found"
            )

        unlock_csv = io.bc_csv.CSV(unlock_csv_file.dec_data)

        unlock_data_csv_file = game_data.find_file(
            CastleRecipies.get_unlock_data_file_name()
        )
        if unlock_data_csv_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_unlock_data_file_name()} not found"
            )

        unlock_data_csv = io.bc_csv.CSV(unlock_data_csv_file.dec_data)

        remaining_recipies = self.recipies.copy()

        for i, line in enumerate(unlock_csv.lines):
            castle_type = int(line[0])
            try:
                castle_recipe = self.recipies[castle_type]
            except KeyError:
                continue
            castle_recipe_unlock_set = castle_recipe.unlock_set
            for (
                j,
                castle_recipe_unlock,
            ) in castle_recipe_unlock_set.castle_recipe_unlocks.items():
                line[0] = str(castle_recipe_unlock_set.castle_id)
                line[1] = str(castle_recipe_unlock.unknown_1)
                line[2] = str(castle_recipe_unlock.unknown_2)
                line[3] = str(castle_recipe_unlock.max_level)
                unlock_csv.lines[i + j] = line
            remaining_recipies.pop(castle_type)

        for castle_type, castle_recipe in remaining_recipies.items():
            castle_recipe_unlock_set = castle_recipe.unlock_set
            for (
                j,
                castle_recipe_unlock,
            ) in castle_recipe_unlock_set.castle_recipe_unlocks.items():
                unlock_csv.lines.append(
                    [
                        str(castle_recipe_unlock_set.castle_id),
                        str(castle_recipe_unlock.unknown_1),
                        str(castle_recipe_unlock.unknown_2),
                        str(castle_recipe_unlock.max_level),
                    ]
                )
        remaining_recipies = self.recipies.copy()

        for i, line in enumerate(unlock_data_csv.lines[1:]):
            castle_type = int(line[0])
            try:
                castle_recipe = self.recipies[castle_type]
            except KeyError:
                continue
            line[1] = str(castle_recipe.recipe_id)
            line[2] = str(castle_recipe.dev_level)
            line[3] = str(castle_recipe.stage_unlocked)
            line[4] = str(castle_recipe.user_rank_unlocked)
            line[5] = str(castle_recipe.attack_level)
            line[6] = str(castle_recipe.charge_level)
            unlock_data_csv.lines[i + 1] = line
            remaining_recipies.pop(castle_type)

        for castle_type, castle_recipe in remaining_recipies.items():
            unlock_data_csv.lines.append(
                [
                    str(castle_type),
                    str(castle_recipe.recipe_id),
                    str(castle_recipe.dev_level),
                    str(castle_recipe.stage_unlocked),
                    str(castle_recipe.user_rank_unlocked),
                    str(castle_recipe.attack_level),
                    str(castle_recipe.charge_level),
                ]
            )

        remaining_recipies = self.recipies.copy()

        for i, line in enumerate(description_csv.lines):
            if len(line) < 2:
                continue
            castle_id = int(line[0])
            try:
                castle_recipe = self.recipies[castle_id]
            except KeyError:
                continue
            line[1] = str(castle_recipe.name)
            line[2:] = []
            for j, description_line in enumerate(castle_recipe.description):
                line.append(description_line)
            description_csv.lines[i] = line
            remaining_recipies.pop(i)

        for castle_type, castle_recipe in remaining_recipies.items():
            description_csv.lines.append(
                [
                    castle_recipe.name,
                    *[
                        description_line
                        for description_line in castle_recipe.description
                    ],
                ]
            )

        game_data.set_file(CastleRecipies.get_unlock_file_name(), unlock_csv.to_data())
        game_data.set_file(
            CastleRecipies.get_unlock_data_file_name(), unlock_data_csv.to_data()
        )
        game_data.set_file(
            CastleRecipies.get_description_file_name(), description_csv.to_data()
        )

        for castle_type, castle_recipe in self.recipies.items():
            castle_recipe.to_game_data(castle_type, game_data)

        recipe = self.get_recipe()
        if recipe is not None:
            recipe.name_texture.save(game_data)

    def get_castle_recipe(self, castle_type: int) -> Optional[CastleRecipe]:
        return self.recipies.get(castle_type, None)

    def set_castle_recipe(self, castle_type: int, castle_recipe: CastleRecipe):
        self.recipies[castle_type] = castle_recipe
