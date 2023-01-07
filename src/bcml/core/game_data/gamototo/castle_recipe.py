import enum
from typing import Any, Optional
from bcml.core.game_data.gamototo import cannon
from bcml.core.game_data import pack, bc_anim
from bcml.core import io


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

    def serialize(self) -> dict[str, Any]:
        return {
            "castle_id": self.castle_id,
            "unknown_1": self.unknown_1,
            "unknown_2": self.unknown_2,
            "max_level": self.max_level,
            "local_index": self.local_index,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CastleRecipeUnlock":
        return CastleRecipeUnlock(
            data["castle_id"],
            data["unknown_1"],
            data["unknown_2"],
            data["max_level"],
            data["local_index"],
        )


class CastleRecipeUnlockSet:
    def __init__(
        self, castle_id: int, castle_recipe_unlocks: dict[int, CastleRecipeUnlock]
    ):
        self.castle_recipe_unlocks = castle_recipe_unlocks
        self.castle_id = castle_id

    def serialize(self) -> dict[str, Any]:
        return {
            "castle_id": self.castle_id,
            "castle_recipe_unlocks": {
                k: v.serialize() for k, v in self.castle_recipe_unlocks.items()
            },
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CastleRecipeUnlockSet":
        return CastleRecipeUnlockSet(
            data["castle_id"],
            {
                k: CastleRecipeUnlock.deserialize(v)
                for k, v in data["castle_recipe_unlocks"].items()
            },
        )


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

    def serialize(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "time_hours": self.time_hours,
            "engineers": self.engineers,
            "bricks": self.bricks,
            "feathers": self.feathers,
            "coal": self.coal,
            "sprockets": self.sprockets,
            "gold": self.gold,
            "meteorite": self.meteorite,
            "beast_bones": self.beast_bones,
            "ammonite": self.ammonite,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Recipe":
        return Recipe(
            data["level"],
            data["time_hours"],
            data["engineers"],
            data["bricks"],
            data["feathers"],
            data["coal"],
            data["sprockets"],
            data["gold"],
            data["meteorite"],
            data["beast_bones"],
            data["ammonite"],
        )

    def __str__(self):
        return f"Recipe(level={self.level}, time_hours={self.time_hours}, engineers={self.engineers}, bricks={self.bricks}, feathers={self.feathers}, coal={self.coal}, sprockets={self.sprockets}, gold={self.gold}, meteorite={self.meteorite}, beast_bones={self.beast_bones}, ammonite={self.ammonite})"

    def __repr__(self):
        return self.__str__()


class CastleRecipe:
    def __init__(
        self,
        recipies: dict[int, Recipe],
        castle_type: "cannon.CastleType",
        recipe_id: int,
        dev_level: int,
        stage_unlocked: int,
        user_rank_unlocked: int,
        attack_level: int,
        charge_level: int,
        unlock_set: CastleRecipeUnlockSet,
        name: str,
        description: list[str],
        name_imgcut: "bc_anim.Imgcut",
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
        self.name_imgcut = name_imgcut

    def serialize(self) -> dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "dev_level": self.dev_level,
            "stage_unlocked": self.stage_unlocked,
            "user_rank_unlocked": self.user_rank_unlocked,
            "attack_level": self.attack_level,
            "charge_level": self.charge_level,
            "castle_type": self.castle_type.value,
            "recipies": {
                level: recipie.serialize() for level, recipie in self.recipies.items()
            },
            "unlock_set": self.unlock_set.serialize(),
            "name": self.name,
            "description": self.description,
            "name_imgcut": self.name_imgcut.serialize(),
        }

    @staticmethod
    def deserialize(
        data: dict[str, Any],
    ) -> "CastleRecipe":
        return CastleRecipe(
            {
                level: Recipe.deserialize(recipie)
                for level, recipie in data["recipies"].items()
            },
            cannon.CastleType(data["castle_type"]),
            data["recipe_id"],
            data["dev_level"],
            data["stage_unlocked"],
            data["user_rank_unlocked"],
            data["attack_level"],
            data["charge_level"],
            CastleRecipeUnlockSet.deserialize(data["unlock_set"]),
            data["name"],
            data["description"],
            data["name_imgcut"],
        )

    @staticmethod
    def get_file_name_recipe(castle_type: "cannon.CastleType") -> str:
        return f"CastleRecipe_{io.data.PaddedInt(castle_type.value, 3)}.csv"

    @staticmethod
    def get_name_png_file_name(castle_type: "cannon.CastleType") -> str:
        return f"castleCustom_name_{io.data.PaddedInt(castle_type.value, 2)}.png"

    @staticmethod
    def from_game_data(
        game_data: "pack.GamePacks",
        castle_type: "cannon.CastleType",
        recipe_id: int,
        dev_level: int,
        stage_unlocked: int,
        user_rank_unlocked: int,
        attack_level: int,
        charge_level: int,
        unlock_set: CastleRecipeUnlockSet,
        name: str,
        description: list[str],
        name_imgcut: "bc_anim.Imgcut",
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
                line[0].to_int(),
                line[1].to_int(),
                line[2].to_int(),
                line[3].to_int(),
                line[4].to_int(),
                line[5].to_int(),
                line[6].to_int(),
                line[7].to_int(),
                line[8].to_int(),
                line[9].to_int(),
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
            name_imgcut,
        )

    def to_game_data(
        self,
        castle_type: "cannon.CastleType",
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
            line[0].set(recipie.time_hours)
            line[1].set(recipie.engineers)
            line[2].set(recipie.bricks)
            line[3].set(recipie.feathers)
            line[4].set(recipie.coal)
            line[5].set(recipie.sprockets)
            line[6].set(recipie.gold)
            line[7].set(recipie.meteorite)
            line[8].set(recipie.beast_bones)
            line[9].set(recipie.ammonite)
            csv.set_line(i, line)
            remaining_recipies.remove(i)

        for i in remaining_recipies:
            recipie = self.recipies[i]
            line = [
                recipie.time_hours,
                recipie.engineers,
                recipie.bricks,
                recipie.feathers,
                recipie.coal,
                recipie.sprockets,
                recipie.gold,
                recipie.meteorite,
                recipie.beast_bones,
                recipie.ammonite,
            ]
            csv.add_line(line)

        game_data.set_file(file_name, csv.to_data())

        name_png_file_name = CastleRecipe.get_name_png_file_name(castle_type)
        game_data.set_file(name_png_file_name, self.name_imgcut.image.to_data())


class CastleRecipies:
    def __init__(self, recipies: dict["cannon.CastleType", CastleRecipe]):
        self.recipies = recipies

    def serialize(self) -> dict[str, Any]:
        return {
            castle_type.value: castle_recipe.serialize()
            for castle_type, castle_recipe in self.recipies.items()
        }
    
    def get_recipe(self) -> Optional[CastleRecipe]:
        recipie_lst = list(self.recipies.values())
        try:
            return recipie_lst[0]
        except IndexError:
            return None

    @staticmethod
    def deserialize(
        data: dict[str, Any],
    ) -> "CastleRecipies":
        recipies = {}
        for castle_type, castle_recipe in data.items():
            recipies[cannon.CastleType(castle_type)] = CastleRecipe.deserialize(castle_recipe)
        return CastleRecipies(recipies)

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
        name_imgcut_file = game_data.find_file(
            CastleRecipies.get_name_imgcut_file_name()
        )
        if name_imgcut_file is None:
            raise FileNotFoundError(
                f"{CastleRecipies.get_name_imgcut_file_name()} not found"
            )

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
            castle_id = line[0].to_int()
            name = line[1].to_str()
            description = io.data.Data.data_list_string_list(line[2:])
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

        unlock_sets: dict[cannon.CastleType, CastleRecipeUnlockSet] = {}
        for i in range(0, len(unlock_csv.lines), 3):
            castle_recipe_unlocks: dict[int, CastleRecipeUnlock] = {}
            for j in range(3):
                castle_id = unlock_csv.lines[i + j][0].to_int()
                unknown_1 = unlock_csv.lines[i + j][1].to_int()
                unknown_2 = unlock_csv.lines[i + j][2].to_int()
                max_level = unlock_csv.lines[i + j][3].to_int()
                castle_recipe_unlocks[j] = CastleRecipeUnlock(
                    castle_id, unknown_1, unknown_2, max_level, j
                )
            castle_type = cannon.CastleType(i // 3)
            unlock_sets[castle_type] = CastleRecipeUnlockSet(
                i // 3, castle_recipe_unlocks
            )

        castle_recipies: dict[cannon.CastleType, CastleRecipe] = {}
        for i, line in enumerate(unlock_data_csv.lines[1:]):
            castle_type = cannon.CastleType(line[0].to_int())
            recipe_id = line[1].to_int()
            dev_level = line[2].to_int()
            stage_unlocked = line[3].to_int()
            user_rank_unlocked = line[4].to_int()
            attack_level = line[5].to_int()
            charge_level = line[6].to_int()
            name_png = game_data.find_file(
                CastleRecipe.get_name_png_file_name(castle_type)
            )
            if name_png is None:
                raise FileNotFoundError(
                    f"{CastleRecipe.get_name_png_file_name(castle_type)} not found"
                )
            name_png = io.bc_image.BCImage(name_png.dec_data)
            name_imgcut = bc_anim.Imgcut.from_data(name_imgcut_file.dec_data, name_png)
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
                names[castle_type.value],
                descriptions[castle_type.value],
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

        for i in range(0, len(unlock_csv.lines), 3):
            castle_type = cannon.CastleType(i // 3)
            try:
                castle_recipe_unlock_set = self.recipies[castle_type].unlock_set
            except KeyError:
                continue
            for j in range(3):
                castle_recipe_unlock = castle_recipe_unlock_set.castle_recipe_unlocks[j]
                unlock_csv.lines[i + j][0].set(castle_recipe_unlock.castle_id)
                unlock_csv.lines[i + j][1].set(castle_recipe_unlock.unknown_1)
                unlock_csv.lines[i + j][2].set(castle_recipe_unlock.unknown_2)
                unlock_csv.lines[i + j][3].set(castle_recipe_unlock.max_level)
            remaining_recipies.pop(castle_type)

        for castle_type, castle_recipe in remaining_recipies.items():
            castle_recipe_unlock_set = castle_recipe.unlock_set
            for j in range(3):
                castle_recipe_unlock = castle_recipe_unlock_set.castle_recipe_unlocks[j]
                unlock_csv.add_line(
                    [
                        castle_recipe_unlock.castle_id,
                        castle_recipe_unlock.unknown_1,
                        castle_recipe_unlock.unknown_2,
                        castle_recipe_unlock.max_level,
                    ]
                )

        remaining_recipies = self.recipies.copy()

        for i, line in enumerate(unlock_data_csv.lines[1:]):
            castle_type = cannon.CastleType(line[0].to_int())
            try:
                castle_recipe = self.recipies[castle_type]
            except KeyError:
                continue
            line[1].set(castle_recipe.recipe_id)
            line[2].set(castle_recipe.dev_level)
            line[3].set(castle_recipe.stage_unlocked)
            line[4].set(castle_recipe.user_rank_unlocked)
            line[5].set(castle_recipe.attack_level)
            line[6].set(castle_recipe.charge_level)
            unlock_data_csv.set_line(i + 1, line)
            remaining_recipies.pop(castle_type)

        for castle_type, castle_recipe in remaining_recipies.items():
            unlock_data_csv.add_line(
                [
                    castle_type,
                    castle_recipe.recipe_id,
                    castle_recipe.dev_level,
                    castle_recipe.stage_unlocked,
                    castle_recipe.user_rank_unlocked,
                    castle_recipe.attack_level,
                    castle_recipe.charge_level,
                ]
            )

        remaining_recipies = self.recipies.copy()

        for i, line in enumerate(description_csv.lines):
            if len(line) < 2:
                continue
            castle_id = line[0].to_int()
            try:
                castle_recipe = self.recipies[cannon.CastleType(castle_id)]
            except KeyError:
                continue
            line[1].set(castle_recipe.name)
            line[2:] = []
            for j, description_line in enumerate(castle_recipe.description):
                line.append(io.data.Data(description_line))
            description_csv.set_line(i, line)
            remaining_recipies.pop(cannon.CastleType(i))

        for castle_type, castle_recipe in remaining_recipies.items():
            description_csv.add_line(
                [
                    castle_recipe.name,
                    *[
                        io.data.Data(description_line)
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
            imgcut = recipe.name_imgcut.to_data()
            game_data.set_file("castleCustom_name_ALL.imgcut", imgcut[0])


    def get_castle_recipe(
        self, castle_type: cannon.CastleType
    ) -> Optional[CastleRecipe]:
        return self.recipies.get(castle_type, None)

    def set_castle_recipe(
        self, castle_type: cannon.CastleType, castle_recipe: CastleRecipe
    ):
        self.recipies[castle_type] = castle_recipe