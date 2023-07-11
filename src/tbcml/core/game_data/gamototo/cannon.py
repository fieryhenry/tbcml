from typing import Any, Optional

from tbcml import core


class CastleMixRecipe:
    def __init__(
        self,
        index: int,
        product_id: int,
        unknown_1: int,
        unknown_2: int,
        material_id: int,
        amount: int,
    ):
        self.index = index
        self.product_id = product_id
        self.unknown_1 = unknown_1
        self.unknown_2 = unknown_2
        self.material_id = material_id
        self.amount = amount

    def apply_dict(self, dict_data: dict[str, Any]):
        self.product_id = dict_data.get("product_id", self.product_id)
        self.unknown_1 = dict_data.get("unknown_1", self.unknown_1)
        self.unknown_2 = dict_data.get("unknown_2", self.unknown_2)
        self.material_id = dict_data.get("material_id", self.material_id)
        self.amount = dict_data.get("amount", self.amount)

    @staticmethod
    def create_empty(index: int):
        return CastleMixRecipe(index, 0, 0, 0, 0, 0)


class CastleMixRecipies(core.EditableClass):
    def __init__(self, recipies: dict[int, CastleMixRecipe]):
        self.data = recipies
        super().__init__(recipies)

    @staticmethod
    def get_file_name() -> str:
        return "CastleMixRecipe.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "CastleMixRecipies":
        if game_data.castle_mix_recipies is not None:
            return game_data.castle_mix_recipies
        file = game_data.find_file(CastleMixRecipies.get_file_name())
        if file is None:
            return CastleMixRecipies.create_empty()
        csv = core.CSV(file.dec_data)
        recipies: dict[int, CastleMixRecipe] = {}
        for i, line in enumerate(csv.lines):
            recipies[i] = CastleMixRecipe(
                i,
                int(line[0]),
                int(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
            )

        castle_mix_recipes = CastleMixRecipies(recipies)
        game_data.castle_mix_recipies = castle_mix_recipes
        return castle_mix_recipes

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CastleMixRecipies.get_file_name())
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        remaining_recipies = self.data.copy()
        for i, line in enumerate(csv.lines):
            recipe = self.data.get(i)
            if recipe is None:
                continue
            line[0] = str(recipe.product_id)
            line[1] = str(recipe.unknown_1)
            line[2] = str(recipe.unknown_2)
            line[3] = str(recipe.material_id)
            line[4] = str(recipe.amount)
            csv.lines[i] = line
            remaining_recipies.pop(i)
        for recipe in remaining_recipies.values():
            new_line: list[str] = []
            new_line.append(str(recipe.product_id))
            new_line.append(str(recipe.unknown_1))
            new_line.append(str(recipe.unknown_2))
            new_line.append(str(recipe.material_id))
            new_line.append(str(recipe.amount))
            csv.lines.append(new_line)
        game_data.set_file(CastleMixRecipies.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CastleMixRecipies({})


class BaseDecoRecipeLevel:
    def __init__(
        self,
        index: int,
        time: int,
        engineers: int,
        unknown_1: int,
        unknown_2: int,
        unknown_3: int,
        unknown_4: int,
        unknown_5: int,
        unknown_6: int,
        unknown_7: int,
        unknown_8: int,
        brick_z: int,
        feather_z: int,
        coals_z: int,
        sprockets_z: int,
        gold_z: int,
        meteorite_z: int,
        beast_bones_z: int,
        relic_fossil_z: int,
    ):
        self.index = index
        self.time = time
        self.engineers = engineers
        self.unknown_1 = unknown_1
        self.unknown_2 = unknown_2
        self.unknown_3 = unknown_3
        self.unknown_4 = unknown_4
        self.unknown_5 = unknown_5
        self.unknown_6 = unknown_6
        self.unknown_7 = unknown_7
        self.unknown_8 = unknown_8
        self.brick_z = brick_z
        self.feather_z = feather_z
        self.coals_z = coals_z
        self.sprockets_z = sprockets_z
        self.gold_z = gold_z
        self.meteorite_z = meteorite_z
        self.beast_bones_z = beast_bones_z
        self.relic_fossil_z = relic_fossil_z

    def apply_dict(self, dict_data: dict[str, Any]):
        self.time = dict_data.get("time", self.time)
        self.engineers = dict_data.get("engineers", self.engineers)
        self.unknown_1 = dict_data.get("unknown_1", self.unknown_1)
        self.unknown_2 = dict_data.get("unknown_2", self.unknown_2)
        self.unknown_3 = dict_data.get("unknown_3", self.unknown_3)
        self.unknown_4 = dict_data.get("unknown_4", self.unknown_4)
        self.unknown_5 = dict_data.get("unknown_5", self.unknown_5)
        self.unknown_6 = dict_data.get("unknown_6", self.unknown_6)
        self.unknown_7 = dict_data.get("unknown_7", self.unknown_7)
        self.unknown_8 = dict_data.get("unknown_8", self.unknown_8)
        self.brick_z = dict_data.get("brick_z", self.brick_z)
        self.feather_z = dict_data.get("feather_z", self.feather_z)
        self.coals_z = dict_data.get("coals_z", self.coals_z)
        self.sprockets_z = dict_data.get("sprockets_z", self.sprockets_z)
        self.gold_z = dict_data.get("gold_z", self.gold_z)
        self.meteorite_z = dict_data.get("meteorite_z", self.meteorite_z)
        self.beast_bones_z = dict_data.get("beast_bones_z", self.beast_bones_z)
        self.relic_fossil_z = dict_data.get("relic_fossil_z", self.relic_fossil_z)

    @staticmethod
    def create_empty(index: int):
        return BaseDecoRecipeLevel(
            index, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )


class BaseDecoRecipe:
    def __init__(self, index: int, levels: dict[int, BaseDecoRecipeLevel]):
        self.index = index
        self.levels = levels

    @staticmethod
    def get_file_name(id: int) -> str:
        ...

    @staticmethod
    def from_game_data(game_data: "core.GamePacks", id: int) -> "BaseDecoRecipe":
        file_name = BaseDecoRecipe.get_file_name(id)
        file = game_data.find_file(file_name)
        if file is None:
            return BaseDecoRecipe.create_empty(id)

        csv = core.CSV(file.dec_data)
        levels: dict[int, BaseDecoRecipeLevel] = {}
        for i, level in enumerate(csv.lines):
            levels[i] = BaseDecoRecipeLevel(
                i,
                int(level[0]),
                int(level[1]),
                int(level[2]),
                int(level[3]),
                int(level[4]),
                int(level[5]),
                int(level[6]),
                int(level[7]),
                int(level[8]),
                int(level[9]),
                int(level[10]),
                int(level[11]),
                int(level[12]),
                int(level[13]),
                int(level[14]),
                int(level[15]),
                int(level[16]),
                int(level[17]),
            )

        return BaseDecoRecipe(id, levels)

    def to_game_data(self, game_data: "core.GamePacks"):
        file_name = BaseDecoRecipe.get_file_name(self.index)
        file = game_data.find_file(file_name)
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_levels = self.levels.copy()
        for i in range(len(csv.lines)):
            level = self.levels.get(i)
            if level is None:
                continue
            csv.lines[i] = [
                str(level.time),
                str(level.engineers),
                str(level.unknown_1),
                str(level.unknown_2),
                str(level.unknown_3),
                str(level.unknown_4),
                str(level.unknown_5),
                str(level.unknown_6),
                str(level.unknown_7),
                str(level.unknown_8),
                str(level.brick_z),
                str(level.feather_z),
                str(level.coals_z),
                str(level.sprockets_z),
                str(level.gold_z),
                str(level.meteorite_z),
                str(level.beast_bones_z),
                str(level.relic_fossil_z),
            ]
            remaining_levels.pop(i, None)

        for i, level in remaining_levels.items():
            csv.lines.append(
                [
                    str(level.time),
                    str(level.engineers),
                    str(level.unknown_1),
                    str(level.unknown_2),
                    str(level.unknown_3),
                    str(level.unknown_4),
                    str(level.unknown_5),
                    str(level.unknown_6),
                    str(level.unknown_7),
                    str(level.unknown_8),
                    str(level.brick_z),
                    str(level.feather_z),
                    str(level.coals_z),
                    str(level.sprockets_z),
                    str(level.gold_z),
                    str(level.meteorite_z),
                    str(level.beast_bones_z),
                    str(level.relic_fossil_z),
                ]
            )

        game_data.set_file(file_name, csv.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        levels = dict_data.get("levels")
        if levels is not None:
            current_levels = self.levels.copy()
            modded_levels = core.ModEditDictHandler(levels, current_levels).get_dict(
                convert_int=True
            )
            for id, modded_level in modded_levels.items():
                level = self.levels.get(id)
                if level is None:
                    self.levels[id] = BaseDecoRecipeLevel.create_empty(id)
                self.levels[id].apply_dict(modded_level)

    @staticmethod
    def create_empty(index: int):
        return BaseDecoRecipe(index, {})


class BaseRecipe(BaseDecoRecipe):
    @staticmethod
    def get_file_name(id: int) -> str:
        id_str = core.PaddedInt(id, 3)
        return f"BaseRecipe_{id_str}.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks", id: int) -> "BaseRecipe":
        base_decos = BaseDecoRecipe.from_game_data(game_data, id)
        return BaseRecipe(id, base_decos.levels)

    @staticmethod
    def create_empty(index: int) -> "BaseRecipe":
        return BaseRecipe(index, {})


class DecoRecipe(BaseDecoRecipe):
    @staticmethod
    def get_file_name(id: int) -> str:
        id_str = core.PaddedInt(id, 3)
        return f"DecoRecipe_{id_str}.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks", id: int) -> "DecoRecipe":
        base_decos = BaseDecoRecipe.from_game_data(game_data, id)
        return DecoRecipe(id, base_decos.levels)

    @staticmethod
    def create_empty(index: int) -> "DecoRecipe":
        return DecoRecipe(index, {})


class CannonRecipeLevel:
    def __init__(
        self,
        index: int,
        time: int,
        engineers: int,
        brick: int,
        feather: int,
        coals: int,
        sprockets: int,
        gold: int,
        meteorite: int,
        beast_bones: int,
        relic_fossil: int,
    ):
        self.index = index
        self.time = time
        self.engineers = engineers
        self.brick = brick
        self.feather = feather
        self.coals = coals
        self.sprockets = sprockets
        self.gold = gold
        self.meteorite = meteorite
        self.beast_bones = beast_bones
        self.relic_fossil = relic_fossil

    def apply_dict(self, dict_data: dict[str, Any]):
        self.time = dict_data.get("time", self.time)
        self.engineers = dict_data.get("engineers", self.engineers)
        self.brick = dict_data.get("brick", self.brick)
        self.feather = dict_data.get("feather", self.feather)
        self.coals = dict_data.get("coals", self.coals)
        self.sprockets = dict_data.get("sprockets", self.sprockets)
        self.gold = dict_data.get("gold", self.gold)
        self.meteorite = dict_data.get("meteorite", self.meteorite)
        self.beast_bones = dict_data.get("beast_bones", self.beast_bones)
        self.relic_fossil = dict_data.get("relic_fossil", self.relic_fossil)

    @staticmethod
    def create_empty(index: int):
        return CannonRecipeLevel(index, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


class CannonRecipe:
    def __init__(self, index: int, levels: dict[int, CannonRecipeLevel]):
        self.index = index
        self.levels = levels

    @staticmethod
    def get_file_name(id: int) -> str:
        id_str = core.PaddedInt(id, 3)
        return f"CastleRecipe_{id_str}.csv"

    @staticmethod
    def from_game_data(id: int, game_data: "core.GamePacks") -> "CannonRecipe":
        file_name = CannonRecipe.get_file_name(id)
        file = game_data.find_file(file_name)
        if file is None:
            return CannonRecipe.create_empty(id)

        csv = core.CSV(file.dec_data)
        levels = {}
        for i in range(len(csv.lines)):
            level = CannonRecipeLevel(
                i,
                int(csv.lines[i][0]),
                int(csv.lines[i][1]),
                int(csv.lines[i][2]),
                int(csv.lines[i][3]),
                int(csv.lines[i][4]),
                int(csv.lines[i][5]),
                int(csv.lines[i][6]),
                int(csv.lines[i][7]),
                int(csv.lines[i][8]),
                int(csv.lines[i][9]),
            )
            levels[i] = level

        return CannonRecipe(id, levels)

    def to_game_data(self, game_data: "core.GamePacks"):
        file_name = CannonRecipe.get_file_name(self.index)
        file = game_data.find_file(file_name)
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_levels = self.levels.copy()
        for i in range(len(csv.lines)):
            level = self.levels.get(i)
            if level is None:
                continue
            csv.lines[i] = [
                str(level.time),
                str(level.engineers),
                str(level.brick),
                str(level.feather),
                str(level.coals),
                str(level.sprockets),
                str(level.gold),
                str(level.meteorite),
                str(level.beast_bones),
                str(level.relic_fossil),
            ]
            remaining_levels.pop(i, None)

        for i, level in remaining_levels.items():
            csv.lines.append(
                [
                    str(level.time),
                    str(level.engineers),
                    str(level.brick),
                    str(level.feather),
                    str(level.coals),
                    str(level.sprockets),
                    str(level.gold),
                    str(level.meteorite),
                    str(level.beast_bones),
                    str(level.relic_fossil),
                ]
            )

        game_data.set_file(file_name, csv.to_data())

    def apply_dict(self, dict_data: dict[str, Any]):
        levels = dict_data.get("levels")
        if levels is not None:
            current_levels = self.levels.copy()
            modded_levels = core.ModEditDictHandler(levels, current_levels).get_dict(
                convert_int=True
            )
            for id, modded_level in modded_levels.items():
                level = self.levels.get(id)
                if level is None:
                    level = CannonRecipeLevel.create_empty(id)
                    self.levels[id] = level
                level.apply_dict(modded_level)

    @staticmethod
    def create_empty(index: int):
        return CannonRecipe(index, {})


class CastleRecipeUnlockLevel:
    def __init__(
        self, castle_id: int, part_id: int, unknown_1: int, unknown_2: int, level: int
    ):
        self.castle_id = castle_id
        self.part_id = part_id
        self.unknown_1 = unknown_1
        self.unknown_2 = unknown_2
        self.level = level

    def apply_dict(self, dict_data: dict[str, Any]):
        self.castle_id = dict_data.get("castle_id", self.castle_id)
        self.part_id = dict_data.get("part_id", self.part_id)
        self.unknown_1 = dict_data.get("unknown_1", self.unknown_1)
        self.unknown_2 = dict_data.get("unknown_2", self.unknown_2)
        self.level = dict_data.get("level", self.level)

    @staticmethod
    def create_empty(castle_id: int, part_id: int, level: int):
        return CastleRecipeUnlockLevel(castle_id, part_id, 0, 0, level)

    @staticmethod
    def from_line(line: list[str]):
        return CastleRecipeUnlockLevel(
            int(line[0]),
            int(line[1]),
            int(line[2]),
            int(line[3]),
            int(line[4]),
        )

    def to_line(self):
        return [
            str(self.castle_id),
            str(self.part_id),
            str(self.unknown_1),
            str(self.unknown_2),
            str(self.level),
        ]


class CastleRecipeUnlockPart:
    def __init__(
        self, castle_id: int, part_id: int, levels: dict[int, CastleRecipeUnlockLevel]
    ):
        self.castle_id = castle_id
        self.part_id = part_id
        self.levels = levels

    def apply_dict(self, dict_data: dict[str, Any]):
        levels = dict_data.get("levels")
        if levels is not None:
            current_levels = self.levels.copy()
            modded_levels = core.ModEditDictHandler(levels, current_levels).get_dict(
                convert_int=True
            )
            for id, modded_level in modded_levels.items():
                level = self.levels.get(id)
                if level is None:
                    level = CastleRecipeUnlockLevel.create_empty(
                        self.castle_id, self.part_id, id
                    )
                    self.levels[id] = level
                level.apply_dict(modded_level)

    @staticmethod
    def create_empty(castle_id: int, part_id: int):
        return CastleRecipeUnlockPart(castle_id, part_id, {})

    @staticmethod
    def from_lines(lines: list[list[str]], castle_id: int, part_id: int):
        levels: dict[int, CastleRecipeUnlockLevel] = {}
        for line in lines:
            if int(line[0]) != castle_id or int(line[1]) != part_id:
                continue
            level = CastleRecipeUnlockLevel.from_line(line)
            levels[level.level] = level
        return CastleRecipeUnlockPart(castle_id, part_id, levels)


class CastleRecipeUnlockCastle:
    def __init__(self, castle_id: int, parts: dict[int, CastleRecipeUnlockPart]):
        self.castle_id = castle_id
        self.parts = parts

    def apply_dict(self, dict_data: dict[str, Any]):
        parts = dict_data.get("parts")
        if parts is not None:
            current_parts = self.parts.copy()
            modded_parts = core.ModEditDictHandler(parts, current_parts).get_dict(
                convert_int=True
            )
            for id, modded_part in modded_parts.items():
                part = self.parts.get(id)
                if part is None:
                    part = CastleRecipeUnlockPart.create_empty(self.castle_id, id)
                    self.parts[id] = part
                part.apply_dict(modded_part)

    @staticmethod
    def create_empty(castle_id: int):
        return CastleRecipeUnlockCastle(castle_id, {})

    @staticmethod
    def from_lines(lines: list[list[str]], castle_id: int):
        parts: dict[int, CastleRecipeUnlockPart] = {}
        for line in lines:
            if int(line[0]) != castle_id:
                continue
            part = CastleRecipeUnlockPart.from_lines(lines, castle_id, int(line[1]))
            parts[part.part_id] = part
        return CastleRecipeUnlockCastle(castle_id, parts)


class CastleRecipeUnlock:
    def __init__(self, castles: dict[int, CastleRecipeUnlockCastle]):
        self.castles = castles

    @staticmethod
    def get_file_name():
        return "CastleRecipeUnlock.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file = game_data.find_file(CastleRecipeUnlock.get_file_name())
        if file is None:
            return CastleRecipeUnlock.create_empty()

        csv = core.CSV(file.dec_data)
        castles: dict[int, CastleRecipeUnlockCastle] = {}
        for line in csv.lines:
            castle = CastleRecipeUnlockCastle.from_lines(csv.lines, int(line[0]))
            castles[castle.castle_id] = castle
        return CastleRecipeUnlock(castles)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CastleRecipeUnlock.get_file_name())
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_castles = self.castles.copy()
        for i, line in enumerate(csv.lines):
            castle_id = int(line[0])
            part_id = int(line[1])
            level = int(line[4])
            castle = self.castles.get(castle_id)
            if castle is None:
                continue
            part = castle.parts.get(part_id)
            if part is None:
                continue
            level = part.levels.get(level)
            if level is None:
                continue
            remaining_castles.pop(castle_id, None)
            csv.lines[i] = level.to_line()
        for castle in remaining_castles.values():
            for part in castle.parts.values():
                for level in part.levels.values():
                    csv.lines.append(level.to_line())
        game_data.set_file(CastleRecipeUnlock.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CastleRecipeUnlock({})


class CastleRecipeUnlockDataCastle:
    def __init__(
        self,
        castle_id: int,
        recipe_id: int,
        dev_level: int,
        stage_unlocked: int,
        user_rank_unlocked: int,
        attack_level: int,
        charge_level: int,
    ):
        self.castle_id = castle_id
        self.recipe_id = recipe_id
        self.dev_level = dev_level
        self.stage_unlocked = stage_unlocked
        self.user_rank_unlocked = user_rank_unlocked
        self.attack_level = attack_level
        self.charge_level = charge_level

    def apply_dict(self, dict_data: dict[str, Any]):
        self.dev_level = dict_data.get("dev_level", self.dev_level)
        self.stage_unlocked = dict_data.get("stage_unlocked", self.stage_unlocked)
        self.user_rank_unlocked = dict_data.get(
            "user_rank_unlocked", self.user_rank_unlocked
        )
        self.attack_level = dict_data.get("attack_level", self.attack_level)
        self.charge_level = dict_data.get("charge_level", self.charge_level)

    @staticmethod
    def create_empty(castle_id: int):
        return CastleRecipeUnlockDataCastle(
            castle_id,
            0,
            0,
            0,
            0,
            0,
            0,
        )

    def to_line(self):
        return [
            str(self.castle_id),
            str(self.recipe_id),
            str(self.dev_level),
            str(self.stage_unlocked),
            str(self.user_rank_unlocked),
            str(self.attack_level),
            str(self.charge_level),
        ]


class CastleRecipeUnlockData:
    def __init__(self, castles: dict[int, CastleRecipeUnlockDataCastle]):
        self.castles = castles

    @staticmethod
    def get_file_name():
        return "CastleRecipeUnlockData.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file = game_data.find_file(CastleRecipeUnlockData.get_file_name())
        if file is None:
            return CastleRecipeUnlockData.create_empty()

        csv = core.CSV(file.dec_data)
        castles: dict[int, CastleRecipeUnlockDataCastle] = {}
        for line in csv.lines[1:]:
            castle = CastleRecipeUnlockDataCastle(
                int(line[0]),
                int(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
                int(line[6]),
            )
            castles[castle.castle_id] = castle
        return CastleRecipeUnlockData(castles)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CastleRecipeUnlockData.get_file_name())
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_castles = self.castles.copy()
        for i, line in enumerate(csv.lines[1:]):
            castle_id = int(line[0])
            castle = self.castles.get(castle_id)
            if castle is None:
                continue
            remaining_castles.pop(castle_id, None)
            csv.lines[i] = castle.to_line()
        for castle in remaining_castles.values():
            csv.lines.append(castle.to_line())
        game_data.set_file(CastleRecipeUnlockData.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CastleRecipeUnlockData({})


class CannonEffectLevel:
    def __init__(
        self, castle_id: int, type: int, level: int, start: int, end: int, easing: int
    ):
        self.castle_id = castle_id
        self.type = type
        self.level = level
        self.start = start
        self.end = end
        self.easing = easing

    def apply_dict(self, dict_data: dict[str, Any]):
        self.level = dict_data.get("level", self.level)
        self.start = dict_data.get("start", self.start)
        self.end = dict_data.get("end", self.end)
        self.easing = dict_data.get("easing", self.easing)

    @staticmethod
    def create_empty(castle_id: int, level: int):
        return CannonEffectLevel(castle_id, 0, level, 0, 0, 0)

    def to_line(self):
        return [
            str(self.castle_id),
            str(self.type),
            str(self.level),
            str(self.start),
            str(self.end),
            str(self.easing),
        ]


class CannonEffectCastle:
    def __init__(self, castle_id: int, levels: dict[int, CannonEffectLevel]):
        self.castle_id = castle_id
        self.levels = levels

    def apply_dict(self, dict_data: dict[str, Any]):
        levels = dict_data.get("levels")
        if levels is not None:
            current_levels = self.levels.copy()
            modded_levels = core.ModEditDictHandler(levels, current_levels).get_dict(
                convert_int=True
            )
            for id, modded_level in modded_levels.items():
                level = self.levels.get(id)
                if level is None:
                    level = CannonEffectLevel.create_empty(self.castle_id, id)
                    self.levels[id] = level
                level.apply_dict(modded_level)

    @staticmethod
    def create_empty(castle_id: int):
        return CannonEffectCastle(castle_id, {})

    @staticmethod
    def from_lines(castle_id: int, lines: list[list[str]]):
        levels: dict[int, CannonEffectLevel] = {}
        for line in lines:
            if int(line[0]) != castle_id:
                continue
            level = CannonEffectLevel(
                int(line[0]),
                int(line[1]),
                int(line[2]),
                int(line[3]),
                int(line[4]),
                int(line[5]),
            )
            levels[level.level] = level
        return CannonEffectCastle(castle_id, levels)


class CannonEffectsData:
    def __init__(self, castles: dict[int, CannonEffectCastle]):
        self.castles = castles

    @staticmethod
    def get_file_name() -> str:
        return "CC_AllParts_growth.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file = game_data.find_file(CannonEffectsData.get_file_name())
        if file is None:
            return CannonEffectsData.create_empty()

        csv = core.CSV(file.dec_data)
        castles: dict[int, CannonEffectCastle] = {}

        for line in csv.lines[1:]:
            castle_id = int(line[0])
            castle_effect = CannonEffectCastle.from_lines(castle_id, csv.lines[1:])
            castles[castle_id] = castle_effect
        return CannonEffectsData(castles)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CannonEffectsData.get_file_name())
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_castles = self.castles.copy()
        for i, line in enumerate(csv.lines[1:]):
            castle_id = int(line[0])
            castle = self.castles.get(castle_id)
            if castle is None:
                continue
            level = int(line[2])
            remaining_castles.pop(castle_id, None)
            csv.lines[i] = castle.levels[level].to_line()
        for castle in remaining_castles.values():
            for level in castle.levels.values():
                csv.lines.append(level.to_line())
        game_data.set_file(CannonEffectsData.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CannonEffectsData({})


class BaseEffectsData(CannonEffectsData):
    @staticmethod
    def get_file_name() -> str:
        return "CC_BaseParts_growth.csv"


class DecoEffectsData(CannonEffectsData):
    @staticmethod
    def get_file_name() -> str:
        return "CC_DecoParts_growth.csv"


class CannonStatus:
    def __init__(
        self,
        castle_id: int,
        type: int,
        wave: bool,
        option: int,
        knockback: bool,
        mark: bool,
        unknown: bool,
    ):
        self.castle_id = castle_id
        self.type = type
        self.wave = wave
        self.option = option
        self.knockback = knockback
        self.mark = mark
        self.unknown = unknown

    def apply_dict(self, dict_data: dict[str, Any]):
        self.type = dict_data.get("type", self.type)
        self.wave = dict_data.get("wave", self.wave)
        self.option = dict_data.get("option", self.option)
        self.knockback = dict_data.get("knockback", self.knockback)
        self.mark = dict_data.get("mark", self.mark)
        self.unknown = dict_data.get("unknown", self.unknown)

    @staticmethod
    def create_empty(castle_id: int):
        return CannonStatus(castle_id, 0, False, 0, False, False, False)

    @staticmethod
    def from_line(line: list[str]):
        return CannonStatus(
            int(line[0]),
            int(line[1]),
            bool(int(line[2])),
            int(line[3]),
            bool(int(line[4])),
            bool(int(line[5])),
            bool(int(line[6])),
        )

    def to_line(self):
        return [
            str(self.castle_id),
            str(self.type),
            str(int(self.wave)),
            str(self.option),
            str(int(self.knockback)),
            str(int(self.mark)),
            str(int(self.unknown)),
        ]


class CannonStatusesData:
    def __init__(self, statuses: dict[int, CannonStatus]):
        self.statuses = statuses

    @staticmethod
    def get_file_name() -> str:
        return "CC_AllParts_status.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file = game_data.find_file(CannonStatusesData.get_file_name())
        if file is None:
            return CannonStatusesData.create_empty()

        csv = core.CSV(file.dec_data)
        statuses: dict[int, CannonStatus] = {}

        for line in csv.lines[1:]:
            castle_id = int(line[0])
            status = CannonStatus.from_line(line)
            statuses[castle_id] = status
        return CannonStatusesData(statuses)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CannonStatusesData.get_file_name())
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_statuses = self.statuses.copy()
        for i, line in enumerate(csv.lines[1:]):
            castle_id = int(line[0])
            status = self.statuses.get(castle_id)
            if status is None:
                continue
            remaining_statuses.pop(castle_id, None)
            csv.lines[i] = status.to_line()
        for status in remaining_statuses.values():
            csv.lines.append(status.to_line())
        game_data.set_file(CannonStatusesData.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CannonStatusesData({})


class CastleEffect:
    def __init__(self, level: int, start: int, end: int, easing: int):
        self.level = level
        self.start = start
        self.end = end
        self.easing = easing

    def apply_dict(self, dict_data: dict[str, Any]):
        self.level = dict_data.get("level", self.level)
        self.start = dict_data.get("start", self.start)
        self.end = dict_data.get("end", self.end)
        self.easing = dict_data.get("easing", self.easing)

    @staticmethod
    def create_empty(level: int):
        return CastleEffect(level, 0, 0, 0)

    @staticmethod
    def from_line(line: list[str]):
        return CastleEffect(
            int(line[0]),
            int(line[1]),
            int(line[2]),
            int(line[3]),
        )

    def to_line(self):
        return [
            str(self.level),
            str(self.start),
            str(self.end),
            str(self.easing),
        ]


class CastleEffectsData:
    def __init__(self, effects: dict[int, CastleEffect]):
        self.effects = effects

    @staticmethod
    def get_file_name() -> str:
        return "CC_Castle_growth.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file = game_data.find_file(CastleEffectsData.get_file_name())
        if file is None:
            return CastleEffectsData.create_empty()

        csv = core.CSV(file.dec_data)
        effects: dict[int, CastleEffect] = {}

        for line in csv.lines[1:]:
            level = int(line[0])
            effect = CastleEffect.from_line(line)
            effects[level] = effect
        return CastleEffectsData(effects)

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(CastleEffectsData.get_file_name())
        if file is None:
            return

        csv = core.CSV(file.dec_data)
        remaining_effects = self.effects.copy()
        for i, line in enumerate(csv.lines[1:]):
            level = int(line[0])
            effect = self.effects.get(level)
            if effect is None:
                continue
            remaining_effects.pop(level, None)
            csv.lines[i] = effect.to_line()
        for effect in remaining_effects.values():
            csv.lines.append(effect.to_line())
        game_data.set_file(CastleEffectsData.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty():
        return CastleEffectsData({})

    def apply_dict(self, dict_data: dict[str, Any]):
        for level, effect in self.effects.items():
            effect.apply_dict(dict_data.get(str(level), {}))


class RecipeDescriptionCastle:
    def __init__(
        self,
        castle_id: int,
        castle_name: str,
        foundation_build_description: str,
        style_build_description: str,
        effect_build_description: str,
        castle_upgrade_description: str,
        cannon_name: str,
        foundation_name: str,
        style_name: str,
        cannon_effect_description: str,
        foundation_effect_description: Optional[str] = None,
        style_effect_description: Optional[str] = None,
        foundation_effect_description_2: Optional[str] = None,
        style_effect_description_2: Optional[str] = None,
        foundation_effect_description_3: Optional[str] = None,
        style_effect_description_3: Optional[str] = None,
    ):
        self.castle_id = castle_id
        self.castle_name = castle_name
        self.foundation_build_description = foundation_build_description
        self.style_build_description = style_build_description
        self.effect_build_description = effect_build_description
        self.castle_upgrade_description = castle_upgrade_description
        self.cannon_name = cannon_name
        self.foundation_name = foundation_name
        self.style_name = style_name
        self.cannon_effect_description = cannon_effect_description
        self.foundation_effect_description = foundation_effect_description
        self.style_effect_description = style_effect_description
        self.foundation_effect_description_2 = foundation_effect_description_2
        self.style_effect_description_2 = style_effect_description_2
        self.foundation_effect_description_3 = foundation_effect_description_3
        self.style_effect_description_3 = style_effect_description_3

    @staticmethod
    def from_line(line: list[str]):
        castle_id = int(line[0])
        castle_name = line[1]
        foundation_build_description = line[2]
        style_build_description = line[3]
        effect_build_description = line[4]
        castle_upgrade_description = line[5]
        cannon_name = line[6]
        foundation_name = line[7]
        style_name = line[8]
        cannon_effect_description = line[9]
        foundation_effect_description = None
        style_effect_description = None
        foundation_effect_description_2 = None
        style_effect_description_2 = None
        foundation_effect_description_3 = None
        style_effect_description_3 = None
        if len(line) == 11:
            foundation_effect_description = line[10]
        elif len(line) == 12:
            style_effect_description = line[11]
        elif len(line) == 13:
            foundation_effect_description_2 = line[12]
        elif len(line) == 14:
            style_effect_description_2 = line[13]
        elif len(line) == 15:
            foundation_effect_description_3 = line[14]
        elif len(line) == 16:
            style_effect_description_3 = line[15]

        return RecipeDescriptionCastle(
            castle_id,
            castle_name,
            foundation_build_description,
            style_build_description,
            effect_build_description,
            castle_upgrade_description,
            cannon_name,
            foundation_name,
            style_name,
            cannon_effect_description,
            foundation_effect_description,
            style_effect_description,
            foundation_effect_description_2,
            style_effect_description_2,
            foundation_effect_description_3,
            style_effect_description_3,
        )

    def to_line(self):
        line = [str(self.castle_id), self.castle_name]
        line.append(self.foundation_build_description)
        line.append(self.style_build_description)
        line.append(self.effect_build_description)
        line.append(self.castle_upgrade_description)
        line.append(self.cannon_name)
        line.append(self.foundation_name)
        line.append(self.style_name)
        line.append(self.cannon_effect_description)
        if self.foundation_effect_description is not None:
            line.append(self.foundation_effect_description)
        if self.style_effect_description is not None:
            line.append(self.style_effect_description)
        if self.foundation_effect_description_2 is not None:
            line.append(self.foundation_effect_description_2)
        if self.style_effect_description_2 is not None:
            line.append(self.style_effect_description_2)
        if self.foundation_effect_description_3 is not None:
            line.append(self.foundation_effect_description_3)
        if self.style_effect_description_3 is not None:
            line.append(self.style_effect_description_3)
        return line

    @staticmethod
    def create_empty(id: int):
        return RecipeDescriptionCastle(id, "", "", "", "", "", "", "", "", "")

    def apply_dict(self, dict_data: dict[str, Any]):
        self.castle_name = dict_data.get("castle_name", self.castle_name)
        self.foundation_build_description = dict_data.get(
            "foundation_build_description", self.foundation_build_description
        )
        self.style_build_description = dict_data.get(
            "style_build_description", self.style_build_description
        )
        self.effect_build_description = dict_data.get(
            "effect_build_description", self.effect_build_description
        )
        self.castle_upgrade_description = dict_data.get(
            "castle_upgrade_description", self.castle_upgrade_description
        )
        self.cannon_name = dict_data.get("cannon_name", self.cannon_name)
        self.foundation_name = dict_data.get("foundation_name", self.foundation_name)
        self.style_name = dict_data.get("style_name", self.style_name)
        self.cannon_effect_description = dict_data.get(
            "cannon_effect_description", self.cannon_effect_description
        )
        self.foundation_effect_description = dict_data.get(
            "foundation_effect_description", self.foundation_effect_description
        )
        self.style_effect_description = dict_data.get(
            "style_effect_description", self.style_effect_description
        )
        self.foundation_effect_description_2 = dict_data.get(
            "foundation_effect_description_2", self.foundation_effect_description_2
        )
        self.style_effect_description_2 = dict_data.get(
            "style_effect_description_2", self.style_effect_description_2
        )
        self.foundation_effect_description_3 = dict_data.get(
            "foundation_effect_description_3", self.foundation_effect_description_3
        )
        self.style_effect_description_3 = dict_data.get(
            "style_effect_description_3", self.style_effect_description_3
        )


class RecipeDescription:
    def __init__(self, recipies: dict[int, RecipeDescriptionCastle]):
        self.recipies = recipies

    @staticmethod
    def get_file_name():
        return "CastleRecipeDescriptions.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        file_name = RecipeDescription.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return RecipeDescription.create_empty()

        csv = core.CSV(
            file.dec_data,
            core.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        recipies: dict[int, RecipeDescriptionCastle] = {}
        for line in csv.lines:
            recipe = RecipeDescriptionCastle.from_line(line)
            recipies[recipe.castle_id] = recipe

        return RecipeDescription(recipies)

    def to_game_data(self, game_data: "core.GamePacks"):
        file_name = RecipeDescription.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return

        csv = core.CSV(
            file.dec_data,
            core.Delimeter.from_country_code_res(game_data.country_code),
            remove_empty=False,
        )
        remaining_recipies = self.recipies.copy()
        for i, line in enumerate(csv.lines):
            recipe = self.recipies.get(int(line[0]))
            if recipe is None:
                continue
            csv.lines[i] = recipe.to_line()
            del remaining_recipies[recipe.castle_id]

        for recipe in remaining_recipies.values():
            csv.lines.append(recipe.to_line())

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty():
        return RecipeDescription({})


class Castle:
    def __init__(
        self,
        id: int,
        recipe_description: RecipeDescriptionCastle,
        cannon_recipe: CannonRecipe,
        base_recipe: BaseRecipe,
        deco_recipe: DecoRecipe,
        recipe_unlock: CastleRecipeUnlockCastle,
        recipe_data_unlock: CastleRecipeUnlockDataCastle,
        all_parts_effects: CannonEffectCastle,
        base_effect: CannonEffectCastle,
        deco_effect: CannonEffectCastle,
        status: CannonStatus,
    ):
        self.id = id
        self.recipe_description = recipe_description
        self.cannon_recipe = cannon_recipe
        self.base_recipe = base_recipe
        self.deco_recipe = deco_recipe
        self.recipe_unlock = recipe_unlock
        self.recipe_data_unlock = recipe_data_unlock
        self.all_parts_effects = all_parts_effects
        self.base_effect = base_effect
        self.deco_effect = deco_effect
        self.status = status

    def apply_dict(self, dict_data: dict[str, Any]):
        recipe_description = dict_data.get("recipe_description")
        if recipe_description is not None:
            self.recipe_description.apply_dict(recipe_description)
        cannon_recipe = dict_data.get("cannon_recipe")
        if cannon_recipe is not None:
            self.cannon_recipe.apply_dict(cannon_recipe)
        base_recipe = dict_data.get("base_recipe")
        if base_recipe is not None:
            self.base_recipe.apply_dict(base_recipe)
        deco_recipe = dict_data.get("deco_recipe")
        if deco_recipe is not None:
            self.deco_recipe.apply_dict(deco_recipe)
        recipe_unlock = dict_data.get("recipe_unlock")
        if recipe_unlock is not None:
            self.recipe_unlock.apply_dict(recipe_unlock)
        recipe_data_unlock = dict_data.get("recipe_data_unlock")
        if recipe_data_unlock is not None:
            self.recipe_data_unlock.apply_dict(recipe_data_unlock)
        all_parts_effects = dict_data.get("all_parts_effects")
        if all_parts_effects is not None:
            self.all_parts_effects.apply_dict(all_parts_effects)
        base_effect = dict_data.get("base_effect")
        if base_effect is not None:
            self.base_effect.apply_dict(base_effect)
        deco_effect = dict_data.get("deco_effect")
        if deco_effect is not None:
            self.deco_effect.apply_dict(deco_effect)
        status = dict_data.get("status")
        if status is not None:
            self.status.apply_dict(status)

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        id: int,
        recipe_description_data: RecipeDescription,
        recipe_unlock_data: CastleRecipeUnlock,
        recipe_data_unlock_data: CastleRecipeUnlockData,
        cannon_effects_data: CannonEffectsData,
        base_effects_data: CannonEffectsData,
        deco_effects_data: CannonEffectsData,
        status_data: CannonStatusesData,
    ) -> tuple["Castle", bool]:
        missing_data = False
        cannon_recipe = CannonRecipe.from_game_data(id, game_data)
        base_recipe = BaseRecipe.from_game_data(game_data, id)
        deco_recipe = DecoRecipe.from_game_data(game_data, id)
        recipe_description = recipe_description_data.recipies.get(id)
        if recipe_description is None:
            recipe_description = RecipeDescriptionCastle.create_empty(id)
            missing_data = True
        recipe_unlock = recipe_unlock_data.castles.get(id)
        if recipe_unlock is None:
            recipe_unlock = CastleRecipeUnlockCastle.create_empty(id)
            missing_data = True
        recipe_data_unlock = recipe_data_unlock_data.castles.get(id)
        if recipe_data_unlock is None:
            recipe_data_unlock = CastleRecipeUnlockDataCastle.create_empty(id)
            missing_data = True
        all_parts_effects = cannon_effects_data.castles.get(id)
        if all_parts_effects is None:
            all_parts_effects = CannonEffectCastle.create_empty(id)
            missing_data = True
        base_effect = base_effects_data.castles.get(id)
        if base_effect is None:
            base_effect = CannonEffectCastle.create_empty(id)
            missing_data = True
        deco_effect = deco_effects_data.castles.get(id)
        if deco_effect is None:
            deco_effect = CannonEffectCastle.create_empty(id)
            missing_data = True
        status = status_data.statuses.get(id)
        if status is None:
            status = CannonStatus.create_empty(id)
            missing_data = True

        return (
            Castle(
                id,
                recipe_description,
                cannon_recipe,
                base_recipe,
                deco_recipe,
                recipe_unlock,
                recipe_data_unlock,
                all_parts_effects,
                base_effect,
                deco_effect,
                status,
            ),
            missing_data,
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        self.cannon_recipe.to_game_data(game_data)
        self.base_recipe.to_game_data(game_data)
        self.deco_recipe.to_game_data(game_data)

    @staticmethod
    def create_empty(id: int) -> "Castle":
        return Castle(
            id,
            RecipeDescriptionCastle.create_empty(id),
            CannonRecipe.create_empty(id),
            BaseRecipe.create_empty(id),
            DecoRecipe.create_empty(id),
            CastleRecipeUnlockCastle.create_empty(id),
            CastleRecipeUnlockDataCastle.create_empty(id),
            CannonEffectCastle.create_empty(id),
            CannonEffectCastle.create_empty(id),
            CannonEffectCastle.create_empty(id),
            CannonStatus.create_empty(id),
        )


class Castles(core.EditableClass):
    def __init__(
        self,
        castles: dict[int, Castle],
        castle_effect_data: CastleEffectsData,
    ):
        self.data = castles
        self.castle_effects = castle_effect_data
        super().__init__(self.data)

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        if game_data.castles is not None:
            return game_data.castles
        recipe_description_data = RecipeDescription.from_game_data(game_data)
        recipe_unlock_data = CastleRecipeUnlock.from_game_data(game_data)
        recipe_data_unlock_data = CastleRecipeUnlockData.from_game_data(game_data)
        cannon_effects_data = CannonEffectsData.from_game_data(game_data)
        base_effects_data = CannonEffectsData.from_game_data(game_data)
        deco_effects_data = CannonEffectsData.from_game_data(game_data)
        status_data = CannonStatusesData.from_game_data(game_data)
        castle_effects_data = CastleEffectsData.from_game_data(game_data)
        castles: dict[int, Castle] = {}
        while True:
            id = len(castles)
            castle, missing_data = Castle.from_game_data(
                game_data,
                id,
                recipe_description_data,
                recipe_unlock_data,
                recipe_data_unlock_data,
                cannon_effects_data,
                base_effects_data,
                deco_effects_data,
                status_data,
            )
            if missing_data:
                break
            castles[id] = castle
        castleso = Castles(castles, castle_effects_data)
        game_data.castles = castleso
        return castleso

    def to_game_data(self, game_data: "core.GamePacks"):
        recipe_description_data = RecipeDescription.create_empty()
        recipe_unlock_data = CastleRecipeUnlock.create_empty()
        recipe_data_unlock_data = CastleRecipeUnlockData.create_empty()
        cannon_effects_data = CannonEffectsData.create_empty()
        base_effects_data = CannonEffectsData.create_empty()
        deco_effects_data = CannonEffectsData.create_empty()
        status_data = CannonStatusesData.create_empty()

        for castle in self.data.values():
            castle.to_game_data(game_data)
            recipe_description_data.recipies[castle.id] = castle.recipe_description
            recipe_unlock_data.castles[castle.id] = castle.recipe_unlock
            recipe_data_unlock_data.castles[castle.id] = castle.recipe_data_unlock
            cannon_effects_data.castles[castle.id] = castle.all_parts_effects
            base_effects_data.castles[castle.id] = castle.base_effect
            deco_effects_data.castles[castle.id] = castle.deco_effect
            status_data.statuses[castle.id] = castle.status

        recipe_description_data.to_game_data(game_data)
        recipe_unlock_data.to_game_data(game_data)
        recipe_data_unlock_data.to_game_data(game_data)
        cannon_effects_data.to_game_data(game_data)
        base_effects_data.to_game_data(game_data)
        deco_effects_data.to_game_data(game_data)
        status_data.to_game_data(game_data)
        self.castle_effects.to_game_data(game_data)

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        data = dict_data.get(mod_edit_key)
        if data is None:
            return
        super().apply_dict(data, "castles", convert_int=convert_int)

        castle_effects = data.get("castle_effects")
        if castle_effects is not None:
            self.castle_effects.apply_dict(castle_effects)

    @staticmethod
    def create_empty() -> "Castles":
        return Castles({}, CastleEffectsData.create_empty())
