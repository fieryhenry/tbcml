import enum
from typing import Optional
from tbcml.core.game_data.gamototo import castle_recipe
from tbcml.core.game_data import pack
from tbcml.core import io, anim


class CannonStatus:
    def __init__(
        self,
        id: int,
        type: int,
        wave: bool,
        option: int,
        knockback: bool,
        mark: bool,
        unknown: bool,
    ):
        self.id = id
        self.type = type
        self.wave = wave
        self.option = option
        self.knockback = knockback
        self.mark = mark
        self.unknown = unknown


class CannonStatuses:
    def __init__(self, statuses: dict[int, CannonStatus]):
        self.statuses = statuses

    @staticmethod
    def get_file_name() -> str:
        return "CC_AllParts_status.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CannonStatuses":
        file_name = CannonStatuses.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return CannonStatuses.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        statuses: dict[int, CannonStatus] = {}
        for line in csv.lines[1:]:
            id = int(line[0])
            type = int(line[1])
            wave = bool(line[2])
            option = int(line[3])
            knockback = bool(line[4])
            mark = bool(line[5])
            unknown = bool(line[6])
            statuses[id] = CannonStatus(
                id, type, wave, option, knockback, mark, unknown
            )

        return CannonStatuses(statuses)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        file_name = CannonStatuses.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        remaining_statuses = set(self.statuses.keys())
        for i, line in enumerate(csv.lines[1:]):
            id = int(line[0])
            if id in self.statuses:
                status = self.statuses[id]
                line[1] = str(status.type)
                line[2] = str(status.wave)
                line[3] = str(status.option)
                line[4] = str(status.knockback)
                line[5] = str(status.mark)
                line[6] = str(status.unknown)
                csv.lines[i + 1] = line
                remaining_statuses.remove(id)

        for id in remaining_statuses:
            status = self.statuses[id]
            line = [
                str(status.id),
                str(status.type),
                str(status.wave),
                str(status.option),
                str(status.knockback),
                str(status.mark),
                str(status.unknown),
            ]
            csv.lines.append(line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CannonStatuses":
        return CannonStatuses({})


class EasingType(enum.Enum):
    LINEAR = 0
    EASE_IN_CUBIC = 1
    EASE_OUT_CUBIC = 2


class CastleGrowth:
    def __init__(self, level: int, start: int, end: int, easing_type: EasingType):
        self.level = level
        self.start = start
        self.end = end
        self.easing_type = easing_type


class CastleGrowths:
    def __init__(self, growths: dict[int, CastleGrowth]):
        self.growths = growths

    @staticmethod
    def get_file_name() -> str:
        return "CC_Castle_growth.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CastleGrowths":
        file_name = CastleGrowths.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return CastleGrowths.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        growths: dict[int, CastleGrowth] = {}
        for line in csv.lines[1:]:
            level = int(line[0])
            start = int(line[1])
            end = int(line[2])
            easing_type = EasingType(int(line[3]))
            growths[level] = CastleGrowth(level, start, end, easing_type)

        return CastleGrowths(growths)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        file_name = CastleGrowths.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        remaining_levels = set(self.growths.keys())
        for i, line in enumerate(csv.lines[1:]):
            level = int(line[0])
            if level in self.growths:
                growth = self.growths[level]
                line[1] = str(growth.start)
                line[2] = str(growth.end)
                line[3] = str(growth.easing_type.value)
                csv.lines[i + 1] = line
                remaining_levels.remove(level)

        for level in remaining_levels:
            growth = self.growths[level]
            line = [
                str(growth.level),
                str(growth.start),
                str(growth.end),
                str(growth.easing_type.value),
            ]
            csv.lines.append(line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CastleGrowths":
        return CastleGrowths({})


class CannonEffectType(enum.Enum):
    STRENGTH = 0
    SLOW_FRAME = 1
    FREEZE_FRAME = 2
    WALL_HP = 3
    WALL_LIFE_TIME = 4
    THUNDER_RANGE = 5
    WALL_OFFSET_X = 6
    METAL_DAMAGE_1 = 7
    METAL_DAMAGE_2 = 8
    HOLY_BLAST_PERCENTAGE_SURFACE = 9
    HOLY_BLAST_PERCENTAGE_BURROW = 10
    UNKNOWN_HOLY_BLAST = 11
    CURSE_FRAME = 12


class CannonEffect:
    def __init__(
        self,
        castle_type: int,
        effect_type: CannonEffectType,
        level: int,
        start: int,
        end: int,
        easing_type: EasingType,
    ):
        self.castle_type = castle_type
        self.effect_type = effect_type
        self.level = level
        self.start = start
        self.end = end
        self.easing_type = easing_type


class CannonEffects:
    def __init__(self, effects: dict[int, dict[int, CannonEffect]]):
        self.effects = effects

    @staticmethod
    def get_file_name() -> str:
        return "CC_AllParts_growth.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CannonEffects":
        file_name = CannonEffects.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return CannonEffects.create_empty()

        csv = io.bc_csv.CSV(file.dec_data)
        effects: dict[int, dict[int, CannonEffect]] = {}
        for line in csv.lines[1:]:
            castle_type = int(line[0])
            effect_type = CannonEffectType(int(line[1]))
            level = int(line[2])
            start = int(line[3])
            end = int(line[4])
            easing_type = EasingType(int(line[5]))
            if castle_type not in effects:
                effects[castle_type] = {}
            effects[castle_type][level] = CannonEffect(
                castle_type, effect_type, level, start, end, easing_type
            )

        return CannonEffects(effects)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        file_name = CannonEffects.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return None

        csv = io.bc_csv.CSV(file.dec_data)
        remaining_effects = self.effects.copy()
        for i, line in enumerate(csv.lines[1:]):
            castle_type = int(line[0])
            level = int(line[2])
            if castle_type in self.effects and level in self.effects[castle_type]:
                effect = self.effects[castle_type][level]
                line[1] = str(effect.effect_type.value)
                line[3] = str(effect.start)
                line[4] = str(effect.end)
                line[5] = str(effect.easing_type.value)
                csv.lines[i + 1] = line
                del remaining_effects[castle_type][level]
                if len(remaining_effects[castle_type]) == 0:
                    del remaining_effects[castle_type]

        for castle_type, levels in remaining_effects.items():
            for level, effect in levels.items():
                csv.lines.append(
                    [
                        str(castle_type),
                        str(effect.effect_type.value),
                        str(level),
                        str(effect.start),
                        str(effect.end),
                        str(effect.easing_type.value),
                    ]
                )

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CannonEffects":
        return CannonEffects({})


class Part(enum.Enum):
    FOUNDATION = 0
    STYLE = 1
    CANNON = 2


class Cannon:
    def __init__(
        self,
        castle_type: int,
        status: CannonStatus,
        effects: dict[int, "CannonEffect"],
        recipe: "castle_recipe.CastleRecipe",
        parts_models: dict[Part, dict[int, "anim.model.Model"]],
        parts_texture: dict[Part, "anim.texture.Texture"],
    ):
        self.castle_type = castle_type
        self.status = status
        self.effects = effects
        self.recipe = recipe
        self.parts_models = parts_models
        self.parts_texture = parts_texture

    @staticmethod
    def parts_models_from_game_data(
        game_data: "pack.GamePacks",
        castle_type: int,
    ) -> tuple[
        dict[Part, dict[int, "anim.model.Model"]], dict[Part, "anim.texture.Texture"]
    ]:
        models: dict[Part, dict[int, "anim.model.Model"]] = {}
        textures: dict[Part, "anim.texture.Texture"] = {}
        for part in Part:
            png_name = f"nyankoCastle_{io.data.PaddedInt(part.value, 3)}_{io.data.PaddedInt(castle_type, 2)}.png"
            imgcut_name = png_name.replace(".png", ".imgcut")
            tex = anim.texture.Texture.load(png_name, imgcut_name, game_data)
            textures[part] = tex

            png_name_2 = f"nyankoCastle_{io.data.PaddedInt(part.value, 3)}_{io.data.PaddedInt(castle_type, 2)}_00.png"
            imgcut_name_2 = png_name_2.replace(".png", ".imgcut")

            mamodel_name = png_name_2.replace(".png", ".mamodel")

            maanim_name = png_name_2.replace(".png", ".maanim")

            models[part] = {}
            models[part][0] = anim.model.Model.load(
                mamodel_name, imgcut_name_2, png_name_2, [maanim_name], game_data
            )

            png_name_3 = f"nyankoCastle_{io.data.PaddedInt(part.value, 3)}_{io.data.PaddedInt(castle_type, 2)}_01.png"

            mamodel_name_2 = png_name_3.replace(".png", ".mamodel")

            maanim_name_2 = png_name_3.replace(".png", ".maanim")

            model = None
            try:
                model = anim.model.Model.load(
                    mamodel_name_2,
                    imgcut_name_2,
                    png_name_2,
                    [maanim_name_2],
                    game_data,
                )
            except ValueError:
                pass

            if model is None:
                models[part] = {
                    0: anim.model.Model.load(
                        mamodel_name_2,
                        imgcut_name_2,
                        png_name_2,
                        [maanim_name],
                        game_data,
                    )
                }
                continue

            models[part][1] = model

        return models, textures

    def parts_anims_to_game_data(
        self,
        game_data: "pack.GamePacks",
    ):
        for part in Part:
            self.parts_texture[part].save(game_data)
            self.parts_models[part][0].save(game_data)

            if len(self.parts_models[part]) == 1:
                self.parts_models[part][0].save(
                    game_data,
                )
                continue

            self.parts_models[part][1].save(
                game_data,
            )


class Cannons:
    def __init__(
        self,
        cannons: dict[int, Cannon],
        map_png: "io.bc_image.BCImage",
        silhouette_tex: "anim.texture.Texture",
    ):
        self.cannons = cannons
        self.map_png = map_png
        self.silhouette_tex = silhouette_tex

    def get_cannon(self) -> Optional[Cannon]:
        cannon_lst = list(self.cannons.values())
        try:
            return cannon_lst[0]
        except IndexError:
            return None

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Cannons":
        effects = CannonEffects.from_game_data(game_data)
        statuses = CannonStatuses.from_game_data(game_data)
        recipies = castle_recipe.CastleRecipies.from_game_data(game_data)
        map_png = game_data.find_file(Cannons.get_map_png_file_name())
        map_png_data = map_png.dec_data if map_png else io.data.Data()
        imgcut = anim.texture.Texture.load(
            Cannons.get_silhouette_file_name(),
            Cannons.get_silhouette_file_name().replace(".png", ".imgcut"),
            game_data,
        )

        cannons: dict[int, Cannon] = {}
        castle_type = 0
        while True:
            anims, imgcuts = Cannon.parts_models_from_game_data(game_data, castle_type)
            cannons[castle_type] = Cannon(
                castle_type,
                statuses.statuses[castle_type],
                effects.effects[castle_type],
                recipies.recipies[castle_type],
                anims,
                imgcuts,
            )
            castle_type += 1
        return Cannons(cannons, io.bc_image.BCImage(map_png_data), imgcut)

    @staticmethod
    def get_map_png_file_name() -> str:
        return "castleCustom_map_00.png"

    @staticmethod
    def get_silhouette_file_name() -> str:
        return "CastleCustom_000.png"

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        effects = CannonEffects({k: v.effects for k, v in self.cannons.items()})
        effects.to_game_data(game_data)
        statuses = CannonStatuses({k: v.status for k, v in self.cannons.items()})
        statuses.to_game_data(game_data)
        recipies = castle_recipe.CastleRecipies(
            {k: v.recipe for k, v in self.cannons.items()}
        )
        recipies.to_game_data(game_data)
        if not self.map_png.is_empty():
            game_data.set_file(Cannons.get_map_png_file_name(), self.map_png.to_data())
        if not self.silhouette_tex.is_empty():
            self.silhouette_tex.save(
                game_data,
            )
        for cannon in self.cannons.values():
            cannon.parts_anims_to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Cannons":
        return Cannons(
            {}, io.bc_image.BCImage.create_empty(), anim.texture.Texture.create_empty()
        )

    def set_cannon(self, cannon: Cannon) -> None:
        self.cannons[cannon.castle_type] = cannon

    def get_cannon_types(self) -> list[int]:
        return list(self.cannons.keys())
