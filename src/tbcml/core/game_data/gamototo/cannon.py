import enum
from typing import Any, Optional
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

    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "wave": self.wave,
            "option": self.option,
            "knockback": self.knockback,
            "mark": self.mark,
            "unknown": self.unknown,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CannonStatus":
        return CannonStatus(
            id=data["id"],
            type=data["type"],
            wave=data["wave"],
            option=data["option"],
            knockback=data["knockback"],
            mark=data["mark"],
            unknown=data["unknown"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CannonStatus):
            return False
        return (
            self.id == other.id
            and self.type == other.type
            and self.wave == other.wave
            and self.option == other.option
            and self.knockback == other.knockback
            and self.mark == other.mark
            and self.unknown == other.unknown
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class CannonStatuses:
    def __init__(self, statuses: dict[int, CannonStatus]):
        self.statuses = statuses

    def serialize(self) -> dict[str, dict[str, Any]]:
        return {"statuses": {str(k): v.serialize() for k, v in self.statuses.items()}}

    @staticmethod
    def deserialize(data: dict[str, dict[str, Any]]) -> "CannonStatuses":
        return CannonStatuses(
            statuses={
                int(k): CannonStatus.deserialize(v) for k, v in data["statuses"].items()
            }
        )

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
            id = line[0].to_int()
            type = line[1].to_int()
            wave = line[2].to_bool()
            option = line[3].to_int()
            knockback = line[4].to_bool()
            mark = line[5].to_bool()
            unknown = line[6].to_bool()
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
            id = line[0].to_int()
            if id in self.statuses:
                status = self.statuses[id]
                line[1].set(status.type)
                line[2].set(status.wave)
                line[3].set(status.option)
                line[4].set(status.knockback)
                line[5].set(status.mark)
                line[6].set(status.unknown)
                csv.set_line(i + 1, line)
                remaining_statuses.remove(id)

        for id in remaining_statuses:
            status = self.statuses[id]
            line = [
                status.id,
                status.type,
                status.wave,
                status.option,
                status.knockback,
                status.mark,
                status.unknown,
            ]
            csv.add_line(line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CannonStatuses":
        return CannonStatuses({})

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, CannonStatuses):
            return False
        return self.statuses == __o.statuses

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)


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

    def serialize(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "start": self.start,
            "end": self.end,
            "easing_type": self.easing_type.value,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CastleGrowth":
        return CastleGrowth(
            level=data["level"],
            start=data["start"],
            end=data["end"],
            easing_type=EasingType(data["easing_type"]),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CastleGrowth):
            return False
        return (
            self.level == other.level
            and self.start == other.start
            and self.end == other.end
            and self.easing_type == other.easing_type
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class CastleGrowths:
    def __init__(self, growths: dict[int, CastleGrowth]):
        self.growths = growths

    def serialize(self) -> dict[str, dict[str, Any]]:
        return {"growths": {str(k): v.serialize() for k, v in self.growths.items()}}

    @staticmethod
    def deserialize(data: dict[str, dict[str, Any]]) -> "CastleGrowths":
        return CastleGrowths(
            growths={
                int(k): CastleGrowth.deserialize(v) for k, v in data["growths"].items()
            }
        )

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
            level = line[0].to_int()
            start = line[1].to_int()
            end = line[2].to_int()
            easing_type = EasingType(line[3].to_int())
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
            level = line[0].to_int()
            if level in self.growths:
                growth = self.growths[level]
                line[1].set(growth.start)
                line[2].set(growth.end)
                line[3].set(growth.easing_type.value)
                csv.set_line(i + 1, line)
                remaining_levels.remove(level)

        for level in remaining_levels:
            growth = self.growths[level]
            line = [growth.level, growth.start, growth.end, growth.easing_type.value]
            csv.add_line(line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CastleGrowths":
        return CastleGrowths({})

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, CastleGrowths):
            return False
        return self.growths == __o.growths

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)


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

    def serialize(self) -> dict[str, Any]:
        return {
            "castle_type": self.castle_type,
            "effect_type": self.effect_type.value,
            "level": self.level,
            "start": self.start,
            "end": self.end,
            "easing_type": self.easing_type.value,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CannonEffect":
        return CannonEffect(
            castle_type=data["castle_type"],
            effect_type=CannonEffectType(data["effect_type"]),
            level=data["level"],
            start=data["start"],
            end=data["end"],
            easing_type=EasingType(data["easing_type"]),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CannonEffect):
            return False
        return (
            self.castle_type == other.castle_type
            and self.effect_type == other.effect_type
            and self.level == other.level
            and self.start == other.start
            and self.end == other.end
            and self.easing_type == other.easing_type
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class CannonEffects:
    def __init__(self, effects: dict[int, dict[int, CannonEffect]]):
        self.effects = effects

    def serialize(self) -> dict[str, dict[str, dict[str, Any]]]:
        return {
            "effects": {
                str(k): {str(k2): v2.serialize() for k2, v2 in v.items()}
                for k, v in self.effects.items()
            }
        }

    @staticmethod
    def deserialize(data: dict[str, dict[str, dict[str, Any]]]) -> "CannonEffects":
        return CannonEffects(
            effects={
                int(k): {int(k2): CannonEffect.deserialize(v2) for k2, v2 in v.items()}
                for k, v in data["effects"].items()
            }
        )

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
            castle_type = line[0].to_int()
            effect_type = CannonEffectType(line[1].to_int())
            level = line[2].to_int()
            start = line[3].to_int()
            end = line[4].to_int()
            easing_type = EasingType(line[5].to_int())
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
            castle_type = line[0].to_int()
            level = line[2].to_int()
            if castle_type in self.effects and level in self.effects[castle_type]:
                effect = self.effects[castle_type][level]
                line[1].set(effect.effect_type.value)
                line[3].set(effect.start)
                line[4].set(effect.end)
                line[5].set(effect.easing_type.value)
                csv.set_line(i + 1, line)
                del remaining_effects[castle_type][level]
                if len(remaining_effects[castle_type]) == 0:
                    del remaining_effects[castle_type]

        for castle_type, levels in remaining_effects.items():
            for level, effect in levels.items():
                csv.add_line(
                    [
                        castle_type,
                        effect.effect_type.value,
                        level,
                        effect.start,
                        effect.end,
                        effect.easing_type.value,
                    ]
                )

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CannonEffects":
        return CannonEffects({})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CannonEffects):
            return False
        return self.effects == other.effects

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


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

    def serialize(self) -> dict[str, Any]:
        return {
            "castle_type": self.castle_type,
            "status": self.status.serialize(),
            "effect": {str(k): v.serialize() for k, v in self.effects.items()},
            "recipe": self.recipe.serialize(),
            "parts_models": {
                str(k): {str(k2): v2.serialize() for k2, v2 in v.items()}
                for k, v in self.parts_models.items()
            },
            "parts_texture": {
                str(k): v.serialize() for k, v in self.parts_texture.items()
            },
        }

    @staticmethod
    def deserialize(
        data: dict[str, Any],
    ) -> "Cannon":
        return Cannon(
            castle_type=data["castle_type"],
            status=CannonStatus.deserialize(data["status"]),
            effects={
                int(k): CannonEffect.deserialize(v) for k, v in data["effect"].items()
            },
            recipe=castle_recipe.CastleRecipe.deserialize(data["recipe"]),
            parts_models={
                Part(int(k)): {
                    int(k2): anim.model.Model.deserialize(v2) for k2, v2 in v.items()
                }
                for k, v in data["parts_models"].items()
            },
            parts_texture={
                Part(int(k)): anim.texture.Texture.deserialize(v)
                for k, v in data["parts_texture"].items()
            },
        )

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

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, Cannon):
            return False
        return (
            self.castle_type == __o.castle_type
            and self.parts_texture == __o.parts_texture
            and self.parts_models == __o.parts_models
        )

    def __ne__(self, __o: object) -> bool:
        return not self == __o


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

    def serialize(self) -> dict[str, dict[str, Any]]:
        return {
            "cannons": {str(k): v.serialize() for k, v in self.cannons.items()},
            "map_png": self.map_png.serialize(),
            "silhouette_tex": self.silhouette_tex.serialize(),
        }

    @staticmethod
    def deserialize(
        data: dict[str, dict[str, Any]],
    ) -> "Cannons":
        return Cannons(
            cannons={int(k): Cannon.deserialize(v) for k, v in data["cannons"].items()},
            map_png=io.bc_image.BCImage.deserialize(data["map_png"]),
            silhouette_tex=anim.texture.Texture.deserialize(data["silhouette_tex"]),
        )

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
    def get_zip_folder() -> "io.path.Path":
        return io.path.Path("gamototo").add("ototo")

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        return Cannons.get_zip_folder().add("cannons.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_object(self.serialize())
        zip.add_file(Cannons.get_zip_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Cannons":
        file = zip.get_file(Cannons.get_zip_json_file_path())
        if file is None:
            return Cannons.create_empty()
        json = io.json_file.JsonFile.from_data(file)

        return Cannons.deserialize(json.json)

    @staticmethod
    def create_empty() -> "Cannons":
        return Cannons(
            {}, io.bc_image.BCImage.create_empty(), anim.texture.Texture.create_empty()
        )

    def set_cannon(self, cannon: Cannon) -> None:
        self.cannons[cannon.castle_type] = cannon

    def import_cannons(self, cannons: "Cannons", game_data: "pack.GamePacks") -> None:
        """_summary_

        Args:
            cannons (Cannons): _description_
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_cannons = Cannons.from_game_data(game_data)
        all_keys = set(self.cannons.keys())
        all_keys.update(cannons.cannons.keys())
        for castle_type in all_keys:
            gd_cannon = gd_cannons.cannons.get(castle_type)
            other_cannon = cannons.cannons.get(castle_type)
            if other_cannon is None:
                continue
            if gd_cannon is not None:
                if gd_cannon != other_cannon:
                    self.cannons[castle_type] = other_cannon
            else:
                self.cannons[castle_type] = other_cannon

        other_map_png = cannons.map_png
        gd_map_png = gd_cannons.map_png
        if gd_map_png != other_map_png:
            self.map_png = other_map_png

        other_silhouette_imgcut = cannons.silhouette_tex
        gd_silhouette_imgcut = gd_cannons.silhouette_tex
        if gd_silhouette_imgcut != other_silhouette_imgcut:
            self.silhouette_tex = other_silhouette_imgcut

    def get_cannon_types(self) -> list[int]:
        return list(self.cannons.keys())
