from typing import Any, Optional
from bcml.core import io, game_version, country_code, crypto, game_data


class Mod:
    def __init__(
        self,
        name: str,
        author: str,
        descritpion: str,
        country_code: "country_code.CountryCode",
        game_version: "game_version.GameVersion",
        mod_id: str,
    ):
        self.name = name
        self.author = author
        self.description = descritpion
        self.country_code = country_code
        self.game_version = game_version
        self.mod_id = mod_id
        self.init_custom()
    
    @staticmethod
    def get_extension() -> str:
        return ".bcmod"

    def get_full_mod_name(self) -> str:
        return f"{self.name}-{self.author}-{self.mod_id}{self.get_extension()}"
    
    def init_custom(self):
        self.gamototo = game_data.gamototo.gamototo.Gamototo.create_empty()
        self.battle = game_data.battle.battle.Battle.create_empty()
        self.cat_base = game_data.cat_base.cat_base.CatBase.create_empty()
        self.maps = game_data.map.map.Maps.create_empty()
    
    def create_mod_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "country_code": self.country_code.value,
            "game_version": self.game_version.to_string(),
            "mod_id": self.mod_id,
        }
    
    def save(self, path: "io.path.Path"):
        zip_file = io.zip.Zip()

        self.gamototo.add_to_zip(zip_file)
        self.battle.add_to_zip(zip_file)
        self.cat_base.add_to_zip(zip_file)
        self.maps.add_to_zip(zip_file)

        json = io.json_file.JsonFile.from_json(self.create_mod_json())
        zip_file.add_file(io.path.Path("mod.json"), json.to_data())
        zip_file.save(path)
    
    @staticmethod
    def load(path: "io.path.Path") -> Optional["Mod"]:
        zip_file = io.zip.Zip.from_file(path)
        json_file = zip_file.get_file(io.path.Path("mod.json"))
        if json_file is None:
            return None
        json = io.json_file.JsonFile.from_data(json_file)
        mod = Mod.from_mod_json(json.get_json())

        mod.gamototo = game_data.gamototo.gamototo.Gamototo.from_zip(zip_file)
        mod.battle = game_data.battle.battle.Battle.from_zip(zip_file)
        mod.cat_base = game_data.cat_base.cat_base.CatBase.from_zip(zip_file)
        mod.maps = game_data.map.map.Maps.from_zip(zip_file)

        return mod
    
    @staticmethod
    def from_mod_json(data: dict[str, Any]) -> "Mod":
        return Mod(
            data["name"],
            data["author"],
            data["description"],
            country_code.CountryCode(data["country_code"]),
            game_version.GameVersion.from_string(data["game_version"]),
            data["mod_id"],
        )    

    @staticmethod
    def create_mod_id() -> str:
        return crypto.Random.get_alpha_string(8)
    
    def import_mod(self, other: "Mod"):
        self.gamototo.import_gamototo(other.gamototo)
        self.battle.import_battle(other.battle)
        self.cat_base.import_cat_base(other.cat_base)
        self.maps.import_maps(other.maps)
    
    def import_mods(self, others: list["Mod"]):
        for other in others:
            self.import_mod(other)