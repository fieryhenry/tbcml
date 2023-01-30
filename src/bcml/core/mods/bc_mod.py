from typing import Any, Optional
import zipfile
from bcml.core import io, game_version, country_code, crypto, game_data, mods


class Mod:
    def __init__(
        self,
        name: str,
        author: str,
        descritpion: str,
        country_code: "country_code.CountryCode",
        game_version: "game_version.GameVersion",
        mod_id: str,
        mod_version: str,
        mod_url: Optional[str] = None,
    ):
        self.name = name
        self.author = author
        self.description = descritpion
        self.country_code = country_code
        self.game_version = game_version
        self.mod_id = mod_id
        self.mod_version = mod_version
        self.mod_url = mod_url
        self.init_custom()
        self.init_scripts()

    @staticmethod
    def get_extension() -> str:
        return ".bcmod"

    def get_full_mod_name(self) -> str:
        return f"{self.name}-{self.author}-{self.mod_id}{self.get_extension()}"

    def get_file_name(self) -> str:
        return f"{self.mod_id}{self.get_extension()}"

    def init_custom(self):
        self.gamototo = game_data.gamototo.gamototo.Gamototo.create_empty()
        self.battle = game_data.battle.battle.Battle.create_empty()
        self.cat_base = game_data.cat_base.cat_base.CatBase.create_empty()
        self.maps = game_data.map.map.Maps.create_empty()

    def init_scripts(self):
        self.scripts: mods.frida_script.Scripts = mods.frida_script.Scripts(
            [], self.country_code, self.game_version
        )

    def create_mod_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "country_code": self.country_code.value,
            "game_version": self.game_version.to_string(),
            "mod_id": self.mod_id,
            "mod_version": self.mod_version,
            "mod_url": self.mod_url,
        }

    def save(self, path: "io.path.Path"):
        data = self.to_data()
        path.write(data)

    def to_data(self):
        zip_file = io.zip.Zip()

        self.gamototo.add_to_zip(zip_file)
        self.battle.add_to_zip(zip_file)
        self.cat_base.add_to_zip(zip_file)
        self.maps.add_to_zip(zip_file)

        self.scripts.add_to_zip(zip_file)

        json = io.json_file.JsonFile.from_json(self.create_mod_json())
        zip_file.add_file(io.path.Path("mod.json"), json.to_data())
        return zip_file.to_data()

    @staticmethod
    def load(path: "io.path.Path") -> Optional["Mod"]:
        try:
            zip_file = io.zip.Zip.from_file(path)
        except zipfile.BadZipFile:
            return None
        json_file = zip_file.get_file(io.path.Path("mod.json"))
        if json_file is None:
            return None
        json = io.json_file.JsonFile.from_data(json_file)
        mod = Mod.from_mod_json(json.get_json())

        mod.gamototo = game_data.gamototo.gamototo.Gamototo.from_zip(zip_file)
        mod.battle = game_data.battle.battle.Battle.from_zip(zip_file)
        mod.cat_base = game_data.cat_base.cat_base.CatBase.from_zip(zip_file)
        mod.maps = game_data.map.map.Maps.from_zip(zip_file)

        mod.scripts = mods.frida_script.Scripts.from_zip(
            zip_file, mod.country_code, mod.game_version
        )

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
            data["mod_version"],
            data["mod_url"],
        )

    @staticmethod
    def create_mod_id() -> str:
        return crypto.Random.get_alpha_string(8)

    def import_mod(self, other: "Mod"):
        self.gamototo.import_gamototo(other.gamototo)
        self.battle.import_battle(other.battle)
        self.cat_base.import_cat_base(other.cat_base)
        self.maps.import_maps(other.maps)

        self.scripts.import_scripts(other.scripts)

    def import_mods(self, others: list["Mod"]):
        for other in others:
            self.import_mod(other)

    def get_hash(self) -> str:
        return (
            crypto.Hash(crypto.HashAlgorithm.SHA256, self.to_data()).get_hash().to_hex()
        )
