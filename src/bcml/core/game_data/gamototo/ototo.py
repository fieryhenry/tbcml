from typing import Any
from bcml.core.game_data.gamototo import cannon, engineers, item_pack, ototo_anim
from bcml.core.game_data import pack
from bcml.core import io


class Ototo:
    def __init__(
        self,
        engineer: "engineers.Engineer",
        cannons: "cannon.Cannons",
        item_packs: "item_pack.ItemPacks",
        main_chara_anim: "ototo_anim.MainChara",
    ):
        self.engineer = engineer
        self.cannons = cannons
        self.item_packs = item_packs
        self.main_chara_anim = main_chara_anim

    def serialize(self) -> dict[str, Any]:
        return {
            "engineer": self.engineer.serialize(),
            "cannons": self.cannons.serialize(),
            "item_packs": self.item_packs.serialize(),
            "main_chara_anim": self.main_chara_anim.serialize(),
        }

    @staticmethod
    def deserialize(
        data: dict[str, Any],
    ) -> "Ototo":
        return Ototo(
            engineers.Engineer.deserialize(data["engineer"]),
            cannon.Cannons.deserialize(data["cannons"]),
            item_pack.ItemPacks.deserialize(data["item_packs"]),
            ototo_anim.MainChara.deserialize(data["main_chara_anim"]),
        )

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Ototo":
        engineer = engineers.Engineer.from_game_data(game_data)
        cannons = cannon.Cannons.from_game_data(game_data)
        item_packs = item_pack.ItemPacks.from_game_data(game_data)
        main_chara_anim = ototo_anim.MainChara.from_game_data(game_data)
        return Ototo(
            engineer,
            cannons,
            item_packs,
            main_chara_anim,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.engineer.to_game_data(game_data)
        self.cannons.to_game_data(game_data)
        self.item_packs.to_game_data(game_data)
        self.main_chara_anim.to_game_data(game_data)

    def add_to_zip(self, zip: "io.zip.Zip"):
        self.engineer.add_to_zip(zip)
        self.cannons.add_to_zip(zip)
        self.item_packs.add_to_zip(zip)
        self.main_chara_anim.to_zip(zip)

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Ototo":
        engineer = engineers.Engineer.from_zip(zip)
        cannons = cannon.Cannons.from_zip(zip)
        item_packs = item_pack.ItemPacks.from_zip(zip)
        main_chara_anim = ototo_anim.MainChara.from_zip(zip)
        return Ototo(
            engineer,
            cannons,
            item_packs,
            main_chara_anim,
        )

    @staticmethod
    def create_empty() -> "Ototo":
        return Ototo(
            engineers.Engineer.create_empty(),
            cannon.Cannons.create_empty(),
            item_pack.ItemPacks.create_empty(),
            ototo_anim.MainChara.create_empty(),
        )

    def import_ototo(self, other: "Ototo", game_data: "pack.GamePacks"):
        self.engineer.import_engineer(other.engineer, game_data)
        self.cannons.import_cannons(other.cannons, game_data)
        self.item_packs.import_item_packs(other.item_packs, game_data)
        self.main_chara_anim.import_main_chara(other.main_chara_anim, game_data)
