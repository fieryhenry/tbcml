from bcml.core.game_data import pack
from bcml.core import io
from typing import Any, Optional
from bcml.core.game_data.gamototo import ototo


class Gamototo:
    def __init__(self, ot: "ototo.Ototo"):
        self.ototo = ot

    def serialize(self) -> dict[str, Any]:
        return {
            "ototo": self.ototo.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Gamototo":
        return Gamototo(ototo.Ototo.deserialize(data["ototo"]))

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["Gamototo"]:
        ot = ototo.Ototo.from_game_data(game_data)
        if ot is None:
            return None
        return Gamototo(
            ot,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.ototo.to_game_data(game_data)

    def add_to_zip(self, zip: "io.zip.Zip"):
        self.ototo.add_to_zip(zip)

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Gamototo":
        ot = ototo.Ototo.from_zip(zip)
        return Gamototo(
            ot,
        )

    @staticmethod
    def create_empty() -> "Gamototo":
        return Gamototo(
            ototo.Ototo.create_empty(),
        )

    def import_gamototo(self, other: "Gamototo"):
        self.ototo.import_ototo(other.ototo)
