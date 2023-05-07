from tbcml.core.game_data import pack
from tbcml.core.game_data.gamototo import ototo


class Gamototo:
    def __init__(self, ot: "ototo.Ototo"):
        self.ototo = ot

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Gamototo":
        ot = ototo.Ototo.from_game_data(game_data)
        return Gamototo(
            ot,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.ototo.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Gamototo":
        return Gamototo(
            ototo.Ototo.create_empty(),
        )
