from tbcml.core.game_data.gamototo import cannon, engineers, item_pack, ototo_anim
from tbcml.core.game_data import pack


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

    @staticmethod
    def create_empty() -> "Ototo":
        return Ototo(
            engineers.Engineer.create_empty(),
            cannon.Cannons.create_empty(),
            item_pack.ItemPacks.create_empty(),
            ototo_anim.MainChara.create_empty(),
        )
