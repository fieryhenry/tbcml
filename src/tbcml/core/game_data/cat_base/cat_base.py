from tbcml.core.game_data.cat_base import (
    cats,
    enemies,
    gatya,
    item_shop,
    scheme_item,
    user_rank_reward,
    gatya_item,
)
from tbcml.core.game_data import pack


class CatBase:
    """Represents the CatBase object."""

    def __init__(
        self,
        cats: "cats.Cats",
        enemies: "enemies.Enemies",
        gatya: "gatya.Gatya",
        item_shop: "item_shop.ItemShop",
        scheme_items: "scheme_item.SchemeItems",
        user_rank_rewards: "user_rank_reward.UserRankReward",
        gatya_items: "gatya_item.GatyaItems",
    ):
        """Initialize a new CatBase.

        Args:
            cats (cats.Cats): Cat data.
            enemies (enemies.Enemies): Enemy data.
            gatya (gatya.Gatya): Gatya data.
            item_shop (item_shop.ItemShop): Item shop data.
            scheme_items (scheme_item.SchemeItems): Scheme item data.
            user_rank_rewards (user_rank_reward.UserRankReward): User rank reward data.
            gatya_items (gatya_item.GatyaItems): Gatya item data.
        """
        self.cats = cats
        self.enemies = enemies
        self.gatya = gatya
        self.item_shop = item_shop
        self.scheme_items = scheme_items
        self.user_rank_rewards = user_rank_rewards
        self.gatya_items = gatya_items

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CatBase":
        """Create a CatBase object from a GamePacks object.

        Args:
            game_data (pack.GamePacks): The GamePacks object to create the CatBase object from.

        Returns:
            CatBase: The CatBase object.
        """
        cts = cats.Cats.from_game_data(game_data)
        enem = enemies.Enemies.from_game_data(game_data)
        gt = gatya.Gatya.from_game_data(game_data)
        itms = item_shop.ItemShop.from_game_data(game_data)
        sch = scheme_item.SchemeItems.from_game_data(game_data)
        urr = user_rank_reward.UserRankReward.from_game_data(game_data)
        gtya = gatya_item.GatyaItems.from_game_data(game_data)
        return CatBase(
            cts,
            enem,
            gt,
            itms,
            sch,
            urr,
            gtya,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        """Write the CatBase object to a GamePacks object.

        Args:
            game_data (pack.GamePacks): The GamePacks object to write to.
        """
        self.cats.to_game_data(game_data)
        self.enemies.to_game_data(game_data)
        self.gatya.to_game_data(game_data)
        self.item_shop.to_game_data(game_data)
        self.scheme_items.to_game_data(game_data)
        self.user_rank_rewards.to_game_data(game_data)
        self.gatya_items.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "CatBase":
        """Create an empty CatBase object.

        Returns:
            CatBase: The empty CatBase object.
        """
        return CatBase(
            cats.Cats.create_empty(),
            enemies.Enemies.create_empty(),
            gatya.Gatya.create_empty(),
            item_shop.ItemShop.create_empty(),
            scheme_item.SchemeItems.create_empty(),
            user_rank_reward.UserRankReward.create_empty(),
            gatya_item.GatyaItems.create_empty(),
        )
