from typing import Any, Optional
from bcml.core.game_data.cat_base import (
    cats,
    enemies,
    gatya,
    item_shop,
    nekokan_product,
    scheme_item,
    user_rank_reward,
    gatya_item,
)
from bcml.core.game_data import pack
from bcml.core import io


class CatBase:
    def __init__(
        self,
        cats: "cats.Cats",
        enemies: "enemies.Enemies",
        gatya: "gatya.Gatya",
        item_shop: "item_shop.ItemShop",
        nekokan_product: "nekokan_product.NekokanProducts",
        scheme_items: "scheme_item.SchemeItems",
        user_rank_rewards: "user_rank_reward.UserRankReward",
        gatya_items: "gatya_item.GatyaItems",
    ):
        self.cats = cats
        self.enemies = enemies
        self.gatya = gatya
        self.item_shop = item_shop
        self.nekokan_product = nekokan_product
        self.scheme_items = scheme_items
        self.user_rank_rewards = user_rank_rewards
        self.gatya_items = gatya_items

    def serialize(self) -> dict[str, Any]:
        return {
            "cats": self.cats.serialize(),
            "enemies": self.enemies.serialize(),
            "gatya": self.gatya.serialize(),
            "item_shop": self.item_shop.serialize(),
            "nekokan_product": self.nekokan_product.serialize(),
            "scheme_items": self.scheme_items.serialize(),
            "user_rank_rewards": self.user_rank_rewards.serialize(),
            "gatya_items": self.gatya_items.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CatBase":
        return CatBase(
            cats.Cats.deserialize(data["cats"]),
            enemies.Enemies.deserialize(data["enemies"]),
            gatya.Gatya.deserialize(data["gatya"]),
            item_shop.ItemShop.deserialize(data["item_shop"]),
            nekokan_product.NekokanProducts.deserialize(data["nekokan_product"]),
            scheme_item.SchemeItems.deserialize(data["scheme_items"]),
            user_rank_reward.UserRankReward.deserialize(data["user_rank_rewards"]),
            gatya_item.GatyaItems.deserialize(data["gatya_items"]),
        )

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["CatBase"]:
        cts = cats.Cats.from_game_data(game_data)
        enem = enemies.Enemies.from_game_data(game_data)
        gt = gatya.Gatya.from_game_data(game_data)
        itms = item_shop.ItemShop.from_game_data(game_data)
        np = nekokan_product.NekokanProducts.from_game_data(game_data)
        sch = scheme_item.SchemeItems.from_game_data(game_data)
        urr = user_rank_reward.UserRankReward.from_game_data(game_data)
        gtya = gatya_item.GatyaItems.from_game_data(game_data)
        if (
            cts is None
            or enem is None
            or gt is None
            or itms is None
            or np is None
            or sch is None
            or urr is None
            or gtya is None
        ):
            return None
        return CatBase(
            cts,
            enem,
            gt,
            itms,
            np,
            sch,
            urr,
            gtya,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.cats.to_game_data(game_data)
        self.enemies.to_game_data(game_data)
        self.gatya.to_game_data(game_data)
        self.item_shop.to_game_data(game_data)
        self.nekokan_product.to_game_data(game_data)
        self.scheme_items.to_game_data(game_data)
        self.user_rank_rewards.to_game_data(game_data)
        self.gatya_items.to_game_data(game_data)

    def add_to_zip(self, zip: "io.zip.Zip"):
        self.cats.add_to_zip(zip)
        self.enemies.add_to_zip(zip)
        self.gatya.add_to_zip(zip)
        self.item_shop.add_to_zip(zip)
        self.nekokan_product.add_to_zip(zip)
        self.scheme_items.add_to_zip(zip)
        self.user_rank_rewards.add_to_zip(zip)
        self.gatya_items.add_to_zip(zip)

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "CatBase":
        cts = cats.Cats.from_zip(zip)
        enem = enemies.Enemies.from_zip(zip)
        gt = gatya.Gatya.from_zip(zip)
        itms = item_shop.ItemShop.from_zip(zip)
        np = nekokan_product.NekokanProducts.from_zip(zip)
        sch = scheme_item.SchemeItems.from_zip(zip)
        urr = user_rank_reward.UserRankReward.from_zip(zip)
        gtya = gatya_item.GatyaItems.from_zip(zip)
        return CatBase(
            cts,
            enem,
            gt,
            itms,
            np,
            sch,
            urr,
            gtya,
        )

    @staticmethod
    def create_empty() -> "CatBase":
        return CatBase(
            cats.Cats.create_empty(),
            enemies.Enemies.create_empty(),
            gatya.Gatya.create_empty(),
            item_shop.ItemShop.create_empty(),
            nekokan_product.NekokanProducts.create_empty(),
            scheme_item.SchemeItems.create_empty(),
            user_rank_reward.UserRankReward.create_empty(),
            gatya_item.GatyaItems.create_empty(),
        )

    def import_cat_base(self, other: "CatBase"):
        self.cats.import_cats(other.cats)
        self.enemies.import_enemies(other.enemies)
        self.gatya.import_gatya(other.gatya)
        self.item_shop.import_item_shop(other.item_shop)
        self.nekokan_product.import_nekokan(other.nekokan_product)
        self.scheme_items.import_scheme_items(other.scheme_items)
        self.user_rank_rewards.import_user_rank_rewards(other.user_rank_rewards)
        self.gatya_items.import_items(other.gatya_items)
