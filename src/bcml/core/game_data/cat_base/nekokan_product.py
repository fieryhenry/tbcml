from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class Product:
    def __init__(self, product_id: str, index: int, cf_amount: int, comment: str):
        self.product_id = product_id
        self.index = index
        self.cf_amount = cf_amount
        self.comment = comment

    def serialize(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "index": self.index,
            "cf_amount": self.cf_amount,
            "comment": self.comment,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Product":
        return Product(
            data["product_id"],
            data["index"],
            data["cf_amount"],
            data["comment"],
        )


class NekokanProducts:
    def __init__(self, products: dict[int, Product]):
        self.products = products

    def serialize(self) -> dict[str, Any]:
        return {
            "products": {k: v.serialize() for k, v in self.products.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "NekokanProducts":
        return NekokanProducts(
            {k: Product.deserialize(v) for k, v in data["products"].items()},
        )

    @staticmethod
    def get_file_name(lang_code: str):
        return f"NekokanProduct_{lang_code}.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> Optional["NekokanProducts"]:
        lang_code = game_data.country_code.get_language()
        tsv_data = game_data.find_file(NekokanProducts.get_file_name(lang_code))
        if tsv_data is None:
            return None
        products: dict[int, Product] = {}
        csv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        for line in csv.lines[1:]:
            product = Product(
                line[0].to_str(),
                line[1].to_int(),
                line[2].to_int(),
                line[3].to_str(),
            )
            products[product.index] = product
        return NekokanProducts(products)

    def to_game_data(self, game_data: "pack.GamePacks"):
        lang_code = game_data.country_code.get_language()
        file_name = NekokanProducts.get_file_name(lang_code)
        tsv_data = game_data.find_file(file_name)
        if tsv_data is None:
            return None
        csv = io.bc_csv.CSV(tsv_data.dec_data, delimeter="\t")
        remaining = self.products.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                product = remaining[line[1].to_int()]
            except KeyError:
                continue
            line[0].set(product.product_id)
            line[1].set(product.index)
            line[2].set(product.cf_amount)
            line[3].set(product.comment)
            csv.set_line(i + 1, line)
            del remaining[product.index]
        for product in remaining.values():
            line: list[Any] = []
            line.append(product.product_id)
            line.append(product.index)
            line.append(product.cf_amount)
            line.append(product.comment)
            csv.add_line(line)
        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("catbase").add("nekokan_products.json")

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip_file.add_file(NekokanProducts.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "NekokanProducts":
        json_data = zip.get_file(NekokanProducts.get_json_file_path())
        if json_data is None:
            return NekokanProducts.create_empty()
        json = io.json_file.JsonFile.from_data(json_data)
        return NekokanProducts.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "NekokanProducts":
        return NekokanProducts({})

    def get_product(self, index: int) -> Optional[Product]:
        return self.products.get(index)

    def set_product(self, product: Product, index: int):
        product.index = index
        self.products[product.index] = product

    def import_nekokan(self, other: "NekokanProducts"):
        self.products.update(other.products)
