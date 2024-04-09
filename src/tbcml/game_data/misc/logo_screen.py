from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml


@dataclass
class LogoScreen(tbcml.Modification):
    img: Optional["tbcml.BCImage"] = None

    def apply_pkg(self, pkg: "tbcml.PKG", lang: Optional[str]):
        if self.img is not None:
            pkg.add_asset_encrypt("logo.png", self.img.to_data())

    def read(self, pkg: "tbcml.PKG"):
        data = pkg.get_asset_decrypt("logo.png")
        self.img = tbcml.BCImage.from_data(data)

    def pre_to_json(self) -> None:
        if self.img is not None:
            self.img.save_b64()

    def import_img(self, file: "tbcml.File"):
        data = tbcml.load(file)
        self.img = tbcml.BCImage.from_data(data)
