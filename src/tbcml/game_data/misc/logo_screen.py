from typing import Optional
from marshmallow_dataclass import dataclass
import tbcml


@dataclass
class LogoScreen(tbcml.Modification):
    img: Optional["tbcml.BCImage"] = None

    def apply_mod(self, mod: "tbcml.Mod"):
        if self.img is not None:
            mod.add_encrypted_pkg_asset("logo.png", self.img.to_data())

    def read(self, pkg: "tbcml.PKG"):
        data = pkg.get_asset_decrypt("logo.png")
        self.img = tbcml.BCImage.from_data(data)

    def pre_to_json(self) -> None:
        if self.img is not None:
            self.img.save_b64()

    def import_img(self, file: "tbcml.File"):
        data = tbcml.load(file)
        self.img = tbcml.BCImage.from_data(data)
