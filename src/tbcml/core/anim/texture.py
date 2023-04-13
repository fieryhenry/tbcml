from typing import Any, Optional
from tbcml.core.anim import rect
from tbcml.core import io
from tbcml.core import game_data


class TexMetadata:
    def __init__(
        self,
        head_name: str,
        version_code: int,
        img_name: str,
        total_rects: int,
    ):
        self.head_name = head_name
        self.version_code = version_code
        self.img_name = img_name
        self.total_rects = total_rects

    @staticmethod
    def create_empty() -> "TexMetadata":
        return TexMetadata("", 0, "", 0)

    @staticmethod
    def from_csv(csv: "io.bc_csv.CSV") -> "TexMetadata":
        head_line = csv.read_line()
        if head_line is None:
            return TexMetadata.create_empty()
        head_name = head_line[0].to_str()

        version_line = csv.read_line()
        if version_line is None:
            return TexMetadata.create_empty()
        version_code = version_line[0].to_int()

        img_line = csv.read_line()
        if img_line is None:
            return TexMetadata.create_empty()
        img_name = img_line[0].to_str()

        total_rects_line = csv.read_line()
        if total_rects_line is None:
            return TexMetadata.create_empty()
        total_rects = total_rects_line[0].to_int()

        return TexMetadata(head_name, version_code, img_name, total_rects)

    def to_csv(self, total_rects: int) -> "io.bc_csv.CSV":
        self.set_total_rects(total_rects)

        csv = io.bc_csv.CSV()

        csv.add_line(self.head_name)
        csv.add_line(self.version_code)
        csv.add_line(self.img_name)
        csv.add_line(self.total_rects)

        return csv

    def set_total_rects(self, total_rects: int):
        self.total_rects = total_rects

    def serialize(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "img_name": self.img_name,
            "total_rects": self.total_rects,
        }

    @staticmethod
    def deserialize(d: dict[str, Any]) -> "TexMetadata":
        return TexMetadata(
            d["head_name"], d["version_code"], d["img_name"], d["total_rects"]
        )

    def __str__(self):
        return f"TexMetadata({self.head_name}, {self.version_code}, {self.img_name}, {self.total_rects})"

    def __repr__(self):
        return f"TexMetadata({self.head_name}, {self.version_code}, {self.img_name}, {self.total_rects})"

    def __eq__(self, other: Any):
        if not isinstance(other, TexMetadata):
            return False

        return (
            self.head_name == other.head_name
            and self.version_code == other.version_code
            and self.img_name == other.img_name
            and self.total_rects == other.total_rects
        )

    def copy(self) -> "TexMetadata":
        return TexMetadata(
            self.head_name, self.version_code, self.img_name, self.total_rects
        )

    def set_img_name(self, img_name: str):
        self.img_name = img_name

    def set_unit_id(self, id: int):
        img_name = self.img_name
        parts = img_name.split("_")
        parts[0] = f"{id:03}"
        self.img_name = "_".join(parts)

    def set_unit_form(self, form: str):
        img_name = self.img_name
        parts = img_name.split("_")
        parts[1] = form
        self.img_name = "_".join(parts)


class Cut:
    def __init__(self, rect: rect.Rect, img: "io.bc_image.BCImage"):
        self.rect = rect
        self.img = img


class TexLoaderInfo:
    def __init__(
        self, img_name: str, imgcut_name: str, game_packs: "game_data.pack.GamePacks"
    ):
        self.img_name = img_name
        self.imgcut_name = imgcut_name
        self.game_packs = game_packs

    def load(self) -> "Texture":
        return Texture.load(self.img_name, self.imgcut_name, self.game_packs)


class Texture:
    def __init__(
        self,
        image: "io.bc_image.BCImage",
        rects: list[rect.Rect],
        metadata: TexMetadata,
        img_name: str,
        imgcut_name: str,
    ):
        self.image = image
        self.rects = rects
        self.metadata = metadata
        self.img_name = img_name
        self.imgcut_name = imgcut_name

    @staticmethod
    def load(png_name: str, imgcut_name: str, game_packs: "game_data.pack.GamePacks"):
        imgcut = game_packs.find_file(imgcut_name)
        png = game_packs.find_file(png_name)
        if not imgcut or not png:
            return Texture.create_empty()

        csv = imgcut.dec_data.to_csv()
        meta_data = TexMetadata.from_csv(csv)

        total_rects = meta_data.total_rects
        rects: list[rect.Rect] = []
        for _ in range(total_rects):
            rect_l = csv.read_line()
            if rect_l is None:
                return Texture.create_empty()
            rect_ = rect.Rect.from_list(rect_l)
            if rect_ is None:
                return Texture.create_empty()
            rects.append(rect_)

        return Texture(
            io.bc_image.BCImage(png.dec_data), rects, meta_data, png_name, imgcut_name
        )

    @staticmethod
    def create_empty():
        return Texture(
            io.bc_image.BCImage.create_empty(), [], TexMetadata.create_empty(), "", ""
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "image": self.image.serialize(),
            "rects": [r.serialize() for r in self.rects],
            "metadata": self.metadata.serialize(),
            "img_name": self.img_name,
            "imgcut_name": self.imgcut_name,
        }

    @staticmethod
    def deserialize(d: dict[str, Any]) -> "Texture":
        return Texture(
            io.bc_image.BCImage.deserialize(d["image"]),
            [rect.Rect.deserialize(r) for r in d["rects"]],
            TexMetadata.deserialize(d["metadata"]),
            d["img_name"],
            d["imgcut_name"],
        )

    def __str__(self):
        return f"Texture({self.image}, {self.rects}, {self.metadata}, {self.img_name}, {self.imgcut_name})"

    def __repr__(self):
        return f"Texture({self.image}, {self.rects}, {self.metadata}, {self.img_name}, {self.imgcut_name})"

    def save(self, game_packs: "game_data.pack.GamePacks"):
        imgcut = game_packs.find_file(self.imgcut_name)
        if not imgcut:
            return
        png_data = self.image.to_data()
        game_packs.set_file(self.img_name, png_data)

        csv = self.metadata.to_csv(len(self.rects))
        for r in self.rects:
            csv.add_line(r.to_list())
        imgcut_data = csv.to_data()
        game_packs.set_file(self.imgcut_name, imgcut_data)

    def __eq__(self, other: Any):
        if not isinstance(other, Texture):
            return False

        return (
            self.image == other.image
            and self.rects == other.rects
            and self.metadata == other.metadata
        )

    def copy(self) -> "Texture":
        return Texture(
            self.image.copy(),
            [r.copy() for r in self.rects],
            self.metadata.copy(),
            self.img_name,
            self.imgcut_name,
        )

    def get_rect(self, index: int) -> Optional[rect.Rect]:
        try:
            return self.rects[index]
        except IndexError:
            return None

    def set_rect(self, index: int, rect_: rect.Rect):
        self.rects[index] = rect_

    def get_image(self, index: int) -> Optional["io.bc_image.BCImage"]:
        cut = self.get_cut(index)
        if cut is not None:
            return cut.img

        rct = self.get_rect(index)
        if rct is None:
            return None

        return self.image.get_subimage(rct)

    def is_empty(self) -> bool:
        return self.image.is_empty()

    def set_unit_id(self, id: int):
        self.metadata.set_unit_id(id)

    def set_unit_form(self, form: str):
        self.metadata.set_unit_form(form)

    def split_cuts(self):
        self.cuts: list[Cut] = []

        for r in self.rects:
            self.cuts.append(Cut(r, self.image.get_subimage(r)))

    def get_cut(self, index: int) -> Optional[Cut]:
        try:
            return self.cuts[index]
        except IndexError:
            return None
