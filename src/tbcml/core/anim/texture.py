from typing import Any, Optional
from tbcml import core


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
    def from_csv(csv: "core.CSV") -> "TexMetadata":
        head_line = csv.read_line()
        if head_line is None:
            return TexMetadata.create_empty()
        head_name = head_line[0]

        version_line = csv.read_line()
        if version_line is None:
            return TexMetadata.create_empty()
        version_code = int(version_line[0])

        img_line = csv.read_line()
        if img_line is None:
            return TexMetadata.create_empty()
        img_name = img_line[0]

        total_rects_line = csv.read_line()
        if total_rects_line is None:
            return TexMetadata.create_empty()
        total_rects = int(total_rects_line[0])

        return TexMetadata(head_name, version_code, img_name, total_rects)

    def to_csv(self, total_rects: int) -> "core.CSV":
        self.set_total_rects(total_rects)

        csv = core.CSV()

        csv.lines.append([self.head_name])
        csv.lines.append([str(self.version_code)])
        csv.lines.append([self.img_name])
        csv.lines.append([str(self.total_rects)])

        return csv

    def set_total_rects(self, total_rects: int):
        self.total_rects = total_rects

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
        if not self.img_name.endswith(".png"):
            self.img_name += ".png"

    def set_unit_form(self, form: str):
        name = self.img_name
        parts = name.split("_")
        cat_id = parts[0]
        self.img_name = f"{cat_id}_{form}.png"

    def apply_dict(self, dict_data: dict[str, Any]):
        head_name = dict_data.get("head_name")
        if head_name is not None:
            self.head_name = head_name

        version_code = dict_data.get("version_code")
        if version_code is not None:
            self.version_code = version_code

        img_name = dict_data.get("img_name")
        if img_name is not None:
            self.img_name = img_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "img_name": self.img_name,
        }


class CutTexture:
    def __init__(self, rect: "core.Rect", img: "core.BCImage"):
        self.rect = rect
        self.img = img

    def apply_dict(self, dict_data: dict[str, Any]):
        rect_data = dict_data.get("rect")
        if rect_data is not None:
            self.rect.apply_dict(rect_data)

        img_data = dict_data.get("img")
        if img_data is not None:
            self.img.apply_dict(img_data)

    def to_dict(self) -> dict[str, Any]:
        return {"rect": self.rect.to_dict(), "img": self.img.to_dict()}


class TexLoaderInfo:
    def __init__(self, img_name: str, imgcut_name: str, game_packs: "core.GamePacks"):
        self.img_name = img_name
        self.imgcut_name = imgcut_name
        self.game_packs = game_packs

    def load(self) -> "Texture":
        return Texture.load(self.img_name, self.imgcut_name, self.game_packs)


class Texture:
    def __init__(
        self,
        image: "core.BCImage",
        rects: list["core.Rect"],
        metadata: "TexMetadata",
        imgcut_name: str,
        img_name: Optional[str] = None,
    ):
        self.image = image
        self.rects = rects
        self.metadata = metadata
        self.imgcut_name = imgcut_name
        self.cuts: list[CutTexture] = []
        if img_name is not None:
            self.metadata.set_img_name(img_name)

    @property
    def img_name(self) -> str:
        return self.metadata.img_name

    @staticmethod
    def load(png_name: str, imgcut_name: str, game_packs: "core.GamePacks"):
        imgcut = game_packs.find_file(imgcut_name)
        png = game_packs.find_file(png_name)
        if not imgcut or not png:
            return Texture.create_empty()

        return Texture.from_data(imgcut.dec_data, png.dec_data, png_name, imgcut_name)

    @staticmethod
    def from_data(
        imgcut_data: "core.Data",
        png_data: "core.Data",
        png_name: str,
        imgcut_name: str,
    ):
        csv = imgcut_data.to_csv()
        meta_data = TexMetadata.from_csv(csv)

        total_rects = meta_data.total_rects
        rects: list[core.Rect] = []
        for _ in range(total_rects):
            rect_l = csv.read_line()
            if rect_l is None:
                return Texture.create_empty()
            rect_ = core.Rect.from_list(rect_l)
            if rect_ is None:
                return Texture.create_empty()
            rects.append(rect_)

        return Texture(core.BCImage(png_data), rects, meta_data, imgcut_name, png_name)

    @staticmethod
    def create_empty():
        return Texture(core.BCImage.create_empty(), [], TexMetadata.create_empty(), "")

    def save(self, game_packs: "core.GamePacks"):
        imgcut_data, png_data = self.to_data()
        game_packs.set_file(self.imgcut_name, imgcut_data)
        game_packs.set_file(self.metadata.img_name, png_data)

    def to_data(self):
        csv = self.metadata.to_csv(len(self.rects))
        for r in self.rects:
            csv.lines.append(r.to_list())
        imgcut_data = csv.to_data()
        png_data = self.image.to_data()
        return imgcut_data, png_data

    def copy(self) -> "Texture":
        return Texture(
            self.image.copy(),
            [r.copy() for r in self.rects],
            self.metadata.copy(),
            self.imgcut_name,
        )

    def get_rect(self, index: int) -> Optional["core.Rect"]:
        try:
            return self.rects[index]
        except IndexError:
            return None

    def set_rect(self, index: int, rect_: "core.Rect"):
        self.rects[index] = rect_

    def get_image(self, index: int) -> Optional["core.BCImage"]:
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
        self.imgcut_name = self.metadata.img_name.replace(".png", ".imgcut")

    def set_unit_form(self, form: str):
        self.metadata.set_unit_form(form)
        self.imgcut_name = self.metadata.img_name.replace(".png", ".imgcut")

    def split_cuts(self):
        self.cuts: list[CutTexture] = []

        for r in self.rects:
            self.cuts.append(CutTexture(r, self.image.get_subimage(r)))

    def get_cut(self, index: int) -> Optional[CutTexture]:
        try:
            return self.cuts[index]
        except IndexError:
            return None

    def apply_dict(self, dict_data: dict[str, Any]):
        image = dict_data.get("image")
        if image is not None:
            self.image.apply_dict(image)

        rects = dict_data.get("rects")
        if rects is not None:
            for i, data_rect in enumerate(rects):
                if i < len(self.rects):
                    self.rects[i].apply_dict(data_rect)
                else:
                    self.rects.append(core.Rect.from_dict(data_rect))

        metadata = dict_data.get("metadata")
        if metadata is not None:
            self.metadata.apply_dict(metadata)

        imgcut_name = dict_data.get("imgcut_name")
        if imgcut_name is not None:
            self.imgcut_name = imgcut_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "image": self.image.to_dict(),
            "rects": [r.to_dict() for r in self.rects],
            "metadata": self.metadata.to_dict(),
            "imgcut_name": self.imgcut_name,
        }

    def reconstruct_image_from_cuts(self):
        self.image = core.BCImage.create_empty()
        for cut in self.cuts:
            self.image.paste_rect(cut.img, cut.rect)

        self.rects = [cut.rect for cut in self.cuts]
