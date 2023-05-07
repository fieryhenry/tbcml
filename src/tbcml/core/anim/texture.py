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

    def to_csv(self, total_rects: int) -> "io.bc_csv.CSV":
        self.set_total_rects(total_rects)

        csv = io.bc_csv.CSV()

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

    def set_unit_form(self, form: str):
        img_name = self.img_name
        parts = img_name.split("_")
        parts[1] = form
        self.img_name = "_".join(parts)

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

        total_rects = dict_data.get("total_rects")
        if total_rects is not None:
            self.total_rects = total_rects


class Cut:
    def __init__(self, rect: rect.Rect, img: "io.bc_image.BCImage"):
        self.rect = rect
        self.img = img

    def apply_dict(self, dict_data: dict[str, Any]):
        rect_data = dict_data.get("rect")
        if rect_data is not None:
            self.rect.apply_dict(rect_data)

        img_data = dict_data.get("img")
        if img_data is not None:
            self.img.apply_dict(img_data)


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

    def save(self, game_packs: "game_data.pack.GamePacks"):
        imgcut = game_packs.find_file(self.imgcut_name)
        if not imgcut:
            return
        png_data = self.image.to_data()
        game_packs.set_file(self.img_name, png_data)

        csv = self.metadata.to_csv(len(self.rects))
        for r in self.rects:
            csv.lines.append(r.to_list())
        imgcut_data = csv.to_data()
        game_packs.set_file(self.imgcut_name, imgcut_data)

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

    def apply_dict(self, dict_data: dict[str, Any]):
        image = dict_data.get("image")
        if image is not None:
            self.image.apply_dict(image)

        rects = dict_data.get("rects")
        if rects is not None:
            for i, data_rect in enumerate(rects):
                if i < len(self.rects):
                    self.rects[i].apply_dict(data_rect)

        metadata = dict_data.get("metadata")
        if metadata is not None:
            self.metadata.apply_dict(metadata)

        img_name = dict_data.get("img_name")
        if img_name is not None:
            self.img_name = img_name

        imgcut_name = dict_data.get("imgcut_name")
        if imgcut_name is not None:
            self.imgcut_name = imgcut_name

        cuts = dict_data.get("cuts")
        if cuts is not None:
            for i, data_cut in enumerate(cuts):
                if i < len(self.cuts):
                    self.cuts[i].apply_dict(data_cut)
            self.reconstruct_image_from_cuts()

    def reconstruct_image_from_cuts(self):
        self.image = io.bc_image.BCImage.create_empty()
        for cut in self.cuts:
            self.image.paste_rect(cut.img, cut.rect)

        self.rects = [cut.rect for cut in self.cuts]
