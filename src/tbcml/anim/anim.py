from dataclasses import field
import enum
from typing import Optional
import tbcml
import copy

from tbcml.io.csv_fields import (
    IntCSVField,
    CSVField,
    StringCSVField,
)
from marshmallow_dataclass import dataclass


class AnimModificationType(enum.Enum):
    PARENT = 0
    ID = 1
    SPRITE = 2
    Z_ORDER = 3
    POS_X = 4
    POS_Y = 5
    PIVOT_X = 6
    PIVOT_Y = 7
    SCALE_UNIT = 8
    SCALE_X = 9
    SCALE_Y = 10
    ANGLE = 11
    OPACITY = 12
    H_FLIP = 13
    V_FLIP = 14


class AnimType(enum.Enum):
    WALK = 0
    IDLE = 1
    ATTACK = 2
    KNOCK_BACK = 3

    @staticmethod
    def from_bcu_str(string: str) -> Optional["AnimType"]:
        string = string.split("_")[1]
        string = string.split(".")[0]
        if string == "walk":
            return AnimType.WALK
        elif string == "idle":
            return AnimType.IDLE
        elif string == "attack":
            return AnimType.ATTACK
        elif string == "kb":
            return AnimType.KNOCK_BACK
        else:
            return None


@dataclass
class Rect:
    x: IntCSVField = CSVField.to_field(IntCSVField, 0)
    y: IntCSVField = CSVField.to_field(IntCSVField, 1)
    w: IntCSVField = CSVField.to_field(IntCSVField, 2)
    h: IntCSVField = CSVField.to_field(IntCSVField, 3)
    name: StringCSVField = CSVField.to_field(StringCSVField, 4)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class TextureMetadata:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    img_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=2)
    total_rects: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=3)

    def read_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.apply_csv_fields(self, csv)

    def set_unit_form(self, form: str):
        name = self.img_name.get()
        parts = name.split("_")
        id = parts[0]
        self.img_name.set(f"{id}_{form}.png")

    def set_id(self, id: str):
        name = self.img_name.get()
        parts = name.split("_")
        form = parts[1]
        self.img_name.set(f"{id}_{form}")


@dataclass
class Texture:
    metadata: TextureMetadata = field(default_factory=lambda: TextureMetadata())
    image: Optional["tbcml.BCImage"] = field(
        default_factory=lambda: tbcml.BCImage.create_empty()
    )
    rects: list[Rect] = field(default_factory=lambda: [])
    imgcut_name: str = ""

    def save_b64(self):
        if self.image is not None:
            self.image.save_b64()

    def read_csv(self, csv: "tbcml.CSV", imgcut_name: Optional[str] = None):
        if imgcut_name is not None:
            self.imgcut_name = imgcut_name
        self.rects = []
        self.metadata.read_csv(csv)
        for i in range(self.metadata.total_rects.get()):
            index = i + 4
            rect = Rect()
            rect.read_csv(index, csv)
            self.rects.append(rect)

    def apply_csv(
        self,
        csv: "tbcml.CSV",
        game_data: "tbcml.GamePacks",
        imgname_save_overwrite: Optional[str] = None,
    ):
        self.metadata.total_rects.set(len(self.rects))
        self.metadata.apply_csv(csv)
        for i, rect in enumerate(self.rects):
            index = i + 4
            rect.apply_csv(index, csv)

        self.apply_img(game_data, imgname_save_overwrite)

    def apply_img(
        self, game_data: "tbcml.GamePacks", imgname_save_overwrite: Optional[str] = None
    ):
        if imgname_save_overwrite is not None:
            name = imgname_save_overwrite
        else:
            name = self.metadata.img_name.get()
        game_data.set_img(name, self.image)

    def read_img(self, game_data: "tbcml.GamePacks", img_name: str):
        self.image = game_data.get_img(img_name)

    def set_unit_form(self, form: str):
        self.metadata.set_unit_form(form)
        self.imgcut_name = self.metadata.img_name.get().replace(".png", ".imgcut")

    def set_id(self, id: str):
        self.metadata.set_id(id)
        self.imgcut_name = self.metadata.img_name.get().replace(".png", ".imgcut")

    def get_rect(self, id: int) -> Optional["Rect"]:
        try:
            rect = self.rects[id]
        except IndexError:
            return None
        return rect

    def get_cut(self, rect_id: int):
        if not self.image:
            return None

        rect = self.get_rect(rect_id)
        if rect is None:
            return None

        return self.image.get_subimage(rect)

    def get_cut_from_rect(self, rect: "tbcml.Rect") -> Optional["tbcml.BCImage"]:
        if self.image is None:
            return None
        return self.image.get_subimage(rect)

    def set_cut(self, rect_id: int, img: "tbcml.BCImage"):
        original_rect = self.get_rect(rect_id)
        if original_rect is None or self.image is None:
            return
        new_rect_new = img.get_rect(original_rect.x.get(), original_rect.y.get())
        self.rects[rect_id] = new_rect_new
        if (
            new_rect_new.w.get() <= original_rect.w.get()
            and new_rect_new.h.get() <= original_rect.h.get()
        ):
            self.image.wipe_rect(original_rect)
            self.image.paste_rect(img, new_rect_new)
            return

        # reconstruct imgcut
        x = 0
        y = 0
        new_rects: list["tbcml.Rect"] = []
        for rect in self.rects:
            new_rect = tbcml.Rect()
            new_rect.x.set(x)
            new_rect.y.set(0)
            new_rect.h.set(rect.h.get())
            new_rect.w.set(rect.w.get())
            new_rects.append(new_rect)
            x += new_rect.w.get()
            y = max(new_rect.h.get(), y)

        new_img = tbcml.BCImage.from_size(x, y)

        for i, (old_rect, new_rect) in enumerate(zip(self.rects, new_rects)):
            if i == rect_id:
                cut = img
            else:
                cut = self.get_cut_from_rect(old_rect)
            if cut is None:
                continue
            new_img.paste_rect(cut, new_rect)

        self.image = new_img
        self.rects = new_rects


@dataclass
class MamodelMetaData:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    total_parts: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=2)

    def read_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class ModelPart:
    parent_id: IntCSVField = CSVField.to_field(IntCSVField, 0)
    unit_id: IntCSVField = CSVField.to_field(IntCSVField, 1)
    cut_id: IntCSVField = CSVField.to_field(IntCSVField, 2)
    z_depth: IntCSVField = CSVField.to_field(IntCSVField, 3)
    x: IntCSVField = CSVField.to_field(IntCSVField, 4)
    y: IntCSVField = CSVField.to_field(IntCSVField, 5)
    pivot_x: IntCSVField = CSVField.to_field(IntCSVField, 6)
    pivot_y: IntCSVField = CSVField.to_field(IntCSVField, 7)
    scale_x: IntCSVField = CSVField.to_field(IntCSVField, 8)
    scale_y: IntCSVField = CSVField.to_field(IntCSVField, 9)
    rotation: IntCSVField = CSVField.to_field(IntCSVField, 10)
    alpha: IntCSVField = CSVField.to_field(IntCSVField, 11)
    glow: IntCSVField = CSVField.to_field(IntCSVField, 12)
    name: StringCSVField = CSVField.to_field(StringCSVField, 13)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv)

    def flip_rotation(self):
        self.rotation.value_ *= -1

    def flip_x(self, index: int):
        if index == 0:
            self.scale_x.value_ *= -1
        self.flip_rotation()

    def flip_y(self, index: int):
        if index == 0:
            self.scale_y.value_ *= -1
        self.flip_rotation()


@dataclass
class MamodelUnits:
    scale_unit: IntCSVField = CSVField.to_field(IntCSVField, 0)
    angle_unit: IntCSVField = CSVField.to_field(IntCSVField, 1)
    alpha_unit: IntCSVField = CSVField.to_field(IntCSVField, 2)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class MamodelInts:
    int_0: IntCSVField = CSVField.to_field(IntCSVField, 0)
    int_1: IntCSVField = CSVField.to_field(IntCSVField, 1)
    int_2: IntCSVField = CSVField.to_field(IntCSVField, 2)
    int_3: IntCSVField = CSVField.to_field(IntCSVField, 3)
    int_4: IntCSVField = CSVField.to_field(IntCSVField, 4)
    int_5: IntCSVField = CSVField.to_field(IntCSVField, 5)
    comment: StringCSVField = CSVField.to_field(StringCSVField, 6)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class MamodelIntsInts:
    ints: list[MamodelInts] = field(default_factory=lambda: [])
    total_ints: IntCSVField = CSVField.to_field(IntCSVField, 0)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        self.ints = []
        tbcml.Modification.read_csv_fields(self, csv)
        for i in range(self.total_ints.get()):
            ind = index + i + 1
            ints = MamodelInts()
            ints.read_csv(ind, csv)
            self.ints.append(ints)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        self.total_ints.set(len(self.ints))
        tbcml.Modification.apply_csv_fields(self, csv)
        for i, ints in enumerate(self.ints):
            ind = index + i + 1
            ints.apply_csv(ind, csv)


@dataclass
class Mamodel:
    metadata: MamodelMetaData = field(default_factory=lambda: MamodelMetaData())
    parts: list[ModelPart] = field(default_factory=lambda: [])
    units: MamodelUnits = field(default_factory=lambda: MamodelUnits())
    ints: MamodelIntsInts = field(default_factory=lambda: MamodelIntsInts())
    mamodel_name: str = ""

    def read_csv(self, csv: "tbcml.CSV"):
        self.metadata.read_csv(csv)
        self.parts = []
        for i in range(self.metadata.total_parts.get()):
            index = i + 3
            part = ModelPart()
            part.read_csv(index, csv)
            self.parts.append(part)
        self.units.read_csv(len(self.parts) + 3, csv)
        self.ints.read_csv(len(self.parts) + 4, csv)

    def apply_csv(self, csv: "tbcml.CSV"):
        self.metadata.total_parts.set(len(self.parts))
        self.metadata.apply_csv(csv)
        for i, part in enumerate(self.parts):
            index = i + 3
            part.apply_csv(index, csv)

        self.units.apply_csv(len(self.parts) + 3, csv)
        self.ints.apply_csv(len(self.parts) + 4, csv)

    def set_unit_form(self, form: str):
        name = self.mamodel_name
        parts = name.split("_")
        id = parts[0]
        self.mamodel_name = f"{id}_{form}.mamodel"

    def set_id(self, id: str):
        name = self.mamodel_name
        parts = name.split("_")
        form = parts[1]
        self.mamodel_name = f"{id}_{form}"

        for part in self.parts[1:]:
            part.unit_id.set(int(id))

    def dup_ints(self):
        if len(self.ints.ints) == 1:
            self.ints.ints.append(self.ints.ints[0])
            self.ints.total_ints.set(2)


@dataclass
class KeyFrame:
    frame: IntCSVField = CSVField.to_field(IntCSVField, 0)
    change_in_value: IntCSVField = CSVField.to_field(IntCSVField, 1)
    ease_mode: IntCSVField = CSVField.to_field(IntCSVField, 2)
    ease_power: IntCSVField = CSVField.to_field(IntCSVField, 3)

    def read_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "tbcml.CSV"):
        csv.index = index
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class MaanimMetadata:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    total_parts: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=2)

    def read_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "tbcml.CSV"):
        tbcml.Modification.apply_csv_fields(self, csv)


@dataclass
class KeyFrames:
    keyframes: list[KeyFrame] = field(default_factory=lambda: [])
    model_id: IntCSVField = CSVField.to_field(IntCSVField, 0)
    modification_type: IntCSVField = CSVField.to_field(IntCSVField, 1)
    loop: IntCSVField = CSVField.to_field(IntCSVField, 2)
    min_value: IntCSVField = CSVField.to_field(IntCSVField, 3)
    max_value: IntCSVField = CSVField.to_field(IntCSVField, 4)
    name: StringCSVField = CSVField.to_field(StringCSVField, 5)
    total_keyframes: IntCSVField = CSVField.to_field(IntCSVField, 0, row_offset=1)

    def read_csv(self, index: int, csv: "tbcml.CSV") -> int:
        csv.index = index
        tbcml.Modification.read_csv_fields(self, csv)
        self.keyframes = []
        for i in range(self.total_keyframes.get()):
            ind = index + i + 2
            keyframe = KeyFrame()
            keyframe.read_csv(ind, csv)
            self.keyframes.append(keyframe)

        return index + 2 + self.total_keyframes.get()

    def apply_csv(self, index: int, csv: "tbcml.CSV") -> int:
        csv.index = index
        self.total_keyframes.set(len(self.keyframes))
        tbcml.Modification.apply_csv_fields(self, csv)
        for i, keyframe in enumerate(self.keyframes):
            ind = index + i + 2
            keyframe.apply_csv(ind, csv)

        return index + 2 + len(self.keyframes)

    def flip(self):
        if self.modification_type.get() != AnimModificationType.ANGLE.value:
            return
        for keyframe in self.keyframes:
            keyframe.change_in_value.set(-keyframe.change_in_value.get())


@dataclass
class UnitAnim:
    metadata: MaanimMetadata = field(default_factory=lambda: MaanimMetadata())
    parts: list[KeyFrames] = field(default_factory=lambda: [])
    name: str = ""

    def read_csv(self, csv: "tbcml.CSV"):
        self.metadata.read_csv(csv)
        index = 3
        self.parts = []
        for _ in range(self.metadata.total_parts.get()):
            part = KeyFrames()
            index = part.read_csv(index, csv)
            self.parts.append(part)

    def apply_csv(self, csv: "tbcml.CSV"):
        self.metadata.total_parts.set(len(self.parts))
        self.metadata.apply_csv(csv)
        index = 3
        for part in self.parts:
            index = part.apply_csv(index, csv)

    def flip(self):
        for part in self.parts:
            part.flip()

    def set_unit_form(self, form: str):
        name = self.name
        parts = name.split("_")
        id = parts[0]
        anim_id = parts[1][1:3]
        self.name = f"{id}_{form}{anim_id}.maanim"

    def set_id(self, id: str):
        parts = self.name.split("_")
        parts[0] = id
        self.name = "_".join(parts)


@dataclass
class Model(tbcml.Modification):
    texture: Texture = field(default_factory=lambda: Texture())
    anims: list[UnitAnim] = field(default_factory=lambda: [])
    mamodel: Mamodel = field(default_factory=lambda: Mamodel())

    def read_csv(
        self,
        img: Optional["tbcml.BCImage"],
        imgcut_csv: Optional["tbcml.CSV"],
        maanim_csvs: dict[str, "tbcml.CSV"],
        mamodel_csv: Optional["tbcml.CSV"],
    ):
        if imgcut_csv is not None:
            self.texture.read_csv(imgcut_csv)
        self.texture.image = img
        self.anims = []
        for name, maanim_csv in maanim_csvs.items():
            anim = UnitAnim(name=name)
            anim.read_csv(maanim_csv)
            self.anims.append(anim)

        if mamodel_csv is not None:
            self.mamodel.read_csv(mamodel_csv)

    def apply_csv(
        self,
        imgcut_csv: "tbcml.CSV",
        maanim_csvs: dict[str, "tbcml.CSV"],
        mamodel_csv: "tbcml.CSV",
        game_data: "tbcml.GamePacks",
    ):
        self.texture.apply_csv(imgcut_csv, game_data)
        for anim in self.anims:
            maanim_csv = maanim_csvs.get(anim.name)
            if maanim_csv is not None:
                anim.apply_csv(maanim_csv)
        self.mamodel.apply_csv(mamodel_csv)

    def read(
        self,
        game_data: "tbcml.GamePacks",
        sprite_name: str,
        imgcut_name: str,
        maanim_names: list[str],
        mamodel_name: str,
    ):
        self.texture.imgcut_name = imgcut_name
        self.texture.metadata.img_name.set(sprite_name)

        texture_csv = game_data.get_csv(imgcut_name)

        self.mamodel.mamodel_name = mamodel_name

        mamodel_csv = game_data.get_csv(mamodel_name)

        maanim_csvs: dict[str, "tbcml.CSV"] = {}
        for maanim_name in maanim_names:
            maanim_csv = game_data.get_csv(maanim_name)
            if maanim_csv is not None:
                maanim_csvs[maanim_name] = maanim_csv

        img = game_data.get_img(sprite_name)

        self.read_csv(img, texture_csv, maanim_csvs, mamodel_csv)

    def read_files(
        self,
        sprite_path: "tbcml.Path",
        imgcut_path: "tbcml.Path",
        maanim_paths: list["tbcml.Path"],
        mamodel_path: "tbcml.Path",
    ):
        self.texture.imgcut_name = imgcut_path.basename()
        self.texture.metadata.img_name.set(sprite_path.basename())
        texture_csv = tbcml.CSV(imgcut_path.read())

        self.mamodel.mamodel_name = mamodel_path.basename()
        mamodel_csv = tbcml.CSV(mamodel_path.read())

        maanim_csvs: dict[str, "tbcml.CSV"] = {}
        for path in maanim_paths:
            maanim_csv = tbcml.CSV(path.read())
            maanim_csvs[path.basename()] = maanim_csv

        self.read_csv(
            tbcml.BCImage.from_file(sprite_path),
            texture_csv,
            maanim_csvs,
            mamodel_csv,
        )

    def read_data(
        self,
        sprite_name: str,
        sprite_data: "tbcml.Data",
        imgcut_name: str,
        imgcut_data: "tbcml.Data",
        maanim_names: list[str],
        maanim_datas: list["tbcml.Data"],
        mamodel_name: str,
        mamodel_data: "tbcml.Data",
    ):
        self.texture.imgcut_name = imgcut_name
        self.texture.metadata.img_name.set(sprite_name)
        texture_csv = tbcml.CSV(imgcut_data)

        self.mamodel.mamodel_name = mamodel_name
        mamodel_csv = tbcml.CSV(mamodel_data)

        maanim_csvs: dict[str, "tbcml.CSV"] = {}
        for name, data in zip(maanim_names, maanim_datas):
            maanim_csv = tbcml.CSV(data)
            maanim_csvs[name] = maanim_csv

        self.read_csv(
            tbcml.BCImage.from_data(sprite_data),
            texture_csv,
            maanim_csvs,
            mamodel_csv,
        )

    def apply(self, game_data: "tbcml.GamePacks"):
        texture_csv = tbcml.CSV()
        self.texture.apply_csv(texture_csv, game_data)
        game_data.set_csv(self.texture.imgcut_name, texture_csv)

        mamodel_csv = tbcml.CSV()
        self.mamodel.apply_csv(mamodel_csv)
        game_data.set_csv(self.mamodel.mamodel_name, mamodel_csv)

        for maanim in self.anims:
            maanim_csv = tbcml.CSV()
            maanim.apply_csv(maanim_csv)
            game_data.set_csv(maanim.name, maanim_csv)

    def flip_x(self):
        for i, part in enumerate(self.mamodel.parts):
            part.flip_x(i)
        self.flip_anims()

    def flip_y(self):
        for i, part in enumerate(self.mamodel.parts):
            part.flip_y(i)
        self.flip_anims()

    def flip_anims(self):
        for anim in self.anims:
            anim.flip()

    def deepcopy(self) -> "Model":
        return copy.deepcopy(self)

    def set_unit_form(self, form: str):
        self.texture.set_unit_form(form)
        self.mamodel.set_unit_form(form)
        for anim in self.anims:
            anim.set_unit_form(form)

    def set_id(self, id: int):
        id_str = tbcml.PaddedInt(id, 3).to_str()
        self.texture.set_id(id_str)
        self.mamodel.set_id(id_str)
        for anim in self.anims:
            anim.set_id(id_str)
