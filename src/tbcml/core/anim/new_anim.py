from dataclasses import field
from typing import Optional
from tbcml import core
import copy

from tbcml.core.io.csv_fields import (
    IntCSVField,
    CSVField,
    StringCSVField,
)
from marshmallow_dataclass import dataclass


@dataclass
class CustomRect:
    x: IntCSVField = CSVField.to_field(IntCSVField, 0)
    y: IntCSVField = CSVField.to_field(IntCSVField, 1)
    w: IntCSVField = CSVField.to_field(IntCSVField, 2)
    h: IntCSVField = CSVField.to_field(IntCSVField, 3)
    name: StringCSVField = CSVField.to_field(StringCSVField, 4)

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomTextureMetadata:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    img_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=2)
    total_rects: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=3)

    def read_csv(self, csv: "core.CSV"):
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "core.CSV"):
        core.Modification.apply_csv_fields(self, csv)

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
class CustomTexture:
    metadata: CustomTextureMetadata = field(
        default_factory=lambda: CustomTextureMetadata()
    )
    image: Optional["core.NewBCImage"] = field(
        default_factory=lambda: core.NewBCImage.create_empty()
    )
    rects: list[CustomRect] = field(default_factory=lambda: [])
    imgcut_name: str = ""

    def save_b64(self):
        if self.image is not None:
            self.image.save_b64()

    def read_csv(self, csv: "core.CSV"):
        self.rects = []
        self.metadata.read_csv(csv)
        for i in range(self.metadata.total_rects.get()):
            index = i + 4
            rect = CustomRect()
            rect.read_csv(index, csv)
            self.rects.append(rect)

    def apply_csv(self, csv: "core.CSV", game_data: "core.GamePacks"):
        self.metadata.total_rects.set(len(self.rects))
        self.metadata.apply_csv(csv)
        for i, rect in enumerate(self.rects):
            index = i + 4
            rect.apply_csv(index, csv)

        self.apply_img(game_data)

    def apply_img(self, game_data: "core.GamePacks"):
        game_data.set_img(self.metadata.img_name.get(), self.image)

    def read_img(self, game_data: "core.GamePacks", img_name: str):
        self.image = game_data.get_img(img_name)

    def set_unit_form(self, form: str):
        self.metadata.set_unit_form(form)
        self.imgcut_name = self.metadata.img_name.get().replace(".png", ".imgcut")

    def set_id(self, id: str):
        self.metadata.set_id(id)
        self.imgcut_name = self.metadata.img_name.get().replace(".png", ".imgcut")


@dataclass
class CustomMamodelMetaData:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    total_parts: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=2)

    def read_csv(self, csv: "core.CSV"):
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "core.CSV"):
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomModelPart:
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

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)

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
class CustomUnits:
    scale_unit: IntCSVField = CSVField.to_field(IntCSVField, 0)
    angle_unit: IntCSVField = CSVField.to_field(IntCSVField, 1)
    alpha_unit: IntCSVField = CSVField.to_field(IntCSVField, 2)

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomInts:
    int_0: IntCSVField = CSVField.to_field(IntCSVField, 0)
    int_1: IntCSVField = CSVField.to_field(IntCSVField, 1)
    int_2: IntCSVField = CSVField.to_field(IntCSVField, 2)
    int_3: IntCSVField = CSVField.to_field(IntCSVField, 3)
    int_4: IntCSVField = CSVField.to_field(IntCSVField, 4)
    int_5: IntCSVField = CSVField.to_field(IntCSVField, 5)
    comment: StringCSVField = CSVField.to_field(StringCSVField, 6)

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomIntsInts:
    ints: list[CustomInts] = field(default_factory=lambda: [])
    total_ints: IntCSVField = CSVField.to_field(IntCSVField, 0)

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        self.ints = []
        core.Modification.read_csv_fields(self, csv)
        for i in range(self.total_ints.get()):
            ind = index + i + 1
            ints = CustomInts()
            ints.read_csv(ind, csv)
            self.ints.append(ints)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        self.total_ints.set(len(self.ints))
        core.Modification.apply_csv_fields(self, csv)
        for i, ints in enumerate(self.ints):
            ind = index + i + 1
            ints.apply_csv(ind, csv)


@dataclass
class CustomMamodel:
    metadata: CustomMamodelMetaData = field(
        default_factory=lambda: CustomMamodelMetaData()
    )
    parts: list[CustomModelPart] = field(default_factory=lambda: [])
    units: CustomUnits = field(default_factory=lambda: CustomUnits())
    ints: CustomIntsInts = field(default_factory=lambda: CustomIntsInts())
    mamodel_name: str = ""

    def read_csv(self, csv: "core.CSV"):
        self.metadata.read_csv(csv)
        self.parts = []
        for i in range(self.metadata.total_parts.get()):
            index = i + 3
            part = CustomModelPart()
            part.read_csv(index, csv)
            self.parts.append(part)
        self.units.read_csv(len(self.parts) + 3, csv)
        self.ints.read_csv(len(self.parts) + 4, csv)

    def apply_csv(self, csv: "core.CSV"):
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
class CustomKeyFrame:
    frame: IntCSVField = CSVField.to_field(IntCSVField, 0)
    change_in_value: IntCSVField = CSVField.to_field(IntCSVField, 1)
    ease_mode: IntCSVField = CSVField.to_field(IntCSVField, 2)
    ease_power: IntCSVField = CSVField.to_field(IntCSVField, 3)

    def read_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, index: int, csv: "core.CSV"):
        csv.index = index
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomMaanimMetadata:
    head_name: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=0)
    version_code: StringCSVField = CSVField.to_field(StringCSVField, 0, row_index=1)
    total_parts: IntCSVField = CSVField.to_field(IntCSVField, 0, row_index=2)

    def read_csv(self, csv: "core.CSV"):
        core.Modification.read_csv_fields(self, csv)

    def apply_csv(self, csv: "core.CSV"):
        core.Modification.apply_csv_fields(self, csv)


@dataclass
class CustomKeyFrames:
    keyframes: list[CustomKeyFrame] = field(default_factory=lambda: [])
    model_id: IntCSVField = CSVField.to_field(IntCSVField, 0)
    modification_type: IntCSVField = CSVField.to_field(IntCSVField, 1)
    loop: IntCSVField = CSVField.to_field(IntCSVField, 2)
    min_value: IntCSVField = CSVField.to_field(IntCSVField, 3)
    max_value: IntCSVField = CSVField.to_field(IntCSVField, 4)
    name: StringCSVField = CSVField.to_field(StringCSVField, 5)
    total_keyframes: IntCSVField = CSVField.to_field(IntCSVField, 0, row_offset=1)

    def read_csv(self, index: int, csv: "core.CSV") -> int:
        csv.index = index
        core.Modification.read_csv_fields(self, csv)
        self.keyframes = []
        for i in range(self.total_keyframes.get()):
            ind = index + i + 2
            keyframe = CustomKeyFrame()
            keyframe.read_csv(ind, csv)
            self.keyframes.append(keyframe)

        return index + 2 + self.total_keyframes.get()

    def apply_csv(self, index: int, csv: "core.CSV") -> int:
        csv.index = index
        self.total_keyframes.set(len(self.keyframes))
        core.Modification.apply_csv_fields(self, csv)
        for i, keyframe in enumerate(self.keyframes):
            ind = index + i + 2
            keyframe.apply_csv(ind, csv)

        return index + 2 + len(self.keyframes)

    def flip(self):
        if self.modification_type.get() != core.AnimModificationType.ANGLE.value:
            return
        for keyframe in self.keyframes:
            keyframe.change_in_value.set(-keyframe.change_in_value.get())


@dataclass
class CustomUnitAnim:
    metadata: CustomMaanimMetadata = field(
        default_factory=lambda: CustomMaanimMetadata()
    )
    parts: list[CustomKeyFrames] = field(default_factory=lambda: [])
    name: str = ""

    def read_csv(self, csv: "core.CSV"):
        self.metadata.read_csv(csv)
        index = 3
        self.parts = []
        for _ in range(self.metadata.total_parts.get()):
            part = CustomKeyFrames()
            index = part.read_csv(index, csv)
            self.parts.append(part)

    def apply_csv(self, csv: "core.CSV"):
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
class CustomModel(core.Modification):
    texture: CustomTexture = field(default_factory=lambda: CustomTexture())
    anims: list[CustomUnitAnim] = field(default_factory=lambda: [])
    mamodel: CustomMamodel = field(default_factory=lambda: CustomMamodel())

    def read_csv(
        self,
        img: Optional["core.NewBCImage"],
        imgcut_csv: Optional["core.CSV"],
        maanim_csvs: dict[str, "core.CSV"],
        mamodel_csv: Optional["core.CSV"],
    ):
        if imgcut_csv is not None:
            self.texture.read_csv(imgcut_csv)
        self.texture.image = img
        self.anims = []
        for name, maanim_csv in maanim_csvs.items():
            anim = CustomUnitAnim(name=name)
            anim.read_csv(maanim_csv)
            self.anims.append(anim)

        if mamodel_csv is not None:
            self.mamodel.read_csv(mamodel_csv)

    def apply_csv(
        self,
        imgcut_csv: "core.CSV",
        maanim_csvs: dict[str, "core.CSV"],
        mamodel_csv: "core.CSV",
        game_data: "core.GamePacks",
    ):
        self.texture.apply_csv(imgcut_csv, game_data)
        for anim in self.anims:
            maanim_csv = maanim_csvs.get(anim.name)
            if maanim_csv is not None:
                anim.apply_csv(maanim_csv)
        self.mamodel.apply_csv(mamodel_csv)

    def read(
        self,
        game_data: "core.GamePacks",
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

        maanim_csvs: dict[str, "core.CSV"] = {}
        for maanim_name in maanim_names:
            maanim_csv = game_data.get_csv(maanim_name)
            if maanim_csv is not None:
                maanim_csvs[maanim_name] = maanim_csv

        img = game_data.get_img(sprite_name)

        self.read_csv(img, texture_csv, maanim_csvs, mamodel_csv)

    def read_files(
        self,
        sprite_path: "core.Path",
        imgcut_path: "core.Path",
        maanim_paths: list["core.Path"],
        mamodel_path: "core.Path",
    ):
        self.texture.imgcut_name = imgcut_path.basename()
        self.texture.metadata.img_name.set(sprite_path.basename())
        texture_csv = core.CSV(imgcut_path.read())

        self.mamodel.mamodel_name = mamodel_path.basename()
        mamodel_csv = core.CSV(mamodel_path.read())

        maanim_csvs: dict[str, "core.CSV"] = {}
        for path in maanim_paths:
            maanim_csv = core.CSV(path.read())
            maanim_csvs[path.basename()] = maanim_csv

        self.read_csv(
            core.NewBCImage.from_file(sprite_path),
            texture_csv,
            maanim_csvs,
            mamodel_csv,
        )

    def apply(self, game_data: "core.GamePacks"):
        texture_csv = core.CSV()
        self.texture.apply_csv(texture_csv, game_data)
        game_data.set_csv(self.texture.imgcut_name, texture_csv)

        mamodel_csv = core.CSV()
        self.mamodel.apply_csv(mamodel_csv)
        game_data.set_csv(self.mamodel.mamodel_name, mamodel_csv)

        for maanim in self.anims:
            maanim_csv = core.CSV()
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

    def deepcopy(self) -> "CustomModel":
        return copy.deepcopy(self)

    def set_unit_form(self, form: str):
        self.texture.set_unit_form(form)
        self.mamodel.set_unit_form(form)
        for anim in self.anims:
            anim.set_unit_form(form)

    def set_id(self, id: int):
        id_str = core.PaddedInt(id, 3).to_str()
        self.texture.set_id(id_str)
        self.mamodel.set_id(id_str)
        for anim in self.anims:
            anim.set_id(id_str)
