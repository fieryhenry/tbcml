from typing import Any, Optional, Union

from tbcml import core


class ModelMetaData:
    def __init__(self, head_name: str, version_code: int, total_parts: int):
        self.head_name = head_name
        self.version_code = version_code
        self.total_parts = total_parts

    @staticmethod
    def from_csv(csv: "core.CSV") -> "ModelMetaData":
        head_line = csv.read_line()
        if head_line is None:
            raise ValueError("Invalid model file")
        head_name = head_line[0]

        version_line = csv.read_line()
        if version_line is None:
            raise ValueError("Invalid model file")
        version_code = int(version_line[0])

        total_parts_line = csv.read_line()
        if total_parts_line is None:
            raise ValueError("Invalid model file")
        total_parts = int(total_parts_line[0])

        return ModelMetaData(head_name, version_code, total_parts)

    def to_csv(self, total_parts: int) -> "core.CSV":
        self.set_total_parts(total_parts)

        csv = core.CSV()
        csv.lines.append([self.head_name])
        csv.lines.append([str(self.version_code)])
        csv.lines.append([str(self.total_parts)])

        return csv

    def set_total_parts(self, total_parts: int):
        self.total_parts = total_parts

    def copy(self) -> "ModelMetaData":
        return ModelMetaData(
            self.head_name,
            self.version_code,
            self.total_parts,
        )

    @staticmethod
    def create_empty() -> "ModelMetaData":
        return ModelMetaData("", 0, 0)

    def apply_dict(self, dict_data: dict[str, Any]):
        head_name = dict_data.get("head_name")
        if head_name is not None:
            self.head_name = head_name

        version_code = dict_data.get("version_code")
        if version_code is not None:
            self.version_code = version_code

        total_parts = dict_data.get("total_parts")
        if total_parts is not None:
            self.total_parts = total_parts

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_name": self.head_name,
            "version_code": self.version_code,
            "total_parts": self.total_parts,
        }


class MamodelLoaderInfo:
    def __init__(self, mamodel_name: str, game_packs: "core.GamePacks"):
        self.mamodel_name = mamodel_name
        self.game_packs = game_packs

    def load(self) -> "Mamodel":
        mamodel = Mamodel.load(self.mamodel_name, self.game_packs)
        if mamodel is None:
            return Mamodel.create_empty()
        return mamodel


class Mamodel:
    def __init__(
        self,
        meta_data: "ModelMetaData",
        scale_unit: int,
        angle_unit: int,
        alpha_unit: int,
        ints: list[list[int]],
        parts: list["core.ModelPart"],
        comments: list[str],
    ):
        self.meta_data = meta_data
        self.scale_unit = scale_unit
        self.angle_unit = angle_unit
        self.alpha_unit = alpha_unit
        self.ints = ints
        self.parts = parts
        self.comments = comments

    def copy(self) -> "Mamodel":
        return Mamodel(
            self.meta_data.copy(),
            self.scale_unit,
            self.angle_unit,
            self.alpha_unit,
            self.ints,
            [part.copy() for part in self.parts],
            self.comments.copy(),
        )

    @staticmethod
    def create_empty() -> "Mamodel":
        return Mamodel(ModelMetaData.create_empty(), 0, 0, 0, [], [], [])

    @staticmethod
    def load(mamodel_name: str, game_packs: "core.GamePacks") -> Optional["Mamodel"]:
        mamodel_file = game_packs.find_file(mamodel_name)
        if mamodel_file is None:
            return None
        return Mamodel.from_data(mamodel_file.dec_data)

    @staticmethod
    def from_data(mamodel_data: "core.Data") -> Optional["Mamodel"]:
        csv = mamodel_data.to_csv()
        meta_data = ModelMetaData.from_csv(csv)
        total_parts = meta_data.total_parts

        parts: list[core.ModelPart] = []
        for i in range(total_parts):
            line_data = csv.read_line()
            if line_data is None:
                continue
            part = core.ModelPart.from_data(line_data, i)
            parts.append(part)

        units_line = csv.read_line()
        if units_line is None:
            return None

        scale_unit = int(units_line[0])
        angle_unit = int(units_line[1])
        alpha_unit = int(units_line[2])

        ints: list[list[int]] = []
        total_ints_line = csv.read_line()
        if total_ints_line is None:
            return None
        total_ints = int(total_ints_line[0])
        comments: list[str] = []

        for _ in range(total_ints):
            line_data = csv.read_line()
            if line_data is None:
                continue
            comment = ""
            if len(line_data) == 7:
                comment = line_data[6]
            ints.append([int(x) for x in line_data[:6]])
            comments.append(comment)

        mamodel = Mamodel(
            meta_data, scale_unit, angle_unit, alpha_unit, ints, parts, comments
        )
        return mamodel

    def to_data(self) -> "core.Data":
        csv = self.meta_data.to_csv(len(self.parts))
        for part in self.parts:
            csv.lines.append(part.to_data())

        csv.lines.append(
            [
                str(self.scale_unit),
                str(self.angle_unit),
                str(self.alpha_unit),
            ]
        )

        csv.lines.append([str(len(self.ints))])
        for i, ints in enumerate(self.ints):
            csv.lines.append([str(x) for x in ints])
            if self.comments[i]:
                csv.lines[-1].append(self.comments[i])

        return csv.to_data()

    def apply_dict(self, dict_data: dict[str, Any]):
        meta_data = dict_data.get("meta_data")
        if meta_data is not None:
            self.meta_data.apply_dict(meta_data)

        scale_unit = dict_data.get("scale_unit")
        if scale_unit is not None:
            self.scale_unit = scale_unit

        angle_unit = dict_data.get("angle_unit")
        if angle_unit is not None:
            self.angle_unit = angle_unit

        alpha_unit = dict_data.get("alpha_unit")
        if alpha_unit is not None:
            self.alpha_unit = alpha_unit

        ints = dict_data.get("ints")
        if ints is not None:
            self.ints = ints

        parts = dict_data.get("parts")
        if parts is not None:
            for part_id, data_part in parts.items():
                part_id = int(part_id)
                if part_id < len(self.parts):
                    self.parts[part_id].apply_dict(data_part)
                else:
                    part = core.ModelPart.create_empty(part_id)
                    part.apply_dict(data_part)
                    self.parts.append(part)

        comments = dict_data.get("comments")
        if comments is not None:
            self.comments = comments

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta_data": self.meta_data.to_dict(),
            "scale_unit": self.scale_unit,
            "angle_unit": self.angle_unit,
            "alpha_unit": self.alpha_unit,
            "ints": self.ints,
            "parts": {str(part.index): part.to_dict() for part in self.parts},
            "comments": self.comments,
        }


class Model:
    def __init__(
        self,
        tex: Union["core.TexLoaderInfo", "core.Texture"],
        anims: list[Union["core.UnitAnim", "core.UnitAnimLoaderInfo"]],
        mamodel: Union[Mamodel, MamodelLoaderInfo],
        name: str,
    ):
        self.__tex = tex
        self.__anims = anims
        self.__mamodel = mamodel
        self.name = name

    def get_part(self, index: int) -> Optional["core.ModelPart"]:
        if index < 0 or index >= len(self.mamodel.parts):
            return None
        return self.mamodel.parts[index]

    def get_part_create(self, index: int) -> "core.ModelPart":
        if index < 0 or index >= len(self.mamodel.parts):
            part = core.ModelPart.create_empty(index)
            self.set_part(index, part)
        return self.mamodel.parts[index]

    def set_part(self, index: int, part: "core.ModelPart"):
        part.index = index
        if index < 0:
            return
        if index >= len(self.mamodel.parts):
            self.mamodel.parts.append(part)
        else:
            self.mamodel.parts[index] = part

    def get_sorted_parts(self) -> list["core.ModelPart"]:
        return sorted(self.mamodel.parts, key=lambda part: part.z_depth)

    def set_models(self):
        for part in self.mamodel.parts:
            part.set_model(self)

    def set_parents(self):
        for part in self.mamodel.parts:
            if part.parent_id != -1:
                pp = self.get_part(part.parent_id)
                if pp is not None:
                    part.set_parent(pp)

    def set_children(self):
        for part in self.mamodel.parts:
            part.set_children(self.mamodel.parts)

    def set_units(self):
        for part in self.mamodel.parts:
            part.set_units(
                self.mamodel.scale_unit,
                self.mamodel.angle_unit,
                self.mamodel.alpha_unit,
            )

    def set_ints(self):
        for part in self.mamodel.parts:
            part.set_ints(self.mamodel.ints)

    def set_required(self):
        self.set_models()
        self.set_parents()
        self.set_children()
        self.set_units()
        self.set_ints()
        self.tex.split_cuts()
        self.load_texs()

    def load_texs(self):
        for part in self.mamodel.parts:
            part.load_texs()

    def set_keyframes_sets(self, anim_index: int):
        for part in self.mamodel.parts:
            anim_parts = self.anims[anim_index].get_parts(part.index)
            part.set_keyframes_sets(anim_parts)

    @property
    def tex(self) -> "core.Texture":
        if isinstance(self.__tex, core.TexLoaderInfo):
            self.__tex = self.__tex.load()
        return self.__tex

    @property
    def anims(self) -> list["core.UnitAnim"]:
        anims: list["core.UnitAnim"] = []
        for i, anim in enumerate(self.__anims):
            if isinstance(anim, core.UnitAnimLoaderInfo):
                anim = anim.load()
                if anim is not None:
                    self.__anims[i] = anim
                    anims.append(anim)
            else:
                anims.append(anim)
        return anims

    @property
    def mamodel(self) -> Mamodel:
        if isinstance(self.__mamodel, MamodelLoaderInfo):
            self.__mamodel = self.__mamodel.load()
        return self.__mamodel

    def tex_loaded(self) -> bool:
        return not isinstance(self.__tex, core.TexLoaderInfo)

    def anims_loaded(self) -> bool:
        return any(
            not isinstance(anim, core.UnitAnimLoaderInfo) for anim in self.__anims
        )

    def mamodel_loaded(self) -> bool:
        return not isinstance(self.__mamodel, MamodelLoaderInfo)

    def copy(self) -> "Model":
        return Model(
            self.tex.copy(),
            [anim.copy() for anim in self.anims],
            self.mamodel.copy(),
            self.name,
        )

    @staticmethod
    def load(
        mamodel_name: str,
        imgcut_name: str,
        img_name: str,
        maanim_names: list[str],
        game_packs: "core.GamePacks",
    ):
        tex_loader = core.TexLoaderInfo(img_name, imgcut_name, game_packs)
        anim_loaders: list[core.UnitAnimLoaderInfo] = []
        for maanim_name in maanim_names:
            anim = core.UnitAnimLoaderInfo(maanim_name, game_packs)
            anim_loaders.append(anim)

        mamodel_loader = MamodelLoaderInfo(mamodel_name, game_packs)

        model = Model(
            tex_loader,
            anim_loaders,  # type: ignore
            mamodel_loader,
            mamodel_name,
        )
        return model

    @staticmethod
    def from_data(
        mamodel_data: "core.Data",
        mamodel_name: str,
        imgcut_data: "core.Data",
        imgcut_name: str,
        img_data: "core.Data",
        img_name: str,
        maanim_datas: list["core.Data"],
        maanim_names: list[str],
    ):
        tex = core.Texture.from_data(imgcut_data, img_data, img_name, imgcut_name)
        anims: list[core.UnitAnim] = []
        for maanim_data, maanim_name in zip(maanim_datas, maanim_names):
            anim = core.UnitAnim.from_data(maanim_name, maanim_data)
            anims.append(anim)

        mamodel = Mamodel.from_data(mamodel_data)
        if mamodel is None:
            mamodel = Mamodel.create_empty()
        model = Model(tex, anims, mamodel, mamodel_name)  # type: ignore
        return model

    def save(
        self,
        game_packs: "core.GamePacks",
    ):
        if self.tex_loaded():
            self.tex.save(game_packs)

        if self.anims_loaded():
            for anim in self.anims:
                anim.save(game_packs)

        if self.mamodel_loaded():
            csv = self.mamodel.meta_data.to_csv(self.get_total_parts())
            for part in self.mamodel.parts:
                csv.lines.append(part.to_data())

            csv.lines.append(
                [
                    str(self.mamodel.scale_unit),
                    str(self.mamodel.angle_unit),
                    str(self.mamodel.alpha_unit),
                ]
            )
            csv.lines.append([str(len(self.mamodel.ints))])
            for i, ints in enumerate(self.mamodel.ints):
                csv.lines.append([str(x) for x in ints])
                if self.mamodel.comments[i]:
                    csv.lines[-1].append(self.mamodel.comments[i])

            game_packs.set_file(self.name, csv.to_data())

    def to_data(self) -> dict[str, Any]:
        data = {
            "tex": self.tex.to_data(),
            "anims": [anim.to_data() for anim in self.anims],
            "mamodel": self.mamodel.to_data(),
        }
        return data

    def get_total_parts(self) -> int:
        return len(self.mamodel.parts)

    def set_unit_id(self, unit_id: int):
        self.tex.set_unit_id(unit_id)
        name = self.name
        parts = name.split("_")
        parts[0] = core.PaddedInt(unit_id, 3).to_str()
        name = "_".join(parts)
        self.name = name
        for part in self.mamodel.parts[1:]:
            part.set_unit_id(unit_id)
        for anim in self.anims:
            anim.set_unit_id(unit_id)

    def set_unit_form(self, unit_form: str):
        self.tex.set_unit_form(unit_form)
        name = self.name
        parts = name.split("_")
        cat_id = parts[0]
        self.name = f"{cat_id}_{unit_form}.mamodel"
        _ = self.mamodel
        _ = self.anims
        for anim in self.anims:
            anim.set_unit_form(unit_form)

    def is_empty(self) -> bool:
        return self.tex.is_empty()

    @staticmethod
    def create_empty() -> "Model":
        return Model(
            core.Texture.create_empty(),
            [],
            Mamodel.create_empty(),
            "",
        )

    def set_action(self, frame_counter: int):
        for part in self.mamodel.parts:
            for keyframes in part.keyframes_sets:
                part.set_action(frame_counter, keyframes)

    def get_end_frame(self) -> int:
        end_frame = 1
        for part in self.mamodel.parts:
            end_frame = max(end_frame, part.get_end_frame())
        return end_frame

    def get_total_frames(self) -> int:
        return self.get_end_frame() + 1

    def apply_dict(self, dict_data: dict[str, Any]):
        parts = dict_data.get("parts")
        if parts is not None:
            current_parts = {part.index: part for part in self.mamodel.parts}
            mod_parts = core.ModEditDictHandler(parts, current_parts).get_dict(
                convert_int=True
            )
            for part_id, data_part in mod_parts.items():
                part = self.get_part_create(part_id)
                part.apply_dict(data_part)

        mamodel = dict_data.get("mamodel")
        if mamodel is not None:
            self.mamodel.apply_dict(mamodel)

        name = dict_data.get("name")
        if name is not None:
            self.name = name

        tex = dict_data.get("tex")
        if tex is not None:
            self.tex.apply_dict(tex)

        anims = dict_data.get("anims")
        if anims is not None:
            current_anims = {i: anim for i, anim in enumerate(self.anims)}
            mod_anims = core.ModEditDictHandler(anims, current_anims).get_dict(
                convert_int=True
            )
            for anim_id, data_anim in mod_anims.items():
                anim = self.get_anim(anim_id)
                if anim is None:
                    anim = core.UnitAnim.create_empty()
                    self.anims.append(anim)
                anim.apply_dict(data_anim)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "parts": {part.index: part.to_dict() for part in self.mamodel.parts},
            "mamodel": self.mamodel.to_dict(),
            "tex": self.tex.to_dict(),
            "anims": {i: anim.to_dict() for i, anim in enumerate(self.anims)},
            "name": self.name,
        }
        return data

    def get_anim(self, anim_id: int) -> Optional["core.UnitAnim"]:
        if anim_id < len(self.anims):
            return self.anims[anim_id]
        return None

    def flip_x(self):
        for part in self.mamodel.parts:
            part.flip_x()
        for anim in self.anims:
            anim.flip_x()

    def flip_y(self):
        for part in self.mamodel.parts:
            part.flip_y()
        for anim in self.anims:
            anim.flip_y()
