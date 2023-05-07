from typing import Any, Optional, Union
from tbcml.core.anim import texture, unit_animation, model_part
from tbcml.core import io, game_data


class ModelMetaData:
    def __init__(self, head_name: str, version_code: int, total_parts: int):
        self.head_name = head_name
        self.version_code = version_code
        self.total_parts = total_parts

    @staticmethod
    def from_csv(csv: "io.bc_csv.CSV") -> "ModelMetaData":
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

    def to_csv(self, total_parts: int) -> "io.bc_csv.CSV":
        self.set_total_parts(total_parts)

        csv = io.bc_csv.CSV()
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


class MamodelLoaderInfo:
    def __init__(self, mamodel_name: str, game_packs: "game_data.pack.GamePacks"):
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
        meta_data: ModelMetaData,
        scale_unit: int,
        angle_unit: int,
        alpha_unit: int,
        ints: list[list[int]],
        parts: list[model_part.ModelPart],
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
    def load(
        mamodel_name: str, game_packs: "game_data.pack.GamePacks"
    ) -> Optional["Mamodel"]:
        mamodel_file = game_packs.find_file(mamodel_name)
        if mamodel_file is None:
            return None

        csv = mamodel_file.dec_data.to_csv()
        meta_data = ModelMetaData.from_csv(csv)
        total_parts = meta_data.total_parts

        parts: list[model_part.ModelPart] = []
        for i in range(total_parts):
            line_data = csv.read_line()
            if line_data is None:
                continue
            part = model_part.ModelPart.from_data(line_data, i)
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
                    part = model_part.ModelPart.create_empty(part_id)
                    part.apply_dict(data_part)
                    self.parts.append(part)

        comments = dict_data.get("comments")
        if comments is not None:
            self.comments = comments


class Model:
    def __init__(
        self,
        tex: Union[texture.TexLoaderInfo, texture.Texture],
        anims: list[Union[unit_animation.UnitAnim, unit_animation.UnitAnimLoaderInfo]],
        mamodel: Union[Mamodel, MamodelLoaderInfo],
        name: str,
    ):
        self.__tex = tex
        self.__anims = anims
        self.__mamodel = mamodel
        self.name = name

    def get_part(self, index: int) -> Optional[model_part.ModelPart]:
        if index < 0 or index >= len(self.mamodel.parts):
            return None
        return self.mamodel.parts[index]

    def get_sorted_parts(self) -> list[model_part.ModelPart]:
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
    def tex(self) -> texture.Texture:
        if isinstance(self.__tex, texture.TexLoaderInfo):
            self.__tex = self.__tex.load()
        return self.__tex

    @property
    def anims(self) -> list[unit_animation.UnitAnim]:
        for i, anim in enumerate(self.__anims):
            if isinstance(anim, unit_animation.UnitAnimLoaderInfo):
                anim = anim.load()
                if anim is None:
                    self.__anims[i] = unit_animation.UnitAnim.create_empty()
                else:
                    self.__anims[i] = anim
        return self.__anims  # type: ignore

    @property
    def mamodel(self) -> Mamodel:
        if isinstance(self.__mamodel, MamodelLoaderInfo):
            self.__mamodel = self.__mamodel.load()
        return self.__mamodel

    def tex_loaded(self) -> bool:
        return not isinstance(self.__tex, texture.TexLoaderInfo)

    def anims_loaded(self) -> bool:
        return all(
            not isinstance(anim, unit_animation.UnitAnimLoaderInfo)
            for anim in self.__anims
        )

    def mamodel_loaded(self) -> bool:
        return not isinstance(self.__mamodel, MamodelLoaderInfo)

    def copy(self) -> "Model":
        return Model(
            self.tex,
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
        game_packs: "game_data.pack.GamePacks",
    ):
        tex_loader = texture.TexLoaderInfo(img_name, imgcut_name, game_packs)
        anim_loaders: list[unit_animation.UnitAnimLoaderInfo] = []
        for maanim_name in maanim_names:
            anim = unit_animation.UnitAnimLoaderInfo(maanim_name, game_packs)
            anim_loaders.append(anim)

        mamodel_loader = MamodelLoaderInfo(mamodel_name, game_packs)

        model = Model(
            tex_loader,
            anim_loaders,  # type: ignore
            mamodel_loader,
            mamodel_name,
        )
        return model

    def save(
        self,
        game_packs: "game_data.pack.GamePacks",
    ):
        if self.tex_loaded():
            self.tex.save(game_packs)

        if self.anims_loaded():
            for anim in self.anims:
                anim.save(game_packs)

        if self.mamodel_loaded():
            mamodel_file = game_packs.find_file(self.name)
            if mamodel_file is None:
                return
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

    def get_total_parts(self) -> int:
        return len(self.mamodel.parts)

    def set_unit_id(self, unit_id: int):
        self.tex.set_unit_id(unit_id)
        for part in self.mamodel.parts:
            part.set_unit_id(unit_id)

    def set_unit_form(self, unit_form: str):
        self.tex.set_unit_form(unit_form)

    def is_empty(self) -> bool:
        return self.tex.is_empty()

    @staticmethod
    def create_empty() -> "Model":
        return Model(
            texture.Texture.create_empty(),
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
            for part_id, data_part in parts.items():
                part = self.get_part(part_id)
                if part is None:
                    part = model_part.ModelPart.create_empty(part_id)
                    self.mamodel.parts.append(part)
                part.apply_dict(data_part)

        mamodel = dict_data.get("mamodel")
        if mamodel is not None:
            self.mamodel.apply_dict(mamodel)

        tex = dict_data.get("tex")
        if tex is not None:
            self.tex.apply_dict(tex)

        anims = dict_data.get("anims")
        if anims is not None:
            for anim_id, data_anim in anims.items():
                anim = self.get_anim(anim_id)
                if anim is None:
                    anim = unit_animation.UnitAnim.create_empty()
                    self.anims.append(anim)
                anim.apply_dict(data_anim)

    def get_anim(self, anim_id: int) -> Optional[unit_animation.UnitAnim]:
        if anim_id < len(self.anims):
            return self.anims[anim_id]
        return None
