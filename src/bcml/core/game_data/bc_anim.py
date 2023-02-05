import enum
from typing import Any, Optional, Union
from bcml.core.game_data import pack
from bcml.core import io


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


class MaanimMove:
    def __init__(self, frame: int, change_in_value: int, ease: int, ease_power: int):
        self.frame = frame
        self.change_in_value = change_in_value
        self.ease = ease
        self.ease_power = ease_power

    @staticmethod
    def from_data(data: list["io.data.Data"]):
        frame = data[0].to_int()
        change_in_value = data[1].to_int()
        ease = data[2].to_int()
        ease_power = data[3].to_int()
        return MaanimMove(frame, change_in_value, ease, ease_power)

    def serialize(self) -> dict[str, Any]:
        return {
            "frame": self.frame,
            "change_in_value": self.change_in_value,
            "ease": self.ease,
            "ease_power": self.ease_power,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return MaanimMove(
            data["frame"], data["change_in_value"], data["ease"], data["ease_power"]
        )

    def copy(self):
        return MaanimMove(self.frame, self.change_in_value, self.ease, self.ease_power)

    def to_data(self) -> list["io.data.Data"]:
        ls: list[int] = [self.frame, self.change_in_value, self.ease, self.ease_power]
        return io.data.Data.int_list_data_list(ls)


class ModificationType(enum.Enum):
    PARENT = 0
    ID = 1
    SPRITE = 2
    Z_ORDER = 3
    POS_X = 4
    POS_Y = 5
    PIVOT_X = 6
    PIVOT_Y = 7
    SCALE = 8
    SCALE_X = 9
    SCALE_Y = 10
    ANGLE = 11
    OPACITY = 12
    H_FLIP = 13
    V_FLIP = 14
    EXTEND_X = 50
    EXTEND_Y = 52


class MaanimPart:
    def __init__(
        self,
        model_id: int,
        modification_type: ModificationType,
        loop: int,
        min_value: int,
        max_value: int,
        name: str,
        moves: list[MaanimMove],
        end_index: int = 0,
    ):
        self.model_id = model_id
        self.modification_type = modification_type
        self.loop = loop
        self.min_value = min_value
        self.max_value = max_value
        self.name = name
        self.moves = moves
        self.end_index = end_index

    @staticmethod
    def from_data(data: list[list["io.data.Data"]]):
        model_id = data[0][0].to_int()
        modification_type = ModificationType(data[0][1].to_int())
        loop = data[0][2].to_int()
        min_value = data[0][3].to_int()
        max_value = data[0][4].to_int()
        try:
            name = data[0][5].to_str()
        except IndexError:
            name = ""

        total_moves = data[1][0].to_int()
        end_index = 2
        moves: list[MaanimMove] = []
        for _ in range(total_moves):
            moves.append(MaanimMove.from_data(data[end_index]))
            end_index += 1

        return MaanimPart(
            model_id,
            modification_type,
            loop,
            min_value,
            max_value,
            name,
            moves,
            end_index,
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "modification_type": self.modification_type.value,
            "loop": self.loop,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "name": self.name,
            "moves": [move.serialize() for move in self.moves],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return MaanimPart(
            data["model_id"],
            ModificationType(data["modification_type"]),
            data["loop"],
            data["min_value"],
            data["max_value"],
            data["name"],
            [MaanimMove.deserialize(move) for move in data["moves"]],
        )

    def copy(self):
        return MaanimPart(
            self.model_id,
            self.modification_type,
            self.loop,
            self.min_value,
            self.max_value,
            self.name,
            [move.copy() for move in self.moves],
        )

    def to_data(self) -> list[list["io.data.Data"]]:
        ls: list[list[Any]] = [
            [
                self.model_id,
                self.modification_type.value,
                self.loop,
                self.min_value,
                self.max_value,
            ],
            [len(self.moves)],
        ]
        if self.name:
            ls[0].append(self.name)
        new_ls: list[list["io.data.Data"]] = []
        for i in ls:
            new_ls.append(io.data.Data.string_list_data_list(i))
        for move in self.moves:
            new_ls.append(move.to_data())
        return new_ls

    def flip(self):
        if self.modification_type == ModificationType.ANGLE:
            for move in self.moves:
                move.change_in_value *= -1

    def get_max_frame(self) -> int:
        if not self.moves:
            return 0
        return max(move.frame for move in self.moves)


class Maanim:
    def __init__(self, parts: list[MaanimPart], name: str):
        self.parts = parts
        self.name = name

    def is_empty(self) -> bool:
        return not self.parts

    @staticmethod
    def from_data(data: "io.data.Data", name: str):
        csv = io.bc_csv.CSV(data)
        csv.read_line()
        csv.read_line()
        total_parts_d = csv.read_line()
        if total_parts_d is None:
            return Maanim([], name)

        total_parts = total_parts_d[0].to_int()
        parts: list[MaanimPart] = []
        start_index = 3
        for _ in range(total_parts):
            part = MaanimPart.from_data(csv.lines[start_index:])
            parts.append(part)
            start_index += part.end_index

        return Maanim(parts, name)

    def serialize(self) -> dict[str, Any]:
        return {
            "parts": [part.serialize() for part in self.parts],
            "name": self.name,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        return Maanim(
            [MaanimPart.deserialize(part) for part in data["parts"]], data["name"]
        )

    def copy(self):
        return Maanim([part.copy() for part in self.parts], self.name)

    def to_data(self) -> "io.data.Data":
        csv = io.bc_csv.CSV()
        csv.add_line(["[modelanim:animation]"])
        csv.add_line(["1"])
        csv.add_line([len(self.parts)])
        for part in self.parts:
            for line in part.to_data():
                csv.add_line(line)

        return csv.to_data()

    def flip(self):
        for part in self.parts:
            part.flip()

    def get_max_frame(self) -> int:
        return max(part.get_max_frame() for part in self.parts)

    def remove_loop_minus_one(
        self,
    ):  # for enemy attack anims only, bcu allows -1 loop, the game does not
        max_frame = self.get_max_frame()
        for part in self.parts:
            if part.loop != -1:
                continue
            part_max_frame = part.get_max_frame()
            if part_max_frame == 0:
                part.loop = 1
            else:
                part.loop = max_frame // part_max_frame


class MamodelPart:
    def __init__(
        self,
        index: int,
        parent_id: int,
        unit_id: int,
        cut_id: int,
        z_depth: int,
        x: int,
        y: int,
        pivot_x: int,
        pivot_y: int,
        scale_x: int,
        scale_y: int,
        rotation: int,
        alpha: int,
        glow: int,
        name: str,
        cut: "Cut",
    ):
        self.index = index
        self.parent_id = parent_id
        self.unit_id = unit_id
        self.cut_id = cut_id
        self.z_depth = z_depth
        self.x = x
        self.y = y
        self.pivot_x = pivot_x
        self.pivot_y = pivot_y
        self.scale_x = scale_x
        self.scale_y = scale_y
        self.rotation = rotation
        self.alpha = alpha
        self.glow = glow
        self.name = name
        self.parent: Optional["MamodelPart"] = None
        self.children: list["MamodelPart"] = []
        self.cut = cut
        self.real_x: int = 0
        self.real_y: int = 0
        self.real_rotation: int = 0
        self.real_alpha: float = 1
        self.real_scale_x: float = 1
        self.real_scale_y: float = 1

    @staticmethod
    def from_data(data: list["io.data.Data"], cuts: list["Cut"], index: int):
        parent_id = data[0].to_int()
        unit_id = data[1].to_int()
        cut_id = data[2].to_int()
        z_depth = data[3].to_int()
        x = data[4].to_int()
        y = data[5].to_int()
        pivot_x = data[6].to_int()
        pivot_y = data[7].to_int()
        scale_x = data[8].to_int()
        scale_y = data[9].to_int()
        rotation = data[10].to_int()
        alpha = data[11].to_int()
        glow = data[12].to_int()
        try:
            name = data[13].to_str()
        except IndexError:
            name = ""

        return MamodelPart(
            index,
            parent_id,
            unit_id,
            cut_id,
            z_depth,
            x,
            y,
            pivot_x,
            pivot_y,
            scale_x,
            scale_y,
            rotation,
            alpha,
            glow,
            name,
            cuts[cut_id],
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "parent_id": self.parent_id,
            "unit_id": self.unit_id,
            "cut_id": self.cut_id,
            "z_depth": self.z_depth,
            "x": self.x,
            "y": self.y,
            "pivot_x": self.pivot_x,
            "pivot_y": self.pivot_y,
            "scale_x": self.scale_x,
            "scale_y": self.scale_y,
            "rotation": self.rotation,
            "alpha": self.alpha,
            "glow": self.glow,
            "name": self.name,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cuts: list["Cut"]):
        return MamodelPart(
            data["index"],
            data["parent_id"],
            data["unit_id"],
            data["cut_id"],
            data["z_depth"],
            data["x"],
            data["y"],
            data["pivot_x"],
            data["pivot_y"],
            data["scale_x"],
            data["scale_y"],
            data["rotation"],
            data["alpha"],
            data["glow"],
            data["name"],
            cuts[data["cut_id"]],  # type: ignore
        )

    def copy(self):
        return MamodelPart(
            self.index,
            self.parent_id,
            self.unit_id,
            self.cut_id,
            self.z_depth,
            self.x,
            self.y,
            self.pivot_x,
            self.pivot_y,
            self.scale_x,
            self.scale_y,
            self.rotation,
            self.alpha,
            self.glow,
            self.name,
            self.cut,
        )

    def to_data(self) -> list["io.data.Data"]:
        ls: list[Any] = [
            self.parent_id,
            self.unit_id,
            self.cut_id,
            self.z_depth,
            self.x,
            self.y,
            self.pivot_x,
            self.pivot_y,
            self.scale_x,
            self.scale_y,
            self.rotation,
            self.alpha,
            self.glow,
        ]
        if self.name:
            ls.append(self.name)

        return io.data.Data.string_list_data_list(ls)

    def flip(self):
        self.rotation *= -1

    def set_parent(self, all_parts: list["MamodelPart"]):
        if self.parent_id != -1:
            self.parent = all_parts[self.parent_id]

    def set_children(self, all_parts: list["MamodelPart"]):
        for part in all_parts:
            if part.parent_id == self.index:
                self.children.append(part)


class Mamodel:
    def __init__(
        self,
        parts: list[MamodelPart],
        maxes: list[int],
        ints: list[list[int]],
        comments: list[str],
        custs: list["Cut"],
    ):
        self.parts = parts
        self.maxes = maxes
        self.ints = ints
        self.comments = comments
        self.cuts = custs

    @staticmethod
    def create_empty():
        return Mamodel([], [], [], [], [])

    def is_empty(self):
        return len(self.parts) == 0

    def flip_x(self):
        try:
            self.parts[0].scale_x *= -1
        except IndexError:
            pass
        for part in self.parts:
            part.flip()

    def flip_y(self):
        try:
            self.parts[0].scale_y *= -1
        except IndexError:
            pass
        for part in self.parts:
            part.flip()

    @staticmethod
    def from_data(data: "io.data.Data", cuts: list["Cut"]):
        csv = io.bc_csv.CSV(data)
        csv.read_line()
        csv.read_line()
        total_parts_d = csv.read_line()
        if total_parts_d is None:
            return Mamodel([], [], [], [], cuts)

        total_parts = total_parts_d[0].to_int()
        parts: list[MamodelPart] = []
        for i in range(total_parts):
            line_data = csv.read_line()
            if line_data is None:
                break
            parts.append(MamodelPart.from_data(line_data, cuts, i))

        for part in parts:
            part.set_parent(parts)

        maxes_d = csv.read_line()
        if maxes_d is None:
            return Mamodel(parts, [], [], [], cuts)

        maxes = io.data.Data.data_list_int_list(maxes_d)

        total_ints_d = csv.read_line()
        if total_ints_d is None:
            return Mamodel(parts, maxes, [], [], cuts)

        total_ints = total_ints_d[0].to_int()
        ints: list[list[int]] = []
        comments: list[str] = []
        for _ in range(total_ints):
            line_data = csv.read_line()
            if line_data is None:
                break
            if len(line_data) == 7:
                comment = line_data[6].to_str()
                line_data = line_data[:6]
            else:
                comment = ""

            line_data_i = io.data.Data.data_list_int_list(line_data)
            comments.append(comment)
            ints.append(line_data_i)

        return Mamodel(parts, maxes, ints, comments, cuts)

    def serialize(self) -> dict[str, Any]:
        return {
            "parts": [part.serialize() for part in self.parts],
            "maxes": self.maxes,
            "ints": self.ints,
            "comments": self.comments,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], cuts: list["Cut"]):
        return Mamodel(
            [MamodelPart.deserialize(part, cuts) for part in data["parts"]],
            data["maxes"],
            data["ints"],
            data["comments"],
            cuts,
        )

    def to_data(self) -> "io.data.Data":
        csv = io.bc_csv.CSV()
        csv.add_line(["[modelanim:model]"])
        csv.add_line(["3"])
        csv.add_line([len(self.parts)])
        for part in self.parts:
            csv.add_line(part.to_data())

        csv.add_line(self.maxes)
        csv.add_line([len(self.ints)])
        for i, line in enumerate(self.ints):
            csv.add_line(line)
            if self.comments[i]:
                csv.lines[-1].append(io.data.Data(self.comments[i]))

        return csv.to_data()

    def copy(self):
        return Mamodel(
            [part.copy() for part in self.parts],
            self.maxes.copy(),
            self.ints.copy(),
            self.comments.copy(),
            self.cuts.copy(),
        )

    def fix_collision(self):
        if len(self.ints) != 1:
            return
        self.ints.append(self.ints[0].copy())
        self.comments.append("")


class Cut:
    def __init__(
        self,
        index: int,
        x: int,
        y: int,
        width: int,
        height: int,
        name: str,
    ):
        self.index = index
        self.x = x
        self.y = y
        self.__width = width
        self.__height = height
        self.name = name
        self.image: Optional["io.bc_image.BCImage"] = None

    def get_image(self, image: "io.bc_image.BCImage"):
        if self.width == 0 or self.height == 0:
            self.image = io.bc_image.BCImage.from_size(0, 0)
        else:
            self.image = image.crop(
                self.x, self.y, self.x + self.width, self.y + self.height
            )
        return self.image

    @staticmethod
    def from_data(data: list["io.data.Data"], index: int):
        try:
            name = data[4].to_str()
        except IndexError:
            name = ""
        return Cut(
            index,
            data[0].to_int(),
            data[1].to_int(),
            data[2].to_int(),
            data[3].to_int(),
            name,
        )

    def serialize(self, img: bool = False) -> dict[str, Any]:
        return {
            "index": self.index,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "name": self.name,
            "image": self.image.serialize() if img and self.image else None,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        cut = Cut(
            data["index"],
            data["x"],
            data["y"],
            data["width"],
            data["height"],
            data["name"],
        )
        if data["image"]:
            cut.image = io.bc_image.BCImage.deserialize(data["image"])
        return cut

    def to_data(self) -> list["io.data.Data"]:
        return [
            io.data.Data(self.x),
            io.data.Data(self.y),
            io.data.Data(self.width),
            io.data.Data(self.height),
            io.data.Data(self.name),
        ]

    def copy(self):
        return Cut(
            self.index,
            self.x,
            self.y,
            self.width,
            self.height,
            self.name,
        )

    @property
    def width(self) -> int:
        if self.image:
            return self.image.width
        return self.__width

    @property
    def height(self) -> int:
        if self.image:
            return self.image.height
        return self.__height


class Imgcut:
    def __init__(
        self,
        cuts: list["Cut"],
        image_name: str,
        image: "io.bc_image.BCImage",
    ):
        self.__cuts = cuts
        self.image_name = image_name
        self.image = image

    @property
    def cuts(self) -> list["Cut"]:
        return self.reorder_cuts(self.__cuts)

    @cuts.setter
    def cuts(self, value: list["Cut"]):
        cuts = self.reorder_cuts(value)
        self.__cuts = cuts

    def is_empty(self):
        return len(self.cuts) == 0

    @staticmethod
    def create_empty():
        return Imgcut([], "", io.bc_image.BCImage.create_empty())

    @staticmethod
    def from_data(data: "io.data.Data", image: "io.bc_image.BCImage"):
        csv = io.bc_csv.CSV(data)
        csv.read_line()
        csv.read_line()
        img_name_d = csv.read_line()
        if img_name_d is None:
            return Imgcut([], "", image)

        img_name = img_name_d[0].to_str()
        total_cuts_d = csv.read_line()
        if total_cuts_d is None:
            return Imgcut([], img_name, image)

        total_cuts = total_cuts_d[0].to_int()
        cuts: list[Cut] = []
        for i in range(total_cuts):
            line_data = csv.read_line()
            if line_data is None:
                break
            cuts.append(Cut.from_data(line_data, i))

        return Imgcut(cuts, img_name, image)

    def serialize(self) -> dict[str, Any]:
        return {
            "cuts": [cut.serialize() for cut in self.cuts],
            "image_name": self.image_name,
            "image": self.image.serialize(),
        }

    def serialize_no_cuts(self) -> dict[str, Any]:
        return {
            "image_name": self.image_name,
            "image": self.image.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        image = io.bc_image.BCImage.deserialize(data["image"])
        return Imgcut(
            [Cut.deserialize(cut) for cut in data["cuts"]],
            data["image_name"],
            image,
        )

    @staticmethod
    def deserialize_no_cuts(data: dict[str, Any], cuts: list[Cut]):
        image = io.bc_image.BCImage.deserialize(data["image"])
        return Imgcut(
            cuts,
            data["image_name"],
            image,
        )

    def to_data(self) -> tuple["io.data.Data", "io.data.Data"]:
        csv = io.bc_csv.CSV()
        csv.add_line(["[imgcut]"])
        csv.add_line(["0"])
        csv.add_line([self.image_name])
        csv.add_line([len(self.cuts)])
        for cut in self.cuts:
            csv.add_line(cut.to_data())

        return csv.to_data(), self.image.to_data()

    def copy(self):
        return Imgcut(
            [cut.copy() for cut in self.cuts],
            self.image_name,
            self.image,
        )

    def reconstruct_image(self):
        max_width = 0
        max_height = 0
        for cut in self.cuts:
            max_width = max(max_width, cut.x + cut.width)
            max_height = max(max_height, cut.y + cut.height)

        self.image = io.bc_image.BCImage.from_size(max_width, max_height)
        for cut in self.cuts:
            if cut.image is None:
                continue
            self.image.paste(cut.image, cut.x, cut.y)

    @staticmethod
    def from_cuts(cuts: list["Cut"], imgname: str):
        imgcut = Imgcut([], imgname, io.bc_image.BCImage.create_empty())
        imgcut.cuts = cuts
        imgcut.reconstruct_image()
        return imgcut

    @staticmethod
    def reorder_cuts(cuts: list["Cut"]) -> list["Cut"]:
        cuts.sort(key=lambda cut: cut.index)
        for i in range(len(cuts)):
            cuts[i].index = i
        return cuts

    def get_cut(self, index: int) -> Optional["Cut"]:
        if index >= len(self.cuts):
            return None
        return self.cuts[index]

    def remove_cut(self, index: int):
        if index >= len(self.cuts):
            return
        self.cuts.pop(index)
        for i in range(index, len(self.cuts)):
            self.cuts[i].index = i

    def add_cut(self, cut: "Cut"):
        cut.index = len(self.cuts)
        self.cuts.append(cut)

    def set_cut(self, id: int, cut: "Cut"):
        if id >= len(self.cuts):
            self.add_cut(cut)
            return
        cut.index = id
        self.cuts[id] = cut

    def set_cuts(self, cuts: list["Cut"]):
        self.cuts = cuts
        for i in range(len(cuts)):
            cuts[i].index = i

    @staticmethod
    def regenerate_cuts(cuts: list["Cut"]):
        c_x = 0
        for cut in cuts:
            cut.x = c_x
            c_x += cut.width
            cut.y = 0

        return cuts


class Anim:
    def __init__(
        self,
        imgcut: Optional["Imgcut"],
        mamodel: Optional["Mamodel"],
        maanims: Optional[list["Maanim"]],
        imgcut_path: Optional[str] = None,
        png_path: Optional[str] = None,
        mamodel_path: Optional[str] = None,
        maanims_path: Optional[list[str]] = None,
        game_data: Optional["pack.GamePacks"] = None,
    ):
        self.__imgcut = imgcut
        self.__mamodel = mamodel
        self.__maanims = maanims
        self.__imgcut_path = imgcut_path
        self.__png_path = png_path
        self.__mamodel_path = mamodel_path
        self.__maanims_path = maanims_path
        self.__game_data = game_data

    @property
    def maanims(self):
        if (
            self.__maanims_path is not None
            and self.__maanims is None
            and self.__game_data is not None
        ):
            maanims: list[Maanim] = []
            for path in self.__maanims_path:
                data = self.__game_data.find_file(path)
                if data is None:
                    raise Exception("Maanim not found")
                maanims.append(Maanim.from_data(data.dec_data, path))
            self.__maanims = maanims
            self.__maanims_path = None
        if self.__maanims is None:
            raise Exception("Maanims not loaded")
        return self.__maanims

    @property
    def imgcut(self):
        if (
            self.__imgcut_path is not None
            and self.__imgcut is None
            and self.__game_data is not None
            and self.__png_path is not None
        ):
            data = self.__game_data.find_file(self.__imgcut_path)
            if data is None:
                raise Exception("Imgcut not found")
            png_data = self.__game_data.find_file(self.__png_path)
            if png_data is None:
                raise Exception("PNG not found")
            self.__imgcut = Imgcut.from_data(
                data.dec_data, io.bc_image.BCImage(png_data.dec_data)
            )
            self.__imgcut_path = None
        if self.__imgcut is None:
            raise Exception("Imgcut not loaded")
        return self.__imgcut

    @property
    def mamodel(self):
        if (
            self.__mamodel_path is not None
            and self.__mamodel is None
            and self.__game_data is not None
        ):
            data = self.__game_data.find_file(self.__mamodel_path)
            if data is None:
                raise Exception("Mamodel not found")
            self.__mamodel = Mamodel.from_data(data.dec_data, self.imgcut.cuts)
            self.__mamodel_path = None
        if self.__mamodel is None:
            raise Exception("Mamodel not loaded")
        return self.__mamodel

    @staticmethod
    def create_empty():
        return Anim(
            Imgcut.create_empty(),
            Mamodel.create_empty(),
            [],
        )

    def is_empty(self):
        return (
            self.imgcut.is_empty()
            and self.mamodel.is_empty()
            and len(self.maanims) == 0
        )

    @staticmethod
    def from_paths(
        game_data: "pack.GamePacks",
        png_path: str,
        imgcut_path: str,
        mamodel_path: str,
        maanims_path: list[str],
    ):
        return Anim(
            None,
            None,
            None,
            imgcut_path,
            png_path,
            mamodel_path,
            maanims_path,
            game_data,
        )

    def to_game_data(
        self,
        game_data: "pack.GamePacks",
        png_path: str,
        imgcut_path: str,
        mamodel_path: str,
        maanims_paths: list[str],
    ):
        if not self.imgcut.is_empty():
            imgcut_data = self.imgcut.to_data()
            game_data.set_file(imgcut_path, imgcut_data[0])
            game_data.set_file(png_path, imgcut_data[1])

        if not self.mamodel.is_empty():
            mamodel_data = self.mamodel.to_data()
            game_data.set_file(mamodel_path, mamodel_data)

        for maanim in self.maanims:
            if maanim.is_empty():
                continue
            maanim_data = maanim.to_data()
            game_data.set_file(maanim.name, maanim_data)

    def serialize(self) -> dict[str, Any]:
        return {
            "imgcut": self.imgcut.serialize(),
            "mamodel": self.mamodel.serialize(),
            "maanims": [maanim.serialize() for maanim in self.maanims],
        }

    @staticmethod
    def deserialize(data: dict[str, Any]):
        imgcut = Imgcut.deserialize(data["imgcut"])
        mamodel = Mamodel.deserialize(data["mamodel"], imgcut.cuts)
        maanims = [Maanim.deserialize(maanim) for maanim in data["maanims"]]
        return Anim(imgcut, mamodel, maanims)

    def flip_x(self):
        self.mamodel.flip_x()
        for maanim in self.maanims:
            maanim.flip()

    def flip_y(self):
        self.mamodel.flip_y()
        for maanim in self.maanims:
            maanim.flip()

    def copy(self):
        return Anim(
            self.imgcut.copy(),
            self.mamodel.copy(),
            [maanim.copy() for maanim in self.maanims],
        )

    def set_cat_id(self, cat_id: int, form_st: str):
        for part in self.mamodel.parts:
            if part.unit_id != -1:
                part.unit_id = cat_id

        cat_id_str = io.data.PaddedInt(cat_id, 3).to_str()
        self.imgcut.image_name = f"{cat_id_str}_{form_st}.png"

        for maanim in self.maanims:
            type_str = maanim.name.split("_")[1]
            maanim.name = f"{cat_id_str}_{form_st}{type_str[1:]}"

        self.mamodel.fix_collision()

    def set_enemy_id(self, enemy_id: int):
        self.set_cat_id(enemy_id, "e")

        self.mamodel.ints.pop()

    def get_maanim(self, name: str):
        for maanim in self.maanims:
            if maanim.name == name:
                return maanim
        return None

    def get_maanim_by_type(self, type: Union[str, AnimType]):
        if isinstance(type, AnimType):
            type = str(type.value).zfill(2)
        for maanim in self.maanims:
            if maanim.name.split("_")[1][1:3] == type:
                return maanim
        return None

    def set_maanim(self, maanim: "Maanim"):
        for i, anim in enumerate(self.maanims):
            if anim.name == maanim.name:
                self.maanims[i] = maanim
                return
        self.maanims.append(maanim)

    def import_anim(self, anim: "Anim"):
        if not anim.imgcut.is_empty():
            self.imgcut = anim.imgcut
        if not anim.mamodel.is_empty():
            self.mamodel = anim.mamodel
        if len(anim.maanims) > 0:
            self.maanims = anim.maanims

    @imgcut.setter
    def imgcut(self, imgcut: "Imgcut"):
        self.__imgcut = imgcut
        self.mamodel.cuts = imgcut.cuts

    @mamodel.setter
    def mamodel(self, mamodel: "Mamodel"):
        self.__mamodel = mamodel

    @maanims.setter
    def maanims(self, maanims: list["Maanim"]):
        self.__maanims = maanims
