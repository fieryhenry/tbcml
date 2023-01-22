import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class ColorType(enum.Enum):
    """Enum for the different types of colors in a Bg."""    
    SKY_TOP = 0
    SKY_BOTTOM = 1
    GROUND_TOP = 2
    GROUND_BOTTOM = 3


class Color:
    def __init__(self, type: ColorType, r: int, g: int, b: int):
        self.type = type
        self.r = r
        self.g = g
        self.b = b

    def serialize(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "r": self.r,
            "g": self.g,
            "b": self.b,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Color":
        return Color(
            ColorType(data["type"]),
            data["r"],
            data["g"],
            data["b"],
        )


class Bg:
    def __init__(
        self,
        id: int,
        sky_top: Color,
        sky_bottom: Color,
        ground_top: Color,
        ground_bottom: Color,
        imgcut_id: int,
        is_upper_side_bg_enabled: bool,
        extra: Optional[list[int]] = None,
    ):
        self.id = id
        self.sky_top = sky_top
        self.sky_bottom = sky_bottom
        self.ground_top = ground_top
        self.ground_bottom = ground_bottom
        self.imgcut_id = imgcut_id
        self.is_upper_side_bg_enabled = is_upper_side_bg_enabled
        self.extra = extra

    def serialize(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sky_top": self.sky_top.serialize(),
            "sky_bottom": self.sky_bottom.serialize(),
            "ground_top": self.ground_top.serialize(),
            "ground_bottom": self.ground_bottom.serialize(),
            "imgcut_id": self.imgcut_id,
            "is_upper_side_bg_enabled": self.is_upper_side_bg_enabled,
            "extra": self.extra,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Bg":
        return Bg(
            data["id"],
            Color.deserialize(data["sky_top"]),
            Color.deserialize(data["sky_bottom"]),
            Color.deserialize(data["ground_top"]),
            Color.deserialize(data["ground_bottom"]),
            data["imgcut_id"],
            data["is_upper_side_bg_enabled"],
            data["extra"],
        )


class Bgs:
    def __init__(self, bgs: dict[int, Bg]):
        self.bgs = bgs

    @staticmethod
    def get_file_name() -> str:
        return "bg.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks"):
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            raise FileNotFoundError(f"{Bgs.get_file_name()} not found")
        csv = io.bc_csv.CSV(file.dec_data)
        bgs: dict[int, Bg] = {}
        for i, line in enumerate(csv.lines[1:]):
            sky_top = Color(
                ColorType.SKY_TOP,
                line[1].to_int(),
                line[2].to_int(),
                line[3].to_int(),
            )
            sky_bottom = Color(
                ColorType.SKY_BOTTOM,
                line[4].to_int(),
                line[5].to_int(),
                line[6].to_int(),
            )
            ground_top = Color(
                ColorType.GROUND_TOP,
                line[7].to_int(),
                line[8].to_int(),
                line[9].to_int(),
            )
            ground_bottom = Color(
                ColorType.GROUND_BOTTOM,
                line[10].to_int(),
                line[11].to_int(),
                line[12].to_int(),
            )
            imgcut_id = line[13].to_int()
            is_upper_side_bg_enabled = line[14].to_int() != 0
            try:
                extra = io.data.Data.data_list_int_list(line[15:])
            except ValueError:
                extra = None
            bgs[i] = Bg(
                i,
                sky_top,
                sky_bottom,
                ground_top,
                ground_bottom,
                imgcut_id,
                is_upper_side_bg_enabled,
                extra,
            )
        return Bgs(bgs)

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            raise FileNotFoundError(f"{Bgs.get_file_name()} not found")
        csv = io.bc_csv.CSV(file.dec_data)
        remaining_bgs = self.bgs.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                bg = self.bgs[i]
            except KeyError:
                continue
            line[1].set((bg.sky_top.r))
            line[2].set((bg.sky_top.g))
            line[3].set((bg.sky_top.b))
            line[4].set((bg.sky_bottom.r))
            line[5].set((bg.sky_bottom.g))
            line[6].set((bg.sky_bottom.b))
            line[7].set((bg.ground_top.r))
            line[8].set((bg.ground_top.g))
            line[9].set((bg.ground_top.b))
            line[10].set((bg.ground_bottom.r))
            line[11].set((bg.ground_bottom.g))
            line[12].set((bg.ground_bottom.b))
            line[13].set((bg.imgcut_id))
            line[14].set((1 if bg.is_upper_side_bg_enabled else 0))
            if bg.extra is not None:
                for j, extra in enumerate(bg.extra):
                    line[15 + j].set(extra)
            csv.set_line(i + 1, line)
            del remaining_bgs[i]

        for i, bg in remaining_bgs.items():
            line = [
                i,
                bg.sky_top.r,
                bg.sky_top.g,
                bg.sky_top.b,
                bg.sky_bottom.r,
                bg.sky_bottom.g,
                bg.sky_bottom.b,
                bg.ground_top.r,
                bg.ground_top.g,
                bg.ground_top.b,
                bg.ground_bottom.r,
                bg.ground_bottom.g,
                bg.ground_bottom.b,
                bg.imgcut_id,
                1 if bg.is_upper_side_bg_enabled else 0,
            ]
            if bg.extra is not None:
                line.extend(bg.extra)
            csv.add_line(line)

        game_data.set_file(Bgs.get_file_name(), csv.to_data())

    def get_bg(self, id: int) -> Bg:
        return self.bgs[id]

    def set_bg(self, id: int, bg: Bg):
        self.bgs[id] = bg

    def serialize(self) -> dict[str, Any]:
        return {
            "bgs": {id: bg.serialize() for id, bg in self.bgs.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Bgs":
        return Bgs({id: Bg.deserialize(bg) for id, bg in data["bgs"].items()})

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        return io.path.Path("battle").add("bgs.json")
    
    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        path = Bgs.get_zip_json_file_path()
        zip.add_file(path, json.to_data())
    
    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["Bgs"]:
        path = Bgs.get_zip_json_file_path()
        file = zip.get_file(path)
        if file is None:
            return None
        json = io.json_file.JsonFile.from_data(file)
        return Bgs.deserialize(json.get_json())
    
    @staticmethod
    def create_empty() -> "Bgs":
        return Bgs({})
    
    def import_bgs(self, other: "Bgs"):
        self.bgs.update(other.bgs)