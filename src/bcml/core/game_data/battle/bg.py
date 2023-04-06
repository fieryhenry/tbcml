import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class ColorType(enum.Enum):
    """Enum for the different places a color can be used in a background."""

    SKY_TOP = 0
    SKY_BOTTOM = 1
    GROUND_TOP = 2
    GROUND_BOTTOM = 3


class Color:
    def __init__(self, c_type: ColorType, r: int, g: int, b: int):
        """Initializes a Color object.

        Args:
            c_type (ColorType): The location where the color is applied.
            r (int): Red value.
            g (int): Green value.
            b (int): Blue value.
        """
        self.type = c_type
        self.r = r
        self.g = g
        self.b = b

    def serialize(self) -> dict[str, Any]:
        """Serializes the Color object into a dictionary that can be written to a json file.

        Returns:
            dict[str, Any]: The serialized Color object.
        """
        return {
            "type": self.type.value,
            "r": self.r,
            "g": self.g,
            "b": self.b,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Color":
        """Deserializes a Color object from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize from.

        Returns:
            Color: The deserialized Color object.
        """
        return Color(
            ColorType(data["type"]),
            data["r"],
            data["g"],
            data["b"],
        )

    def __eq__(self, other: object) -> bool:
        """Compares two Color objects.

        Args:
            other (object): The other Color object to compare to.

        Returns:
            bool: Whether or not the two Color objects are equal.
        """
        if not isinstance(other, Color):
            return False
        return (
            self.type == other.type
            and self.r == other.r
            and self.g == other.g
            and self.b == other.b
        )

    def __ne__(self, other: object) -> bool:
        """Compares two Color objects.

        Args:
            other (object): The other Color object to compare to.

        Returns:
            bool: Whether or not the two Color objects are not equal.
        """
        return not self.__eq__(other)


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
        """Initializes a Bg object.

        Args:
            id (int): The ID of the background.
            sky_top (Color): The color of the top of the sky.
            sky_bottom (Color): The color of the bottom of the sky.
            ground_top (Color): The color of the top of the ground.
            ground_bottom (Color): The color of the bottom of the ground.
            imgcut_id (int): The ID of the imgcut used for the background.
            is_upper_side_bg_enabled (bool): Whether or not the upper side of the background is enabled. ???
            extra (Optional[list[int]], optional): Extra data. Defaults to None.
        """
        self.id = id
        self.sky_top = sky_top
        self.sky_bottom = sky_bottom
        self.ground_top = ground_top
        self.ground_bottom = ground_bottom
        self.imgcut_id = imgcut_id
        self.is_upper_side_bg_enabled = is_upper_side_bg_enabled
        self.extra = extra

    def serialize(self) -> dict[str, Any]:
        """Serializes the Bg object into a dictionary that can be written to a json file.

        Returns:
            dict[str, Any]: The serialized Bg object.
        """
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
        """Deserializes a Bg object from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize from.

        Returns:
            Bg: The deserialized Bg object.
        """
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

    def __eq__(self, other: object) -> bool:
        """Compares two Bg objects.

        Args:
            other (object): The other Bg object to compare to.

        Returns:
            bool: Whether or not the two Bg objects are equal.
        """
        if not isinstance(other, Bg):
            return False
        return (
            self.id == other.id
            and self.sky_top == other.sky_top
            and self.sky_bottom == other.sky_bottom
            and self.ground_top == other.ground_top
            and self.ground_bottom == other.ground_bottom
            and self.imgcut_id == other.imgcut_id
            and self.is_upper_side_bg_enabled == other.is_upper_side_bg_enabled
            and self.extra == other.extra
        )

    def __ne__(self, other: object) -> bool:
        """Compares two Bg objects.

        Args:
            other (object): The other Bg object to compare to.

        Returns:
            bool: Whether or not the two Bg objects are not equal.
        """
        return not self.__eq__(other)


class Bgs:
    def __init__(self, bgs: dict[int, Bg]):
        """Initializes a Bgs object.

        Args:
            bgs (dict[int, Bg]): A dictionary of Bg objects.
        """
        self.bgs = bgs

    @staticmethod
    def get_file_name() -> str:
        """Gets the name of the file that contains the background data.

        Returns:
            str: The name of the file that contains the background data.
        """
        return "bg.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Bgs":
        """Creates a Bgs object from the game data.

        Args:
            game_data (pack.GamePacks): The game data to create the Bgs object from.

        Returns:
            Bgs: A Bgs object if the file was found, None otherwise.
        """
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            return Bgs.create_empty()
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
        """Writes the Bgs object to the game data.

        Args:
            game_data (pack.GamePacks): The game data to write to.
        """
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            return
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
            new_line = [
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
                new_line.extend(bg.extra)
            csv.add_line(new_line)

        game_data.set_file(Bgs.get_file_name(), csv.to_data())

    def get_bg(self, id: int) -> Optional[Bg]:
        """Gets a Bg by its id.

        Args:
            id (int): The id of the Bg to get.

        Returns:
            Bg: The Bg with the given id.
        """
        return self.bgs.get(id)

    def set_bg(self, id: int, bg: Bg):
        """Sets a Bg by its id.

        Args:
            id (int): The id of the Bg to set.
            bg (Bg): The Bg to set.
        """
        self.bgs[id] = bg

    def serialize(self) -> dict[str, Any]:
        """Serializes the Bgs object to a dict.

        Returns:
            dict[str, Any]: The serialized Bgs object.
        """
        return {
            "bgs": {id: bg.serialize() for id, bg in self.bgs.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Bgs":
        """Deserializes a dict to a Bgs object.

        Args:
            data (dict[str, Any]): The data to deserialize.

        Returns:
            Bgs: The deserialized Bgs object.
        """
        return Bgs({id: Bg.deserialize(bg) for id, bg in data["bgs"].items()})

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        """Gets the path of the Bgs json file in the mod zip.

        Returns:
            io.path.Path: The path of the Bgs json file in the mod zip.
        """
        return io.path.Path("battle").add("bgs.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        """Adds the Bgs object to a mod zip.

        Args:
            zip (io.zip.Zip): The mod zip to add the Bgs object to.
        """
        json = io.json_file.JsonFile.from_object(self.serialize())
        path = Bgs.get_zip_json_file_path()
        zip.add_file(path, json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Bgs":
        """Creates a Bgs object from a mod zip.

        Args:
            zip (io.zip.Zip): The mod zip to create the Bgs object from.

        Returns:
            Bgs: The created Bgs object.
        """
        path = Bgs.get_zip_json_file_path()
        file = zip.get_file(path)
        if file is None:
            return Bgs.create_empty()
        json = io.json_file.JsonFile.from_data(file)
        return Bgs.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "Bgs":
        """Creates an empty Bgs object.

        Returns:
            Bgs: The created Bgs object.
        """
        return Bgs({})

    def import_bgs(self, other: "Bgs", game_data: "pack.GamePacks"):
        """Imports Bgs from another Bgs object.

        Args:
            other (Bgs): The Bgs object to import from.
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_bgs = self.from_game_data(game_data)
        all_keys = set(self.bgs.keys())
        all_keys.update(other.bgs.keys())
        all_keys.update(gd_bgs.bgs.keys())

        for id in all_keys:
            other_bg = gd_bgs.get_bg(id)
            gd_bg = self.get_bg(id)
            if other_bg is None:
                continue
            if gd_bg is not None:
                if gd_bg != other_bg:
                    self.set_bg(id, other_bg)
            else:
                self.set_bg(id, other_bg)
