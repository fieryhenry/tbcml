"""Module for background data."""
import enum
from typing import Any, Optional

from tbcml import core


class ColorType(enum.Enum):
    """Enum for the different places a color can be used in a background."""

    SKY_TOP = 0
    SKY_BOTTOM = 1
    GROUND_TOP = 2
    GROUND_BOTTOM = 3


class Color:
    """Class for a color."""

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

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dictionary to the Color object.

        Args:
            dict_data (dict[str, Any]): The dictionary to apply.
        """

        c_type = dict_data.get("type")
        if c_type is not None:
            self.type = ColorType(c_type)
        self.r = dict_data.get("r", self.r)
        self.g = dict_data.get("g", self.g)
        self.b = dict_data.get("b", self.b)

    @staticmethod
    def create_empty(c_type: ColorType) -> "Color":
        """Creates an empty Color.

        Args:
            c_type (ColorType): The location where the color is applied.

        Returns:
            Color: An empty Color.
        """
        return Color(c_type, 0, 0, 0)


class Bg:
    """Class for a background."""

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
        json_data: Optional[dict[str, Any]] = None,
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
        self.json_data = json_data

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dictionary to the Bg object.

        Args:
            dict_data (dict[str, Any]): The dictionary to apply.
        """
        self.id = dict_data.get("id", self.id)
        self.sky_top.apply_dict(dict_data.get("sky_top", {}))
        self.sky_bottom.apply_dict(dict_data.get("sky_bottom", {}))
        self.ground_top.apply_dict(dict_data.get("ground_top", {}))
        self.ground_bottom.apply_dict(dict_data.get("ground_bottom", {}))
        self.imgcut_id = dict_data.get("imgcut_id", self.imgcut_id)
        self.is_upper_side_bg_enabled = dict_data.get(
            "is_upper_side_bg_enabled", self.is_upper_side_bg_enabled
        )
        self.extra = dict_data.get("extra", self.extra)
        self.json_data = dict_data.get("json_data", self.json_data)

    @staticmethod
    def create_empty(id: int) -> "Bg":
        """Creates an empty Bg.

        Args:
            id (int): The ID of the background.

        Returns:
            Bg: An empty Bg.
        """
        return Bg(
            id,
            Color.create_empty(ColorType.SKY_TOP),
            Color.create_empty(ColorType.SKY_BOTTOM),
            Color.create_empty(ColorType.GROUND_TOP),
            Color.create_empty(ColorType.GROUND_BOTTOM),
            0,
            False,
        )

    @staticmethod
    def get_json_file_name(id: int) -> str:
        """Gets the name of the JSON file for the background.

        Args:
            id (int): The ID of the background.

        Returns:
            str: The name of the JSON file for the background.
        """

        id_str = core.PaddedInt(id, 3).to_str()
        return f"bg{id_str}.json"

    @staticmethod
    def from_game_data(
        game_data: "core.GamePacks",
        id: int,
        sky_top: Color,
        sky_bottom: Color,
        ground_top: Color,
        ground_bottom: Color,
        imgcut_id: int,
        is_upper_side_bg_enabled: bool,
        extra: Optional[list[int]] = None,
    ) -> "Bg":
        """Creates a Bg from game data.

        Args:
            game_data (core.GamePacks): The game data.
            id (int): The ID of the background.
            sky_top (Color): Sky top color.
            sky_bottom (Color): Sky bottom color.
            ground_top (Color): Ground top color.
            ground_bottom (Color): Ground bottom color.
            imgcut_id (int): The ID of the imgcut used for the background.
            is_upper_side_bg_enabled (bool): Whether or not the upper side of the background is enabled. ???
            extra (Optional[list[int]], optional): Extra data. Defaults to None.

        Returns:
            Bg: The Bg created from game data.
        """
        file = game_data.find_file(Bg.get_json_file_name(id))
        if file is None:
            json_data = None
        else:
            json_data = core.JsonFile(file.dec_data).get_json()
        return Bg(
            id,
            sky_top,
            sky_bottom,
            ground_top,
            ground_bottom,
            imgcut_id,
            is_upper_side_bg_enabled,
            extra,
            json_data,
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the Bg to game data.

        Args:
            game_data (core.GamePacks): The game data.
        """
        file_name = Bg.get_json_file_name(self.id)
        data = core.JsonFile.from_object(self.json_data).to_data()
        game_data.set_file(file_name, data)


class Bgs:
    """A class that represents the background data."""

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
    def from_game_data(game_data: "core.GamePacks") -> "Bgs":
        """Creates a Bgs object from the game data.

        Args:
            game_data (core.GamePacks): The game data to create the Bgs object from.

        Returns:
            Bgs: A Bgs object if the file was found, None otherwise.
        """
        if game_data.bgs is not None:
            return game_data.bgs
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            return Bgs.create_empty()
        csv = core.CSV(file.dec_data)
        bgs: dict[int, Bg] = {}
        for line in csv.lines[1:]:
            id = int(line[0])
            sky_top = Color(
                ColorType.SKY_TOP,
                int(line[1]),
                int(line[2]),
                int(line[3]),
            )
            sky_bottom = Color(
                ColorType.SKY_BOTTOM,
                int(line[4]),
                int(line[5]),
                int(line[6]),
            )
            ground_top = Color(
                ColorType.GROUND_TOP,
                int(line[7]),
                int(line[8]),
                int(line[9]),
            )
            ground_bottom = Color(
                ColorType.GROUND_BOTTOM,
                int(line[10]),
                int(line[11]),
                int(line[12]),
            )
            imgcut_id = int(line[13])
            is_upper_side_bg_enabled = int(line[14]) != 0
            try:
                extra = [int(x) for x in line[15:]]
            except ValueError:
                extra = None
            bgs[id] = Bg.from_game_data(
                game_data,
                id,
                sky_top,
                sky_bottom,
                ground_top,
                ground_bottom,
                imgcut_id,
                is_upper_side_bg_enabled,
                extra,
            )
        bgs_obj = Bgs(bgs)
        game_data.bgs = bgs_obj
        return bgs_obj

    def to_game_data(self, game_data: "core.GamePacks"):
        """Writes the Bgs object to the game data.

        Args:
            game_data (core.GamePacks): The game data to write to.
        """
        file = game_data.find_file(Bgs.get_file_name())
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        remaining_bgs = self.bgs.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                bg = self.bgs[i]
            except KeyError:
                continue
            line[1] = str((bg.sky_top.r))
            line[2] = str((bg.sky_top.g))
            line[3] = str((bg.sky_top.b))
            line[4] = str((bg.sky_bottom.r))
            line[5] = str((bg.sky_bottom.g))
            line[6] = str((bg.sky_bottom.b))
            line[7] = str((bg.ground_top.r))
            line[8] = str((bg.ground_top.g))
            line[9] = str((bg.ground_top.b))
            line[10] = str((bg.ground_bottom.r))
            line[11] = str((bg.ground_bottom.g))
            line[12] = str((bg.ground_bottom.b))
            line[13] = str((bg.imgcut_id))
            line[14] = str((1 if bg.is_upper_side_bg_enabled else 0))
            if bg.extra is not None:
                for j, extra in enumerate(bg.extra):
                    line[15 + j] = str(extra)
            csv.lines[i + 1] = line
            del remaining_bgs[i]

        for i, bg in remaining_bgs.items():
            new_line = [
                str(bg.id),
                str(bg.sky_top.r),
                str(bg.sky_top.g),
                str(bg.sky_top.b),
                str(bg.sky_bottom.r),
                str(bg.sky_bottom.g),
                str(bg.sky_bottom.b),
                str(bg.ground_top.r),
                str(bg.ground_top.g),
                str(bg.ground_top.b),
                str(bg.ground_bottom.r),
                str(bg.ground_bottom.g),
                str(bg.ground_bottom.b),
                str(bg.imgcut_id),
                str(1) if bg.is_upper_side_bg_enabled else str(0),
            ]
            if bg.extra is not None:
                new_line.extend([str(x) for x in bg.extra])
            csv.lines.append(new_line)

        for bg in self.bgs.values():
            bg.to_game_data(game_data)

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

    @staticmethod
    def create_empty() -> "Bgs":
        """Creates an empty Bgs object.

        Returns:
            Bgs: The created Bgs object.
        """
        return Bgs({})

    def apply_dict(self, dict_data: dict[str, Any]):
        """Applies a dict to the Bgs object.

        Args:
            dict_data (dict[str, Any]): The dict to apply.
        """
        bgs = dict_data.get("bgs")
        if bgs is None:
            return
        current_bgs = self.bgs.copy()
        modded_bgs = core.ModEditDictHandler(bgs, current_bgs).get_dict(
            convert_int=True
        )
        for id, modded_bg in modded_bgs.items():
            bg = self.bgs.get(id)
            if bg is None:
                bg = Bg.create_empty(id)
            bg.apply_dict(modded_bg)
            self.bgs[id] = bg

    @staticmethod
    def apply_mod_to_game_data(mod: "core.Mod", game_data: "core.GamePacks"):
        """Apply a mod to a GamePacks object.

        Args:
            mod (core.Mod): The mod.
            game_data (GamePacks): The GamePacks object.
        """
        bgs_data = mod.mod_edits.get("bgs")
        if bgs_data is None:
            return
        bgs = Bgs.from_game_data(game_data)
        bgs.apply_dict(bgs_data)
        bgs.to_game_data(game_data)
