import enum
from typing import Any
from tbcml.core.game_data import pack
from tbcml.core import io, anim


class Engineer:
    def __init__(self, limit: "EngineerLimit", anim: "EngineerAnim"):
        self.limit = limit
        self.anim = anim

    def serialize(self) -> dict[str, Any]:
        return {
            "limit": self.limit.serialize(),
            "anim": self.anim.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Engineer":
        return Engineer(
            EngineerLimit.deserialize(data["limit"]),
            EngineerAnim.deserialize(data["anim"]),
        )

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "Engineer":
        limit = EngineerLimit.from_game_data(game_data)
        anim = EngineerAnim.from_game_data(game_data)
        return Engineer(
            limit,
            anim,
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.limit.to_game_data(game_data)
        self.anim.to_game_data(game_data)

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("gamototo").add("ototo").add("engineer.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_object(self.serialize())
        zip.add_file(Engineer.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "Engineer":
        json_data = zip.get_file(Engineer.get_json_file_path())
        if json_data is None:
            return Engineer.create_empty()
        json = io.json_file.JsonFile.from_data(json_data)
        return Engineer.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "Engineer":
        return Engineer(
            EngineerLimit.create_empty(),
            EngineerAnim.create_empty(),
        )

    def import_engineer(self, other: "Engineer", game_data: "pack.GamePacks"):
        gd_limit = EngineerLimit.from_game_data(game_data)
        if gd_limit.limit != other.limit.limit:
            self.limit = other.limit
        self.anim.import_engineer_anim(other.anim, game_data)


class EngineerLimit:
    def __init__(self, limit: int):
        self.limit = limit

    def serialize(self) -> dict[str, Any]:
        return {
            "limit": self.limit,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "EngineerLimit":
        return EngineerLimit(
            data["limit"],
        )

    @staticmethod
    def get_file_name() -> str:
        return "CastleCustomLimit.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "EngineerLimit":
        file = game_data.find_file(EngineerLimit.get_file_name())
        if file is None:
            return EngineerLimit.create_empty()
        csv = io.bc_csv.CSV(file.dec_data)
        return EngineerLimit(
            csv.lines[0][0].to_int(),
        )

    def to_game_data(self, game_data: "pack.GamePacks"):
        file = game_data.find_file(EngineerLimit.get_file_name())
        if file is None:
            return None
        csv = io.bc_csv.CSV(file.dec_data)
        csv.lines[0][0].set(self.limit)
        game_data.set_file(EngineerLimit.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "EngineerLimit":
        return EngineerLimit(0)

    def __str__(self):
        return f"EngineerLimit({self.limit})"

    def __repr__(self):
        return self.__str__()


class EngineerAnim:
    class FilePath(enum.Enum):
        IMGCUT = "castleCustom_researcher_001.imgcut"
        MAMODEL = "castleCustom_researcher_001.mamodel"
        SPRITE = "castleCustom_researcher_001.png"

        MAANIM_ACTION_L = "castleCustom_researcher_actionL.maanim"
        MAANIM_ACTION_R = "castleCustom_researcher_actionR.maanim"

        MAANIM_HAPPY = "castleCustom_researcher_happy.maanim"

        MAANIM_RUN_L = "castleCustom_researcher_runL.maanim"
        MAANIM_RUN_R = "castleCustom_researcher_runR.maanim"

        MAANIM_SUCESS_00 = "castleCustom_researcher_success00.maanim"
        MAANIM_SUCESS_01 = "castleCustom_researcher_success01.maanim"

        MAANIM_WAIT_L = "castleCustom_researcher_waitL.maanim"
        MAANIM_WAIT_R = "castleCustom_researcher_waitR.maanim"

        MAANIM_WALK_L = "castleCustom_researcher_walkL.maanim"
        MAANIM_WALK_R = "castleCustom_researcher_walkR.maanim"

        @staticmethod
        def get_all_maanims() -> list["EngineerAnim.FilePath"]:
            all_maanims: list["EngineerAnim.FilePath"] = []
            for maanim in EngineerAnim.FilePath:
                if maanim.value.endswith(".maanim"):
                    all_maanims.append(maanim)
            return all_maanims

        @staticmethod
        def get_all_maanims_names() -> list[str]:
            all_maanims: list[str] = []
            for maanim in EngineerAnim.FilePath:
                if maanim.value.endswith(".maanim"):
                    all_maanims.append(maanim.value)
            return all_maanims

    def __init__(self, model: "anim.model.Model"):
        self.model = model

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "EngineerAnim":
        an = anim.model.Model.load(
            EngineerAnim.FilePath.MAMODEL.value,
            EngineerAnim.FilePath.IMGCUT.value,
            EngineerAnim.FilePath.SPRITE.value,
            EngineerAnim.FilePath.get_all_maanims_names(),
            game_data,
        )
        return EngineerAnim(an)

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.model.save(game_data)

    def serialize(self) -> dict[str, Any]:
        return {
            "model": self.model.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "EngineerAnim":
        an = anim.model.Model.deserialize(data["model"])
        return EngineerAnim(an)

    @staticmethod
    def create_empty() -> "EngineerAnim":
        an = anim.model.Model.create_empty()
        return EngineerAnim(an)

    def import_engineer_anim(self, other: "EngineerAnim", game_data: "pack.GamePacks"):
        """_summary_

        Args:
            other (EngineerAnim): _description_
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_anim = EngineerAnim.from_game_data(game_data)
        if gd_anim.model != other.model:
            self.model = other.model
