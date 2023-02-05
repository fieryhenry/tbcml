import enum
from typing import Any
from bcml.core.game_data import pack, bc_anim
from bcml.core import io


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
        json = io.json_file.JsonFile.from_json(self.serialize())
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

    def import_engineer(self, other: "Engineer"):
        self.limit = other.limit
        self.anim.import_engineer_anim(other.anim)


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

    def __init__(self, anim: "bc_anim.Anim"):
        self.anim = anim

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "EngineerAnim":
        anim = bc_anim.Anim.from_paths(
            game_data,
            EngineerAnim.FilePath.SPRITE.value,
            EngineerAnim.FilePath.IMGCUT.value,
            EngineerAnim.FilePath.MAMODEL.value,
            EngineerAnim.FilePath.get_all_maanims_names(),
        )
        if anim is None:
            return EngineerAnim.create_empty()
        return EngineerAnim(anim)

    def to_game_data(self, game_data: "pack.GamePacks"):
        self.anim.to_game_data(
            game_data,
            EngineerAnim.FilePath.SPRITE.value,
            EngineerAnim.FilePath.IMGCUT.value,
            EngineerAnim.FilePath.MAMODEL.value,
            EngineerAnim.FilePath.get_all_maanims_names(),
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "anim": self.anim.serialize(),
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "EngineerAnim":
        anim = bc_anim.Anim.deserialize(data["anim"])
        return EngineerAnim(anim)

    @staticmethod
    def create_empty() -> "EngineerAnim":
        anim = bc_anim.Anim.create_empty()
        return EngineerAnim(anim)

    def import_engineer_anim(self, other: "EngineerAnim"):
        self.anim.import_anim(other.anim)
