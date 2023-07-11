import enum
from typing import Any
from tbcml import core


class Engineer:
    def __init__(self, limit: "EngineerLimit", anim: "EngineerAnim"):
        self.limit = limit
        self.anim = anim

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "Engineer":
        limit = EngineerLimit.from_game_data(game_data)
        anim = EngineerAnim.from_game_data(game_data)
        return Engineer(
            limit,
            anim,
        )

    def to_game_data(self, game_data: "core.GamePacks"):
        self.limit.to_game_data(game_data)
        self.anim.to_game_data(game_data)

    @staticmethod
    def create_empty() -> "Engineer":
        return Engineer(
            EngineerLimit.create_empty(),
            EngineerAnim.create_empty(),
        )

    def apply_dict(self, dict_data: dict[str, Any]):
        self.limit.limit = dict_data.get("limit", self.limit.limit)
        self.anim.apply_dict(dict_data, "anim")


class EngineerLimit(core.EditableClass):
    def __init__(self, limit: int):
        self.limit = limit
        super().__init__()

    @staticmethod
    def get_file_name() -> str:
        return "CastleCustomLimit.csv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EngineerLimit":
        if game_data.engineer_limit is not None:
            return game_data.engineer_limit
        file = game_data.find_file(EngineerLimit.get_file_name())
        if file is None:
            return EngineerLimit.create_empty()
        csv = core.CSV(file.dec_data)
        limit = EngineerLimit(
            int(csv.lines[0][0]),
        )
        game_data.engineer_limit = limit
        return limit

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(EngineerLimit.get_file_name())
        if file is None:
            return None
        csv = core.CSV(file.dec_data)
        csv.lines[0][0] = str(self.limit)
        game_data.set_file(EngineerLimit.get_file_name(), csv.to_data())

    @staticmethod
    def create_empty() -> "EngineerLimit":
        return EngineerLimit(0)

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        self.limit = dict_data.get(mod_edit_key, self.limit)


class EngineerAnim(core.EditableClass):
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

    def __init__(self, model: "core.Model"):
        self.model = model
        super().__init__()

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "EngineerAnim":
        if game_data.engineer_anim is not None:
            return game_data.engineer_anim
        an = core.Model.load(
            EngineerAnim.FilePath.MAMODEL.value,
            EngineerAnim.FilePath.IMGCUT.value,
            EngineerAnim.FilePath.SPRITE.value,
            EngineerAnim.FilePath.get_all_maanims_names(),
            game_data,
        )
        anim = EngineerAnim(an)
        game_data.engineer_anim = anim
        return anim

    def to_game_data(self, game_data: "core.GamePacks"):
        self.model.save(game_data)

    @staticmethod
    def create_empty() -> "EngineerAnim":
        an = core.Model.create_empty()
        return EngineerAnim(an)

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        self.model.apply_dict(dict_data.get(mod_edit_key, {}))
