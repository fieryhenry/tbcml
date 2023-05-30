import enum
from typing import Any
from tbcml import core


class MainChara:
    class FilePath(enum.Enum):
        IMGCUT = "castleCustom_mainChara_001.imgcut"
        MAMODEL = "castleCustom_mainChara_001.mamodel"
        SPRITE = "castleCustom_mainChara_001.png"

        MAANIM_ACTION_L_OPEN = "castleCustom_mainChara_actionL_open.maanim"
        MAANIM_ACTION_R_OPEN = "castleCustom_mainChara_actionR_open.maanim"

        MAANIM_HAPPY = "castleCustom_mainChara_happy.maanim"

        MAANIM_RUN_L = "castleCustom_mainChara_runL.maanim"
        MAANIM_RUN_R = "castleCustom_mainChara_runR.maanim"

        MAANIM_WAIT_L = "castleCustom_mainChara_waitL.maanim"
        MAANIM_WAIT_L_OPEN = "castleCustom_mainChara_waitL_open.maanim"
        MAANIM_WAIT_R = "castleCustom_mainChara_waitR.maanim"
        MAANIM_WAIT_R_OPEN = "castleCustom_mainChara_waitR_open.maanim"

        MAANIM_WALK_L = "castleCustom_mainChara_walkL.maanim"
        MAANIM_WALK_L_OPEN = "castleCustom_mainChara_walkL_open.maanim"
        MAANIM_WALK_R = "castleCustom_mainChara_walkR.maanim"
        MAANIM_WALK_R_OPEN = "castleCustom_mainChara_walkR_open.maanim"

        @staticmethod
        def get_all_maanims() -> list["MainChara.FilePath"]:
            all_maanims: list["MainChara.FilePath"] = []
            for member in MainChara.FilePath:
                if member.value.endswith(".maanim"):
                    all_maanims.append(member)
            return all_maanims

        @staticmethod
        def get_all_maanims_names() -> list[str]:
            all_maanims: list[str] = []
            for member in MainChara.FilePath:
                if member.value.endswith(".maanim"):
                    all_maanims.append(member.value)
            return all_maanims

    def __init__(self, model: "core.Model"):
        self.model = model

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "MainChara":
        an = core.Model.load(
            MainChara.FilePath.MAMODEL.value,
            MainChara.FilePath.IMGCUT.value,
            MainChara.FilePath.SPRITE.value,
            MainChara.FilePath.get_all_maanims_names(),
            game_data,
        )
        return MainChara(an)

    def to_game_data(self, game_data: "core.GamePacks"):
        self.model.save(game_data)

    def apply_dict(self, dict_data: dict[str, Any]):
        model = dict_data.get("model")
        if model is not None:
            self.model.apply_dict(model)

    @staticmethod
    def create_empty() -> "MainChara":
        return MainChara(core.Model.create_empty())
