import enum
from typing import Any
from tbcml import core


class OtotoAnim(core.EditableClass):
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
        def get_all_maanims() -> list["OtotoAnim.FilePath"]:
            all_maanims: list["OtotoAnim.FilePath"] = []
            for member in OtotoAnim.FilePath:
                if member.value.endswith(".maanim"):
                    all_maanims.append(member)
            return all_maanims

        @staticmethod
        def get_all_maanims_names() -> list[str]:
            all_maanims: list[str] = []
            for member in OtotoAnim.FilePath:
                if member.value.endswith(".maanim"):
                    all_maanims.append(member.value)
            return all_maanims

    def __init__(self, model: "core.Model"):
        self.model = model
        super().__init__()

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "OtotoAnim":
        if game_data.ototo_anim is not None:
            return game_data.ototo_anim
        an = core.Model.load(
            OtotoAnim.FilePath.MAMODEL.value,
            OtotoAnim.FilePath.IMGCUT.value,
            OtotoAnim.FilePath.SPRITE.value,
            OtotoAnim.FilePath.get_all_maanims_names(),
            game_data,
        )
        anim = OtotoAnim(an)
        game_data.ototo_anim = anim
        return anim

    def to_game_data(self, game_data: "core.GamePacks"):
        self.model.save(game_data)

    def apply_dict(
        self,
        dict_data: dict[str, Any],
        mod_edit_key: str,
        convert_int: bool = True,
    ):
        model = dict_data.get(mod_edit_key)
        if model is not None:
            self.model.apply_dict(model)

    @staticmethod
    def create_empty() -> "OtotoAnim":
        return OtotoAnim(core.Model.create_empty())
