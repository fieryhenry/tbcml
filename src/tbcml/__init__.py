from __future__ import annotations
import dataclasses
from typing import Any

__version__ = "2.0.0"


from .mods.bc_mod import (
    Mod,
    Modification,
    ModificationType,
    ModPath,
)
from .mods.smali import SmaliHandler, SmaliSet, Smali
from .mods.frida_script import FridaScript, FridaGadgetHelper
from .mods.loader import ModLoader
from .mods.compilation import CompilationTarget

from .game_data.cat_base.item_shop import ItemShop
from .game_data.cat_base.item_shop import ShopItem, ItemShop
from .game_data.cat_base.cats import (
    Cat,
    CatForm,
    FormStats,
    CatFormType,
    UnitBuy,
    NyankoPictureBook,
    CatTalent,
    CatTalents,
    CatEvolveText,
)
from .game_data.cat_base.enemy import Enemy, EnemyStats

from .game_data.localizable import Localizable
from .game_data.localizable import Localizable, LocalizableItem
from .game_data.map.stage import (
    Stage,
    StageEnemyData,
    StageInfo,
    StageOptionInfo,
    StageCSV,
    MapStageDataStage,
    NonStoryStageInfo,
)
from .game_data.map.map import Map, MapType

from .game_data.bcu import BCUZip
from .game_data.misc.sound_setting import SoundSetting
from .game_data.misc.loading_screen import LoadingScreen
from .game_data.misc.logo_screen import LogoScreen
from .game_data.misc.main_menu import MainMenu
from .game_data.misc.gatyaitem import GatyaItem, Matatabi, GatyaItemBuy
from .game_data.battle.chara_group import CharaGroup

from .anim.model import (
    Model,
    Mamodel,
    Texture,
    Rect,
    AnimModificationType,
    AnimType,
    UnitAnim,
    KeyFrame,
    KeyFrames,
    ModelPart,
)

from .anim.anim import (
    Anim,
    AnimModificationType,
)

from .io.bc_csv import (
    CSV,
    Delimeter,
    to_str,
)
from .io.csv_fields import (
    CSVField,
    IntCSVField,
    BoolCSVField,
    StringCSVField,
    StrListCSVField,
    StrTupleCSVField,
)

from .io.apk import Apk, PKGProgressSignal
from .io.pkg import Pkg, PkgType
from .io.yamlfile import Yaml
from .io.path import Path, PathStr
from .io.data import Data, PaddedInt
from .io.command import Command, CommandResult
from .io.adb import AdbHandler, BulkAdbHandler
from .io.lib import (
    LibFiles,
    Lib,
    LibPatch,
    LibPatches,
    Patch,
    FuncPatch,
    StringReplacePatch,
    ARC,
    ARCS,
    is_lief_installed,
)
from .io.json_file import JsonFile
from .io.file_handler import FileSize
from .io.xml_parse import XML
from .io.audio import AudioFile, AudioID
from .io.bc_image import BCImage
from .io.thread_helper import run_in_threads, run_in_thread
from .io.zip import Zip
from .io.ipa import Ipa
from .io.temp_file import TempFile, TempFolder
from .crypto import AesCipher, Hash, HashAlgorithm, Random, Hmac
from .langs import Language, LanguageStr
from .request import RequestHandler
from .result import Result
from .server_handler import ServerFileHandler, EventData, GameVersionSearchError
from .game_data.pack import GamePacks, PackFile, GameFile
from .country_code import CountryCode, CC
from .game_version import GameVersion, GV


def to_apk(
    path: PathStr,
    cc_overwrite: CountryCode | None = None,
    gv_overwrite: GameVersion | None = None,
    pkg_folder: Path | None = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> Apk | None:
    return to_pkg(
        path,
        cc_overwrite=cc_overwrite,
        gv_overwrite=gv_overwrite,
        pkg_folder=pkg_folder,
        allowed_script_mods=allowed_script_mods,
        skip_signature_check=skip_signature_check,
        overwrite_pkg=overwrite_pkg,
    )  # type: ignore


def to_ipa(
    path: PathStr,
    cc_overwrite: CountryCode | None = None,
    gv_overwrite: GameVersion | None = None,
    pkg_folder: PathStr | None = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> tuple[Ipa | None, Result]:
    return to_pkg(
        path,
        cc_overwrite=cc_overwrite,
        gv_overwrite=gv_overwrite,
        pkg_folder=pkg_folder,
        allowed_script_mods=allowed_script_mods,
        skip_signature_check=skip_signature_check,
        overwrite_pkg=overwrite_pkg,
    )  # type: ignore


def to_pkg(
    path: PathStr,
    cc_overwrite: CountryCode | None = None,
    gv_overwrite: GameVersion | None = None,
    pkg_folder: PathStr | None = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> tuple[Pkg | None, Result]:
    path = Path(path)
    extension = path.get_extension()
    if pkg_folder is not None:
        pkg_folder = Path(pkg_folder)
    try:
        if extension == "apk":
            pkg, res = Apk.try_get_pkg_from_path(path, all_pkg_dir=pkg_folder)
            if pkg is None:
                pkg, res = Apk.from_pkg_path(
                    path,
                    cc_overwrite=cc_overwrite,
                    gv_overwrite=gv_overwrite,
                    pkg_folder=pkg_folder,
                    allowed_script_mods=allowed_script_mods,
                    skip_signature_check=skip_signature_check,
                    overwrite_pkg=overwrite_pkg,
                )
        elif extension == "ipa":
            pkg, res = Ipa.try_get_pkg_from_path(path, all_pkg_dir=pkg_folder)
            if pkg is None:
                pkg, res = Ipa.from_pkg_path(
                    path,
                    cc_overwrite=cc_overwrite,
                    gv_overwrite=gv_overwrite,
                    pkg_folder=pkg_folder,
                    allowed_script_mods=allowed_script_mods,
                    overwrite_pkg=overwrite_pkg,
                )
        else:
            return None, Result(
                False,
                error=f"Extension: {extension} from path: {path} is not recognised",
            )
    except Exception as e:
        return None, Result.from_exception(e)
    return pkg, res


def merge_dataclasses(curr: Any, new: Any):
    """Sync two dataclasses together

    Args:
        curr (Any): The current dataclass
        new (Any): The new dataclass
    """

    if not dataclasses.is_dataclass(curr) or not dataclasses.is_dataclass(new):
        return
    for field in dataclasses.fields(curr):
        curr_value = getattr(curr, field.name)
        new_value = getattr(new, field.name)
        if curr_value is None:
            setattr(curr, field.name, new_value)
            continue
        if isinstance(curr_value, list) and not curr_value:
            setattr(curr, field.name, new_value)
            continue

        merge_dataclasses(curr_value, new_value)


"""Type alias for a package type, can be a tbcml.Apk or tbcml.Ipa"""

File = Path | str | Data | bytes

"""Type alias for a file type, can be a tbcml.Path, str, tbcml.Data, or bytes"""


def load(f: File) -> Data:
    if isinstance(f, Data):
        return f
    elif isinstance(f, bytes):
        return Data(f)
    else:
        return Path(f).read()


from . import (
    anim,
    game_data,
    io,
    crypto,
    langs,
    request,
    server_handler,
    game_version,
    country_code,
    mods,
    result,
)

__all__ = [
    "result",
    "File",
    "load",
    "ModificationType",
    "CSVField",
    "IntCSVField",
    "BoolCSVField",
    "StringCSVField",
    "StrListCSVField",
    "StrTupleCSVField",
    "Modification",
    "ModPath",
    "Mod",
    "SmaliHandler",
    "SmaliSet",
    "Smali",
    "FridaScript",
    "FridaGadgetHelper",
    "ModLoader",
    "CompilationTarget",
    "ShopItem",
    "ItemShop",
    "ItemShop",
    "Enemy",
    "EnemyStats",
    "Cat",
    "CatForm",
    "FormStats",
    "CatFormType",
    "UnitBuy",
    "NyankoPictureBook",
    "CatTalent",
    "CatTalents",
    "CatEvolveText",
    "EnemyStats",
    "Enemy",
    "Localizable",
    "LocalizableItem",
    "Localizable",
    "Stage",
    "StageEnemyData",
    "StageInfo",
    "StageOptionInfo",
    "StageCSV",
    "MapStageDataStage",
    "NonStoryStageInfo",
    "Map",
    "MapType",
    "BCUZip",
    "Ipa",
    "SoundSetting",
    "CharaGroup",
    "Model",
    "Mamodel",
    "UnitAnim",
    "Texture",
    "Rect",
    "AnimModificationType",
    "KeyFrames",
    "KeyFrame",
    "ModelPart",
    "Anim",
    "AnimModificationType",
    "AnimType",
    "CSV",
    "Delimeter",
    "to_str",
    "Apk",
    "Path",
    "PathStr",
    "Data",
    "PaddedInt",
    "Command",
    "CommandResult",
    "LibFiles",
    "Lib",
    "LibPatch",
    "LibPatches",
    "Patch",
    "FuncPatch",
    "StringReplacePatch",
    "ARC",
    "ARCS",
    "JsonFile",
    "FileSize",
    "XML",
    "AudioFile",
    "AudioID",
    "Yaml",
    "BCImage",
    "run_in_threads",
    "run_in_thread",
    "Zip",
    "TempFile",
    "TempFolder",
    "AesCipher",
    "Hash",
    "HashAlgorithm",
    "Random",
    "Hmac",
    "Language",
    "LanguageStr",
    "RequestHandler",
    "Result",
    "ServerFileHandler",
    "EventData",
    "GameVersionSearchError",
    "GamePacks",
    "PackFile",
    "GameFile",
    "CountryCode",
    "CC",
    "GV",
    "GameVersion",
    "AdbHandler",
    "BulkAdbHandler",
    "is_lief_installed",
    "mods",
    "game_data",
    "io",
    "anim",
    "crypto",
    "langs",
    "request",
    "server_handler",
    "game_version",
    "country_code",
    "to_pkg",
    "PKGProgressSignal",
    "LoadingScreen",
    "LogoScreen",
    "MainMenu",
    "GatyaItem",
    "GatyaItemBuy",
    "Matatabi",
    "Pkg",
    "PkgType",
    "merge_dataclasses",
]
