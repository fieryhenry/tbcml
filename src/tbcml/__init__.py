__version__ = "2.0.0"

from typing import Union, Optional
from .mods.bc_mod import (
    Mod,
    Modification,
    ModificationType,
    ModPath,
)
from .mods.smali import SmaliHandler, SmaliSet, Smali
from .mods.frida_script import FridaScript, FridaGadgetHelper
from .mods.loader import ModLoader
from .mods.ipaloader import IpaModLoader
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
from .game_data.battle.chara_group import CharaGroup

from .anim.model import (
    Model,
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
from .io.audio import AudioFile
from .io.bc_image import BCImage
from .io.thread_helper import run_in_threads, run_in_thread
from .io.zip import Zip
from .io.ipa import Ipa
from .io.temp_file import TempFile, TempFolder
from .crypto import AesCipher, Hash, HashAlgorithm, Random, Hmac
from .langs import Language, LanguageStr
from .request import RequestHandler
from .server_handler import ServerFileHandler, EventData, GameVersionSearchError
from .game_data.pack import GamePacks, PackFile, GameFile
from .country_code import CountryCode, CC
from .game_version import GameVersion, GV

LOADER = Union["ModLoader", "IpaModLoader"]


def to_apk(
    path: "PathStr",
    cc_overwrite: Optional["CountryCode"] = None,
    gv_overwrite: Optional["GameVersion"] = None,
    pkg_folder: Optional["Path"] = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> Optional["Apk"]:
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
    path: "PathStr",
    cc_overwrite: Optional["CountryCode"] = None,
    gv_overwrite: Optional["GameVersion"] = None,
    pkg_folder: Optional["Path"] = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> Optional["Ipa"]:
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
    path: "PathStr",
    cc_overwrite: Optional["CountryCode"] = None,
    gv_overwrite: Optional["GameVersion"] = None,
    pkg_folder: Optional["Path"] = None,
    allowed_script_mods: bool = True,
    skip_signature_check: bool = False,
    overwrite_pkg: bool = True,
) -> Optional[Pkg]:
    path = Path(path)
    extension = path.get_extension()
    pkg = None
    try:
        if extension == "apk":
            pkg = Apk.try_get_pkg_from_path(path, all_pkg_dir=pkg_folder)
            if pkg is None:
                pkg = Apk.from_pkg_path(
                    path,
                    cc_overwrite=cc_overwrite,
                    gv_overwrite=gv_overwrite,
                    pkg_folder=pkg_folder,
                    allowed_script_mods=allowed_script_mods,
                    skip_signature_check=skip_signature_check,
                    overwrite_pkg=overwrite_pkg,
                )
        elif extension == "ipa":
            pkg = Ipa.try_get_pkg_from_path(path, all_pkg_dir=pkg_folder)
            if pkg is None:
                pkg = Ipa.from_pkg_path(
                    path,
                    cc_overwrite=cc_overwrite,
                    gv_overwrite=gv_overwrite,
                    pkg_folder=pkg_folder,
                    allowed_script_mods=allowed_script_mods,
                    overwrite_pkg=overwrite_pkg,
                )
    except Exception:
        pass
    return pkg


"""Type alias for a package type, can be a tbcml.Apk or tbcml.Ipa"""

File = Union[
    Path,
    str,
    Data,
    bytes,
]
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
)

__all__ = [
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
    "IpaModLoader",
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
    "ServerFileHandler",
    "EventData",
    "GameVersionSearchError",
    "GamePacks",
    "PackFile",
    "GameFile",
    "CountryCode",
    "CC",
    "GV",
    "LOADER",
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
    "Pkg",
    "PkgType",
]
