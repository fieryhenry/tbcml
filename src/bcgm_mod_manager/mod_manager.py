import json
import os
from typing import Any, Optional
from . import helper, mod, apk_handler

def add_files_to_mod(mod_name: str):
    files = helper.select_files("Select files to add to mod")
    mod_folder = get_mod_folder()
    mod_file = os.path.join(mod_folder, mod_name + mod.Mod.get_extension())
    bc_mod = mod.Mod.load_from_mod_file(mod_file)
    mods = load_mods()
    for bc_mod in mods:
        if get_mod_name(bc_mod) == mod_name:
            bc_mod.add_files(files, "DownloadLocal")
    enable_mod(mod_name)
    save_mods(mods)

def load_mods() -> list[mod.Mod]:
    """
    Loads all mods from the mod folder.

    Returns:
        list[mod.Mod]: List of all mods.
    """
    check_mod_info()
    mod_folder = get_mod_folder()
    mods: list[mod.Mod] = []
    for mod_file in helper.get_files(mod_folder):
        if mod_file.endswith(mod.Mod.get_extension()):
            mods.append(mod.Mod.load_from_mod_file(mod_file))
    return mods


def get_enabled_mods() -> list[mod.Mod]:
    """
    Gets all enabled mods.

    Returns:
        list[mod.Mod]: List of all enabled mods.
    """
    mods = load_mods()
    enabled_mods: list[mod.Mod] = []
    for bc_mod in mods:
        if get_mod_name(bc_mod) in get_mod_info()["enabled_mods"]:
            enabled_mods.append(bc_mod)
    return enabled_mods


def get_disabled_mods() -> list[mod.Mod]:
    """
    Gets all disabled mods.

    Returns:
        list[mod.Mod]: List of all disabled mods.
    """
    mods = load_mods()
    disabled_mods: list[mod.Mod] = []
    for bc_mod in mods:
        if get_mod_name(bc_mod) not in get_mod_info()["enabled_mods"]:
            disabled_mods.append(bc_mod)
    return disabled_mods


def get_mod_info() -> dict[str, Any]:
    """
    Gets the mod info.

    Returns:
        dict[str, Any]: The mod info.
    """
    mod_folder = get_mod_folder()
    generate_mod_info()
    modinfo = helper.read_file_bytes(os.path.join(mod_folder, "info.json"))
    return json.loads(modinfo.decode("utf-8"))


def write_modinfo(modinfo: dict[str, Any]) -> None:
    """
    Writes the mod info.

    Args:
        modinfo (dict[str, Any]): The mod info.
    """
    mod_folder = get_mod_folder()
    helper.write_file_bytes(
        os.path.join(mod_folder, "info.json"), json.dumps(modinfo, indent=4).encode("utf-8")
    )

def check_mod_info() -> None:
    """
    Removes all mods that are not in the mod folder.
    """
    mod_folder = get_mod_folder()
    modinfo = get_mod_info()
    for mod_name in modinfo["enabled_mods"]:
        if not os.path.exists(os.path.join(mod_folder, mod_name + mod.Mod.get_extension())):
            modinfo["enabled_mods"].remove(mod_name)
    write_modinfo(modinfo)

def generate_mod_info() -> None:
    """
    Generates the mod info.
    """
    mod_folder = get_mod_folder()
    if os.path.exists(os.path.join(mod_folder, "info.json")):
        return
    modinfo: dict[str, Any] = {"enabled_mods": []}
    write_modinfo(modinfo)

def load_mods_into_game(game_version: str, is_jp: bool) -> bool:
    """
    Loads all mods into the game.

    Args:
        game_version (str): The game version.
        is_jp (bool): If the game is a JP game.

    Returns:
        bool: If the loading was successful.
    """
    enabled_pack = pack_enabled_mods(is_jp)
    if enabled_pack.mismatch_version():
        helper.colored_text("WARNING: The enabled mods contain both jp and non-jp mods!", helper.Color.RED)
    for bc_mod in enabled_pack.mods:
        if bc_mod.do_mod_info:
            enabled_pack.add_to_mod_info(bc_mod)
    apk = apk_handler.BC_APK(game_version, is_jp, apk_handler.BC_APK.get_apk_folder())
    if not apk.download():
        return False
    base_mod = apk.get_as_mod(["DownloadLocal"])
    enabled_pack.add_mod(base_mod)
    apk.load_mod(enabled_pack)
    apk.copy_apk(helper.get_config_value("apk_copy_path"))
    return True

def get_oldest_mod_version() -> Optional[int]:
    """
    Gets the oldest mod version.

    Returns:
        int: The oldest mod version.
    """    
    enabled_mods = get_enabled_mods()
    oldest_mod_version = None
    for mod in enabled_mods:
        if oldest_mod_version is None or mod.game_version < oldest_mod_version:
            oldest_mod_version = mod.game_version
    return oldest_mod_version

def get_newest_mod_version() -> Optional[int]:
    """
    Gets the newest mod version.

    Returns:
        int: The newest mod version.
    """
    enabled_mods = get_enabled_mods()
    newest_mod_version = None
    for mod in enabled_mods:
        if newest_mod_version is None or mod.game_version > newest_mod_version:
            newest_mod_version = mod.game_version
    return newest_mod_version

def save_mods(mods: list[mod.Mod]) -> None:
    """
    Saves all mods.

    Args:
        mods (list[mod.Mod]): List of all mods.
    """
    mod_folder = get_mod_folder()
    for bc_mod in mods:
        data = bc_mod.export()
        helper.write_file_bytes(os.path.join(mod_folder, get_mod_name(bc_mod) + mod.Mod.get_extension()), data)

def get_mod_folder() -> str:
    """
    Gets the mod folder.

    Returns:
        str: The path to the mod folder.
    """

    mod_folder = os.path.abspath(helper.get_config_value("mod_folder"))
    helper.check_dir(mod_folder)
    return mod_folder


def get_mod(mod_name: str) -> Optional[mod.Mod]:
    """
    Gets a mod by its name.

    Args:
        mod_name (str): Name of the mod.

    Returns:
        mod.Mod: The mod.
    """
    mod_name = trim_mod_extension(mod_name)
    for mod in load_mods():
        if get_mod_name(mod) == mod_name:
            return mod
    return None

def trim_mod_extension(file_name: str) -> str:
    """
    Trims the mod extension.

    Args:
        file_name (str): The file name.
    """
    if file_name.endswith(mod.Mod.get_extension()):
        return file_name[:-(len(mod.Mod.get_extension()))]
    return file_name

def trim_pack_extension(file_name: str) -> str:
    """
    Trims the pack extension.

    Args:
        file_name (str): The file name.
    """
    if file_name.endswith(mod.ModPack.get_extension()):
        return file_name[:-(len(mod.ModPack.get_extension()))]
    return file_name

def pack_enabled_mods(is_jp: bool) -> mod.ModPack:
    """
    Packs enabled mods into a mod pack.

    Returns:
        mod.ModPack: The mod pack.
    """
    mods = get_enabled_mods()
    modpack = mod.ModPack(is_jp)

    modpack.add_mods(mods)
    return modpack


def create_mod_pack(name: str, is_jp: bool
) -> None:
    """
    Creates a mod pack.

    Args:
        name (str): The name of the mod pack.
    """
    name = trim_pack_extension(name)
    modpack = pack_enabled_mods(is_jp)
    if modpack.mismatch_version():
        helper.colored_text("WARNING: Both jp and non-jp mods are enabled. This could cause issues.", helper.Color.RED)
    data = modpack.export()
    mod_folder = get_mod_folder()
    helper.write_file_bytes(os.path.join(mod_folder, name + mod.ModPack.get_extension()), data)


def create_mod(
    name: str,
    description: str,
    game_version: str,
    author: str,
    country_code: str,
    files: list[str],
) -> None:
    """
    Creates a mod.

    Args:
        name (str): Name of the mod.
        description (str): Description of the mod.
        game_version (str): Game version of the mod.
        author (str): Author of the mod.
        country_code (str): Country code of the mod.
        files (list[str]): List of files to add to the mod.
    """
    bc_mod = mod.Mod(
        name=name,
        author=author,
        description=description,
        game_version=int(helper.str_to_gv(game_version)),
        country_code=country_code,
    )
    bc_mod.add_files(files, "DownloadLocal")
    add_mod(bc_mod)


def enable_mod(mod_name: str) -> None:
    """
    Enables a mod.

    Args:
        mod_name (str): Name of the mod.
    """
    mod_name = trim_mod_extension(mod_name)
    modinfo = get_mod_info()
    if mod_name not in modinfo["enabled_mods"]:
        modinfo["enabled_mods"].append(mod_name)
        write_modinfo(modinfo)


def disable_mod(mod_name: str) -> None:
    """
    Disables a mod.

    Args:
        mod_name (str): Name of the mod.
    """
    mod_name = trim_mod_extension(mod_name)
    modinfo = get_mod_info()
    if mod_name in modinfo["enabled_mods"]:
        modinfo["enabled_mods"].remove(mod_name)
        write_modinfo(modinfo)



def display_mods() -> None:
    """
    Displays all mods.
    """
    enabled_mods = get_enabled_mods()
    helper.colored_text("\nEnabled mods:", helper.Color.GREEN)
    for enabled_mod in enabled_mods:
        helper.colored_text(enabled_mod.format())
    disabled_mods = get_disabled_mods()
    helper.colored_text("Disabled mods:", helper.Color.RED)
    for disabled_mod in disabled_mods:
        helper.colored_text(disabled_mod.format())

def get_mod_name(mod: mod.Mod) -> str:
    """
    Gets the mod name.

    Args:
        mod (mod.Mod): The mod.
    """
    return mod.author + "-" + mod.name

def add_mod(mod: mod.Mod):
    mods = load_mods()
    mods.append(mod)
    enable_mod(get_mod_name(mod))
    save_mods(mods)


def remove_mod(mod_name: str) -> None:
    """
    Removes a mod.

    Args:
        mod_name (str): Name of the mod.
    """
    mod_name = trim_mod_extension(mod_name)
    mods = load_mods()
    bc_mod = get_mod(mod_name)
    if bc_mod is None:
        helper.colored_text("Mod not found.", helper.Color.RED)
        return

    for i in range(len(mods)):
        if get_mod_name(mods[i]) == mod_name:
            del mods[i]
            break
    os.remove(os.path.join(get_mod_folder(), get_mod_name(bc_mod) + mod.Mod.get_extension()))
    disable_mod(get_mod_name(bc_mod))
    save_mods(mods)


def add_modpack(modpack: mod.ModPack) -> None:
    """
    Adds a modpack.

    Args:
        modpack (mod.ModPack): The modpack.
    """
    mods = load_mods()
    for mod in modpack.mods:
        mods.append(mod)
        enable_mod(get_mod_name(mod))
    save_mods(mods)
