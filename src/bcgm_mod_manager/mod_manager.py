import json
import os
from typing import Any, Optional

from alive_progress import alive_bar  # type: ignore

from . import apk_handler, config_handler, helper, mod


def add_files_to_mod(mod_name: str):
    files = helper.select_files("Select files to add to mod")
    mod_folder = get_mod_folder()
    mod_file = os.path.join(mod_folder, mod_name)
    bc_mod = mod.Mod.load_from_mod_file(mod_file)
    apk = apk_handler.BC_APK(
        helper.gv_to_str(bc_mod.game_version),
        bc_mod.is_jp(),
        config_handler.get_config_setting("apk_folder"),
        False,
    )
    apk.download()
    helper.colored_text(f"Extracting apk...", helper.Color.GREEN)
    apk.extract()
    bc_mod = get_mod_from_name(mod_name)
    if bc_mod is None:
        return
    lists = apk.get_lists()
    file_lists = apk.get_files(lists)
    with alive_bar(len(files), title=f"Adding Files to Mod: {bc_mod.get_name()}") as bar:  # type: ignore
        for file in files:
            packname = file_lists.get(os.path.basename(file))
            if packname is not None:
                packname = apk.convert_server_to_local(packname)
                bc_mod.add_file(file, packname.replace(".list", ""))
            else:
                helper.colored_text(
                    "WARNING: File not found in the game files (maybe download server packs?). For now this file will be included with a different pack and should still work in game: "
                    + file,
                    helper.Color.RED,
                )
                bc_mod.add_file(file, "DownloadLocal")
            bar()
    enable_mod(mod_name)
    helper.colored_text(
        "Saving mod..."
    )
    save_mod(bc_mod)


def get_mod_from_name(mod_name: str) -> Optional[mod.Mod]:
    """
    Gets the mod from the name.

    Args:
        mod_name (str): The mod name.

    Returns:
        Optional[mod.Mod]: The mod.
    """
    mods = load_mods()
    for bc_mod in mods:
        if get_mod_name(bc_mod) == mod_name:
            return bc_mod
    return None


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
        os.path.join(mod_folder, "info.json"),
        json.dumps(modinfo, indent=4).encode("utf-8"),
    )


def check_mod_info() -> None:
    """
    Removes all mods that are not in the mod folder.
    """
    mod_folder = get_mod_folder()
    modinfo = get_mod_info()
    for mod_name in modinfo["enabled_mods"]:
        if not os.path.exists(os.path.join(mod_folder, mod_name)):
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
    mods = prepare_mods(is_jp, True)
    if mod.has_mismatched_version(mods):
        helper.colored_text(
            "WARNING: The enabled mods contain both jp and non-jp mods!",
            helper.Color.RED,
        )
    apk = apk_handler.BC_APK(
        game_version, is_jp, apk_handler.BC_APK.get_apk_folder(), True
    )
    if not apk.download():
        return False
    bc_mod = mod.combine_mods(mods)
    print("Extracting base game files...")
    apk.extract()
    all_pack_names = mod.get_all_unique_pack_names(mods)
    print("Adding mods...")
    for pack_name in all_pack_names:
        base_mod = apk.get_as_mod([pack_name])
        bc_mod.import_mod(base_mod, overwite=False)
    apk.load_mod(bc_mod)
    apk.copy_apk(
        os.path.join(config_handler.get_config_setting("apk_copy_path"), "base.apk")
    )
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
    Saves the mods.

    Args:
        mods (list[mod.Mod]): The mods.
    """
    mod_folder = get_mod_folder()
    for bc_mod in mods:
        data = bc_mod.export()
        helper.write_file_bytes(os.path.join(mod_folder, get_mod_name(bc_mod)), data)


def save_mod(mod: mod.Mod) -> None:
    """
    Saves the mod.

    Args:
        mod (mod.Mod): The mod.
    """
    save_mods([mod])


def get_mod_folder() -> str:
    """
    Gets the mod folder.

    Returns:
        str: The path to the mod folder.
    """

    mod_folder = os.path.abspath(config_handler.get_config_setting("mod_folder"))
    helper.check_dir(mod_folder)
    return mod_folder


def get_mod(mod_name: str) -> Optional[mod.Mod]:
    """
    Gets the mod.

    Args:
        mod_name (str): The mod name.

    Returns:
        Optional[mod.Mod]: The mod.
    """
    for mod in load_mods():
        if get_mod_name(mod) == mod_name:
            return mod
    return None

def set_mod_game_version(mod_name: str, game_version: int) -> None:
    """
    Sets the mod game version.

    Args:
        mod_name (str): The mod name.
        game_version (int): The game version.
    """
    mod = get_mod(mod_name)
    if mod is None:
        return
    mod.game_version = game_version
    save_mod(mod)


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
        game_version=helper.str_to_gv(game_version),
        country_code=country_code,
    )
    helper.colored_text(
        f"Creating mod: &{bc_mod.get_name()}&", helper.Color.WHITE, helper.Color.GREEN
    )
    apk = apk_handler.BC_APK(
        game_version, bc_mod.is_jp(), apk_handler.BC_APK.get_apk_folder()
    )
    apk.download()
    helper.colored_text(f"Extracting apk...", helper.Color.GREEN)
    apk.extract()
    helper.colored_text(f"Creating mod files...")
    lists = apk.get_lists()
    file_lists = apk.get_files(lists)
    with alive_bar(len(files), title=f"Adding Files to Mod: {bc_mod.get_name()}") as bar:  # type: ignore
        for file in files:
            pack_name = file_lists.get(os.path.basename(file))
            if pack_name is None:
                helper.colored_text(
                    "WARNING: File not found in the game files (maybe download server packs?). For now this file will be included with a different pack and should still work in game: "
                    + file,
                    helper.Color.RED,
                )
                bc_mod.add_file(
                    file, "DownloadLocal"
                )  # download local because no hash is tracked, has no other langs, not a server pack, and has little files already -> reduces file size + decreased encryption time
            else:
                pack_name = apk.convert_server_to_local(pack_name)
                bc_mod.add_file(file, pack_name.replace(".list", ""))
            bar()
    add_mod(bc_mod)


def enable_mod(mod_name: str) -> None:
    """
    Enables a mod.

    Args:
        mod_name (str): Name of the mod.
    """
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
    return mod.get_name() + mod.get_extension()

def prepare_mods(
    is_jp: bool,
    create_mod_info: bool,
) -> list[mod.Mod]:
    """
    Prepares the mods.

    Returns:
        list[mod.Mod]: The list of mods.
    """
    mods = get_enabled_mods()
    mod_log = ""
    all_mods: list[mod.Mod] = []

    for bc_mod in mods:
        all_mods.append(bc_mod)
        if bc_mod.do_mod_info:
            mod_log = mod.add_mod_to_mod_info(mod_log, bc_mod)
    if create_mod_info:
        mod_log_mod = mod.write_mod_log(mod_log, is_jp)
        all_mods.append(mod_log_mod)
    return all_mods

def add_mod(mod: mod.Mod) -> None:
    """
    Adds a mod to the mod folder.

    Args:
        mod (mod.Mod): The mod to add.
    """
    mods = load_mods()
    mods.append(mod)
    enable_mod(get_mod_name(mod))
    helper.colored_text(
        "Saving mod..."
    )
    save_mod(mod)


def remove_mod(mod_name: str) -> None:
    """
    Removes a mod.

    Args:
        mod_name (str): Name of the mod.
    """
    mods = load_mods()
    bc_mod = get_mod(mod_name)
    if bc_mod is None:
        helper.colored_text("Mod not found.", helper.Color.RED)
        return

    for i in range(len(mods)):
        if get_mod_name(mods[i]) == mod_name:
            del mods[i]
            break
    os.remove(os.path.join(get_mod_folder(), get_mod_name(bc_mod)))
    disable_mod(get_mod_name(bc_mod))
