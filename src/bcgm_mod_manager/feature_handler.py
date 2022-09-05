import os
from typing import Any, Optional

from . import (
    apk_handler,
    config_handler,
    game_file_edits,
    helper,
    mod,
    mod_manager,
    mod_browser,
)

def select_mod() -> Optional[mod.Mod]:
    """
    Selects a mod from the list of mods.

    Returns:
        Optional[mod.Mod]: The selected mod.
    """    
    mods = mod_manager.load_mods()
    helper.colored_list(
        list(map(lambda x: mod_manager.get_mod_name(x), mods)), new=helper.Color.GREEN
    )
    choice = helper.get_int(input("Enter an option:"))
    if choice is None:
        helper.colored_text("Invalid choice.", helper.Color.RED)
        helper.colored_text("Please try again.", helper.Color.RED)
        return None
    if choice > 0 and choice <= len(mods):
        return mods[choice - 1]
    helper.colored_text("Invalid choice.", helper.Color.RED)
    helper.colored_text("Please try again.", helper.Color.RED)
    return None
def set_mod_version():
    bc_mod = select_mod()
    if bc_mod is None:
        return
    
    mod_name = mod_manager.get_mod_name(bc_mod)
    helper.colored_text("Setting version of mod: " + mod_name, helper.Color.GREEN)
    mod_version = helper.str_to_gv(input("Enter the game version (e.g 11.7.1):"))
    mod_manager.set_mod_game_version(mod_name, mod_version)

def download_server_packs():
    is_jp = (
        helper.colored_input(
            "Do you want to get the jp version of the game files? (&y&/&n&):"
        )
        == "y"
    )
    apk_handler.download_server_files(is_jp)


def add_file_to_mod() -> None:
    """
    Adds a file to a mod.
    """
    bc_mod = select_mod()
    if bc_mod is None:
        return
    
    mod_name = mod_manager.get_mod_name(bc_mod)
    helper.colored_text("Adding files to mod: " + mod_name, helper.Color.GREEN)
    mod_manager.add_files_to_mod(mod_name)


def extract_all_mods() -> None:
    """
    Extracts all mods.
    """
    mods = mod_manager.load_mods()
    path = os.path.join(mod_manager.get_mod_folder(), "unpacked_mods")
    for mod in mods:
        mod_path = os.path.join(path, mod_manager.get_mod_name(mod))
        mod.unpack(mod_path)
    helper.colored_text("Mods extracted successfully.", helper.Color.GREEN)
    if (
        helper.colored_input(
            "Do you want to open the folder of the content? (&y&/&n&):"
        )
        == "y"
    ):
        os.startfile(path)


def decrypt_all_game_files() -> None:
    """
    Decrypts all game files.
    """
    is_jp = (
        helper.colored_input(
            "Do you want to get the jp version of the game files? (&y&/&n&):"
        )
        == "y"
    )
    helper.colored_text("Loading apk...", helper.Color.GREEN)
    apk = apk_handler.BC_APK("latest", is_jp, apk_handler.BC_APK.get_apk_folder())
    apk.download()
    helper.colored_text("Extracting apk...", helper.Color.GREEN)
    apk.extract()
    helper.colored_text("Decrypting game files...", helper.Color.GREEN)
    apk.decrypt()

    if (
        helper.colored_input(
            "Do you want to open the decrypted files folder? (&y&/&n&):"
        )
        == "y"
    ):
        os.startfile(apk.decrypted_path)


def open_mod_folder() -> None:
    """
    Opens the mod folder.
    """
    os.startfile(mod_manager.get_mod_folder())


def enable_mods() -> None:
    """
    Enables mods.
    """
    mods = mod_manager.get_disabled_mods()
    if not mods:
        helper.colored_text("No mods disabled.", helper.Color.RED)
        return
    helper.colored_list(
        list(map(lambda x: mod_manager.get_mod_name(x), mods)), new=helper.Color.GREEN
    )
    choices = helper.colored_input(
        "\nEnter an option (You can enter multiple numbers separated by spaces to select multiple at once):"
    ).split(" ")
    for choice in choices:
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        choice = helper.get_int(choice)
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        if choice > 0 and choice <= len(mods):
            helper.colored_text(
                "Enabling mod: " + mod_manager.get_mod_name(mods[choice - 1]),
                helper.Color.GREEN,
            )
            mod_manager.enable_mod(mod_manager.get_mod_name(mods[choice - 1]))


def disable_mods() -> None:
    """
    Disables mods.
    """
    mods = mod_manager.get_enabled_mods()
    if not mods:
        helper.colored_text("No mods enabled.", helper.Color.RED)
        return
    helper.colored_list(
        list(map(lambda x: mod_manager.get_mod_name(x), mods)), new=helper.Color.GREEN
    )
    choices = helper.colored_input(
        "\nEnter an option (You can enter multiple numbers separated by spaces to select multiple at once):"
    ).split(" ")
    for choice in choices:
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        choice = helper.get_int(choice)
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        if choice > 0 and choice <= len(mods):
            helper.colored_text(
                "Disabling mod: " + mod_manager.get_mod_name(mods[choice - 1]),
                helper.Color.GREEN,
            )
            mod_manager.disable_mod(mod_manager.get_mod_name(mods[choice - 1]))


def add_mods() -> None:
    """
    Adds mods to the mod list.
    """
    files = helper.select_files(
        title="Select mods to add", file_types=[("Mod", mod.Mod.get_extension())]
    )
    for file in files:
        bc_mod = mod.Mod.load_from_mod_file(file)
        mod_manager.add_mod(bc_mod)
    helper.colored_text("Mods added successfully.", helper.Color.GREEN)


def remove_mods() -> None:
    """
    Removes mods from the mod list.
    """
    mods = mod_manager.load_mods()
    if not mods:
        helper.colored_text("No mods found.", helper.Color.RED)
        return
    helper.colored_list(
        list(map(lambda x: mod_manager.get_mod_name(x), mods)), new=helper.Color.GREEN
    )
    choices = helper.colored_input(
        "\nEnter an option (You can enter multiple numbers separated by spaces to select multiple at once):"
    ).split(" ")
    for choice in choices:
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        choice = helper.get_int(choice)
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            return
        if choice > 0 and choice <= len(mods):
            helper.colored_text(
                "Removing mod: " + mod_manager.get_mod_name(mods[choice - 1]),
                helper.Color.GREEN,
            )
            mod_manager.remove_mod(mod_manager.get_mod_name(mods[choice - 1]))


def create_mod() -> None:
    """
    Creates a mod.
    """
    name = helper.colored_input("Enter the name of the mod:")
    author = helper.colored_input("Enter the author of the mod:")
    description = helper.colored_input("Enter the description of the mod:")
    game_version = helper.colored_input(
        "Enter the game version of the mod (e.g 11.7.1):"
    )
    country_code = helper.colored_input(
        "Enter the country code of the mod (e.g en, jp, kr, tw):"
    )
    cc = "jp" if country_code == "jp" else ""
    files = helper.select_files(
        title="Select files to add to the mod",
        initial_dir=os.path.join(
            config_handler.get_config_setting("apk_folder"),
            game_version + cc,
            "Modified Files",
        ),
    )

    mod_manager.create_mod(
        name=name,
        author=author,
        description=description,
        game_version=game_version,
        country_code=country_code,
        files=files,
    )
    helper.colored_text("Mod created successfully.", helper.Color.GREEN)

def decrypt_files(files: list[str], version: str, is_jp: bool, output_path: str) -> None:
    """
    Decrypts files.
    Args:
        files (list[str]): The files to decrypt.
        version (str): The game version.
        is_jp (bool): Whether the files are for the jp version.
        output_path (str): The output path.
    """    
    apk = apk_handler.BC_APK(version, is_jp, output_path)
    apk.decrypted_path = os.path.dirname(apk.decrypted_path)
    apk.download()
    apk.extract()
    for file in files:
        apk.decrypt_pack(os.path.join(apk.packs_path, file + ".pack"))
        os.rename(os.path.join(apk.decrypted_path, file + ".pack"), os.path.join(apk.decrypted_path, file.replace(".pack", "")))

def exit_manager() -> None:
    """
    Exits the mod manager.
    """
    helper.colored_text("\nExiting modder.", helper.Color.GREEN)
    exit()


def load_mods_into_game() -> None:
    """
    Loads mods into the game.
    """
    game_version = mod_manager.get_newest_mod_version()
    if game_version is None:
        helper.colored_text("No mods found.", helper.Color.RED)
        return
    is_jp = helper.colored_input("Are you using a jp version? (&y&/&n&):") == "y"

    if not mod_manager.load_mods_into_game(helper.gv_to_str(game_version), is_jp):
        helper.colored_text("\nFailed to load mods into the apk.", helper.Color.RED)
        return

    helper.colored_text("\nSuccessfully loaded mods into the apk.", helper.Color.GREEN)
    apk_path = os.path.abspath(
        os.path.join(
            apk_handler.BC_APK.get_apk_folder(),
            helper.gv_to_str(game_version),
            "modded.apk",
        )
    )
    helper.colored_text(
        f"\n&The apk can be found here: &{apk_path}",
        helper.Color.GREEN,
        helper.Color.WHITE,
    )
    if (
        helper.colored_input(
            "Would you like to open the folder containing the apk? (&y&/&n&):"
        )
        == "y"
    ):
        os.startfile(os.path.dirname(apk_path))
    helper.colored_text("Please re-install the game", helper.Color.GREEN)


OPTIONS: dict[str, Any] = {
    "Display mods": mod_manager.display_mods,
    "Load enabled mods into apk": load_mods_into_game,
    "Mod Management": {
        "Enable mods": enable_mods,
        "Disable mods": disable_mods,
        "Add game files to mod": add_file_to_mod,
        "Remove mods": remove_mods,
        "Load mods from .bcmod files": add_mods,
        "Create mod from game files": create_mod,
        "Load enabled mods into apk": load_mods_into_game,
        "Open mods folder in explorer": open_mod_folder,
        "Set mod game version": set_mod_version,
    },
    "Data Decryption / Extraction / Download": {
        "Extract all mods into game files": extract_all_mods,
        "Decrypt all game files": decrypt_all_game_files,
        "Download server pack files": download_server_packs,
    },
    "Edit Game Files": {
        "Edit cat stats (unit*.csv)": game_file_edits.unit_mod.edit_unit,
        "Edit stage data (stage*.csv)": game_file_edits.stage_mod.edit_stage,
        "Edit enemy data (t_unit.csv)": game_file_edits.enemy_mod.edit_enemy,
        "Import bcu data": game_file_edits.import_from_bcu.import_from_bcu,
        "Add enemies as cats": game_file_edits.add_enemy_as_cat.import_enemy,
    },
    "Set Config Settings": {
        "Set apk folder": config_handler.set_apk_folder,
        "Set mod folder": config_handler.set_mod_folder,
        "Set apk copy path": config_handler.set_apk_copy_path,
        "Set mod repo": config_handler.set_mod_repo,
    },
    "Search For Mods": mod_browser.search_mods,
    "Exit": exit_manager,
}


def get_feature(
    selected_features: Any, search_string: str, results: dict[str, Any]
) -> dict[str, Any]:
    """Search for a feature if the feature name contains the search string"""

    for feature in selected_features:
        feature_data = selected_features[feature]
        if isinstance(feature_data, dict):
            feature_data = get_feature(feature_data, search_string, results)
        if search_string.lower().replace(" ", "") in feature.lower().replace(" ", ""):
            results[feature] = selected_features[feature]
    return results


def show_options(features_to_use: dict[str, Any]) -> None:
    """Allow the user to either enter a feature number or a feature name, and get the features that match"""

    prompt = "What do you want to do?(some options contain other features within them)"
    prompt += "\nYou can enter a number to run a feature or a word to search for that feature (e.g entering enable mod will run the Enable Mods feature)\nYou can press enter to see a list of all of the features"
    user_input = helper.colored_input(f"{prompt}:\n")
    user_int = helper.get_int(user_input)
    results = []
    if user_int is None:
        results = get_feature(features_to_use, user_input, {})
    else:
        if user_int < 1 or user_int > len(features_to_use) + 1:
            helper.colored_text("Value out of range", helper.Color.RED)
            return show_options(features_to_use)
        if OPTIONS != features_to_use:
            if user_int - 2 < 0:
                return menu()
            results = features_to_use[list(features_to_use)[user_int - 2]]
        else:
            results = features_to_use[list(features_to_use)[user_int - 1]]
    if not isinstance(results, dict):
        return results()
    if len(results) == 0:
        helper.colored_text("No feature found with that name.", helper.Color.RED)
        return menu()
    if len(results) == 1 and isinstance(list(results.values())[0], dict):
        results = results[list(results)[0]]
    if len(results) == 1:
        return results[list(results)[0]]()

    helper.colored_list(["Go Back"] + list(results))
    return show_options(results)


def menu() -> None:
    """
    The main menu.
    """
    while True:
        helper.colored_text("\nMod Manager", helper.Color.GREEN)
        helper.colored_list(list(OPTIONS))
        show_options(OPTIONS)
