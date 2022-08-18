import os
from . import mod_manager, helper, mod, apk_handler


def menu() -> None:
    """
    The main menu.
    """    
    options = {
        "Display mods": mod_manager.display_mods,
        "Enable mods": enable_mods,
        "Disable mods": disable_mods,
        "Load mods from .bcmod files": add_mods,
        "Remove mods": remove_mods,
        "Create mod from game files": create_mod,
        "Add game files to mod": add_file_to_mod,
        "Extract all mods into game files": extract_all_mods,
        "Load enabled mods into apk": load_mods_into_game,
        "Load mod packs from .bcmodpack files as mods": add_mod_packs,
        "Create mod pack of enabled mods": create_mod_pack,
        "Open mods folder in explorer": open_mod_folder,
        "Decrypt all local game files": decrypt_all_game_files,
        "Exit": exit_manager,
    }
    while True:
        print()
        helper.colored_text("Mod Manager", helper.Color.GREEN)
        helper.colored_list(list(options.keys()), new=helper.Color.GREEN)
        choice = helper.get_int(input("Enter an option:"))
        if choice is None:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)
            continue
        if choice > 0 and choice <= len(options):
            list(options.values())[choice - 1]()
        else:
            helper.colored_text("Invalid choice.", helper.Color.RED)
            helper.colored_text("Please try again.", helper.Color.RED)

def add_file_to_mod() -> None:
    """
    Adds a file to a mod.
    """    
    mods = mod_manager.get_enabled_mods()
    helper.colored_list(
        list(map(lambda x: mod_manager.get_mod_name(x), mods)), new=helper.Color.GREEN
    )
    choice = helper.get_int(input("Enter an option:"))
    if choice is None:
        helper.colored_text("Invalid choice.", helper.Color.RED)
        helper.colored_text("Please try again.", helper.Color.RED)
        return
    if choice > 0 and choice <= len(mods):
        mod_name = mod_manager.get_mod_name(mods[choice - 1])
        helper.colored_text(
            "Adding file to mod: " + mod_name, helper.Color.GREEN
        )
        mod_manager.add_files_to_mod(mod_name)
    else:
        helper.colored_text("Invalid choice.", helper.Color.RED)
        helper.colored_text("Please try again.", helper.Color.RED)

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
    if helper.colored_input("Do you want to open the folder of the content? (&y&/&n&):") == "y":
        os.startfile(path)

def decrypt_all_game_files() -> None:
    """
    Decrypts all game files.
    """    
    is_jp = helper.colored_input("Do you want to get the jp version of the game files? (&y&/&n&):") == "y"
    helper.colored_text("Loading apk...", helper.Color.GREEN)
    apk = apk_handler.BC_APK("latest", is_jp, apk_handler.BC_APK.get_apk_folder())
    apk.download()
    helper.colored_text("Extracting apk...", helper.Color.GREEN)
    apk.extract()
    helper.colored_text("Decrypting game files...", helper.Color.GREEN)
    apk.decrypt()
    
    if helper.colored_input("Do you want to open the decrypted files folder? (&y&/&n&):") == "y":
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


def add_mod_packs() -> None:
    """
    Adds mod packs to the mod list.
    """
    files = helper.select_files(
        title="Select mod packs to add",
        file_types=[("Mod pack", mod.ModPack.get_extension())],
    )
    for file in files:
        bc_mod_pack = mod.ModPack.load_from_mod_pack(file)
        mod_manager.add_modpack(bc_mod_pack)
    helper.colored_text("Mod packs added successfully.", helper.Color.GREEN)


def create_mod_pack() -> None:
    """
    Creates a mod pack.
    """    
    name = helper.colored_input("Enter the name of the mod pack:")
    author = helper.colored_input("Enter the author of the mod pack:")
    is_jp = helper.colored_input("Is this for the jp version? (&y&/&n&):") == "y"

    name = f"{author}-{name}{mod.ModPack.get_extension()}"

    mod_manager.create_mod_pack(name, is_jp)


def create_mod() -> None:
    """
    Creates a mod.
    """    
    files = helper.select_files(
        title="Select files to add to the mod",
    )
    name = helper.colored_input("Enter the name of the mod:")
    author = helper.colored_input("Enter the author of the mod:")
    description = helper.colored_input("Enter the description of the mod:")
    game_version = helper.colored_input(
        "Enter the game version of the mod (e.g 11.7.1):"
    )
    country_code = helper.colored_input(
        "Enter the country code of the mod (e.g en, jp, kr, tw):"
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
        helper.colored_text("Failed to load mods into game.", helper.Color.RED)
        return

    helper.colored_text("Successfully loaded mods into game.", helper.Color.GREEN)
    apk_path = os.path.abspath(os.path.join(apk_handler.BC_APK.get_apk_folder(), helper.gv_to_str(game_version), 'modded.apk'))
    helper.colored_text(
        f"The apk can be found here: &{apk_path}&",
        helper.Color.GREEN,
        helper.Color.WHITE,
    )
    if helper.colored_input("Would you like to open the folder containing the apk? (&y&/&n&):") == "y":
        os.startfile(os.path.dirname(apk_path))
    helper.colored_text("Please re-install the game", helper.Color.GREEN)


def main() -> None:
    """
    Main function.
    """    
    menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit_manager()
