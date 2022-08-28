import io
import os
from typing import Any, Optional
from .. import game_file_editor, helper
from PIL import Image
import json

def get_form_str(form: int) -> Optional[str]:
    """
    Returns the form string for the given form

    Args:
        form (int): The form to get the string for

    Returns:
        Optional[str]: The form string or None if the form is invalid
    """    
    form_strs = [
        "f",
        "c",
        "s"
    ]
    if form < 0 or form > len(form_strs):
        return None
    return form_strs[form]

def get_form_index(form_str: str):
    forms = [
        "f",
        "c",
        "s"
    ]
    try:
        return forms.index(form_str)
    except ValueError:
        return -1

def make_image(file_path: str, size: tuple[int ,int]) -> bytes:
    """
    Make a 128x128 transparent png
    """
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    img.save(file_path)
    return helper.read_file_bytes(file_path)

def insert_deploy_image(deploy_path: str) -> bytes:
    """
    Copy the deploy image into the centre of a 128x128 transparent png

    Args:
        deply_path (str): _description_
    """    
    transparent_data = make_image("temp.png", (128, 128))
    deploy_data = helper.read_file_bytes(deploy_path)
    if deploy_data is None:
        helper.colored_text("Could not read deploy file")
        return transparent_data
    deploy_img = Image.open(io.BytesIO(deploy_data))
    transparent_img = Image.open(io.BytesIO(transparent_data))
    transparent_img.paste(deploy_img, (9, 21), deploy_img)
    transparent_img.save("temp.png")
    data = helper.read_file_bytes("temp.png")
    os.remove("temp.png")
    return data

def insert_display_image(display_path: str) -> bytes:
    transparent_data = make_image("temp.png", (512, 128))
    display_data = scale_height_display_file(display_path)
    if display_data is None:
        return transparent_data
    display_img = Image.open(io.BytesIO(display_data))
    transparent_img = Image.open(io.BytesIO(transparent_data))
    transparent_img.paste(display_img, (13, 1), display_img)
    transparent_img.save("temp.png")
    data = make_display_bottom_right_transparent("temp.png")
    if data is None:
        return transparent_data
    return data

def scale_height_display_file(display_path: str) -> Optional[bytes]:
    """
    Scale the display file by 3.5x the height
    """
    display_data = helper.read_file_bytes(display_path)
    if display_data is None:
        helper.colored_text("Could not read display file")
        return None
    display_img = Image.open(io.BytesIO(display_data))
    new_height = int(display_img.height * 3.5)
    new_width = int(display_img.width * 3.5)
    display_img = display_img.resize((new_width, new_height), Image.ANTIALIAS)
    display_img.save("temp.png")
    data = helper.read_file_bytes("temp.png")
    os.remove("temp.png")
    return data

def make_display_bottom_right_transparent(display_path: str):
    """
    Make the bottom right corner of the display transparent
    """
    display_data = helper.read_file_bytes(display_path)
    if display_data is None:
        helper.colored_text("Could not read display file")
        return
    display_img = Image.open(io.BytesIO(display_data))
    start_pos = (146, 112)
    end_pos = (188, 70)
    start_offset = 0
    start_width = 311 - start_pos[0]
    for i in range(start_pos[1] - end_pos[1]):
        for j in range(start_width):
            display_img.putpixel((start_pos[0] + j + start_offset, start_pos[1] - i), (0, 0, 0, 0))
        start_width -= 1
        start_offset += 1
    display_img.save("temp.png")
    data = helper.read_file_bytes("temp.png")
    os.remove("temp.png")
    return data



def make_deploy_file(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the deploy file for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the deploy file for
        form_id (int): The form of the cat to create the deploy file for
    """    
    deploy_file = os.path.join(dir_name, "icon_deploy.png")
    if not os.path.exists(deploy_file):
        helper.colored_text("Deploy file not found")
        return
    cat_id_str = str(cat_id).zfill(3)
    final_deploy_file = f"uni{cat_id_str}_{get_form_str(form_id)}00.png"
    deploy_data = editor.read_bytes(deploy_file)
    if deploy_data is None:
        helper.colored_text("Could not read deploy file")
        return
    deploy_data = insert_deploy_image(deploy_file)
    editor.write_bytes(final_deploy_file, deploy_data)

def make_display_file(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the display file for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the display file for
        form_id (int): The form of the cat to create the display file for
    """    
    display_file = os.path.join(dir_name, "icon_display.png")
    if not os.path.exists(display_file):
        helper.colored_text("Display file not found")
        return
    cat_id_str = str(cat_id).zfill(3)
    final_display_file = f"udi{cat_id_str}_{get_form_str(form_id)}.png"
    display_data = editor.read_bytes(display_file)
    if display_data is None:
        helper.colored_text("Could not read display file")
        return
    display_data = insert_display_image(display_file)
    if display_data is None:
        return
    editor.write_bytes(final_display_file, display_data)

def get_cat_id(editor: game_file_editor.GameFileEditor, dir_name: str) -> tuple[int, int]:
    """
    Gets the cat id and form from the given directory

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from

    Returns:
        tuple[int, int]: The cat id and form
    """    
    imgcut_file = os.path.join(dir_name, "imgcut.txt")
    if not os.path.exists(imgcut_file):
        helper.colored_text("Imgcut file not found")
        return -1, -1
    imgcut_data = editor.parse_file(imgcut_file)
    if imgcut_data is None:
        helper.colored_text("Could not read imgcut file")
        return -1, -1
    cat_id = helper.get_int(imgcut_data[2][0][:3])
    if cat_id is None:
        cat_id = 0
    form_str = imgcut_data[2][0][4:5]
    form_index = get_form_index(form_str)
    if form_index == -1:
        form_index = 0
    return cat_id, form_index

def make_imgcut_file(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the imgcut file for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the imgcut file for
        form_id (int): The form of the cat to create the imgcut file for
    """    
    imgcut_file = os.path.join(dir_name, "imgcut.txt")
    if not os.path.exists(imgcut_file):
        helper.colored_text("Imgcut file not found")
        return
    cat_id_str = str(cat_id).zfill(3)
    final_imgcut_file = f"{cat_id_str}_{get_form_str(form_id)}.imgcut"
    imgcut_data = editor.read_bytes(imgcut_file)
    if imgcut_data is None:
        helper.colored_text("Could not read imgcut file")
        return
    editor.write_bytes(final_imgcut_file, imgcut_data, add_padding=False)

def get_maanim_index(anim_name: str):
    moves = [
        "walk",
        "idle",
        "attack",
        "kb"
    ]
    try:
        return moves.index(anim_name)
    except ValueError:
        return -1

def get_burrow_index(burrow_type: str):
    burrows = [
        "burrow_down",
        "burrow_move",
        "burrow_up",
    ]
    try:
        return burrows.index(burrow_type)
    except ValueError:
        return -1

def make_maanim_files(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the maanim files for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the maanim files for
        form_id (int): The form of the cat to create the maanim files for
    """    
    maanim_files = os.listdir(dir_name)
    for maanim_file in maanim_files:
        if not maanim_file.startswith("maanim"):
            continue
        anim_type = os.path.basename(maanim_file).split("_")[1].replace(".txt", "")
        maanim_index = get_maanim_index(anim_type)
        maanim_str = str(maanim_index).zfill(2)
        maanim_data = editor.parse_file(os.path.join(dir_name, maanim_file))
        if maanim_data is None:
            helper.colored_text("Could not read maanim file")
            return
        if maanim_index == -1:
            if "burrow" in anim_type and len(maanim_data) > 4:
                zombie_index = get_burrow_index(anim_type)
                if zombie_index == -1:
                    continue
                maanim_str = "_" + "zombie" + str(zombie_index).zfill(2)
            else:
                continue
        maanim_data[0][0] = "[modelanim:animation]"
        cat_id_str = str(cat_id).zfill(3)
        final_maanim_file = f"{cat_id_str}_{get_form_str(form_id)}{maanim_str}.maanim"
        editor.write_csv(final_maanim_file, maanim_data, add_padding=False)

def make_sprite_file(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the sprite file for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the sprite file for
        form_id (int): The form of the cat to create the sprite file for
    """    
    sprite_file = os.path.join(dir_name, "sprite.png")
    if not os.path.exists(sprite_file):
        helper.colored_text("Sprite file not found")
        return
    cat_id_str = str(cat_id).zfill(3)
    final_sprite_file = f"{cat_id_str}_{get_form_str(form_id)}.png"
    sprite_data = editor.read_bytes(sprite_file)
    if sprite_data is None:
        helper.colored_text("Could not read sprite file")
        return
    editor.write_bytes(final_sprite_file, sprite_data)

def make_mamodel_file(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int):
    """
    Creates the mamodel file for the given cat and form

    Args:
        editor (game_file_editor.GameFileEditor): The game file editor to use
        dir_name (str): The directory to read the files from
        cat_id (int): The cat id to create the mamodel file for
        form_id (int): The form of the cat to create the mamodel file for
    """    
    mamodel_file = os.path.join(dir_name, "mamodel.txt")
    if not os.path.exists(mamodel_file):
        helper.colored_text("Mamodel file not found")
        return
    cat_id_str = str(cat_id).zfill(3)
    final_mamodel_file = f"{cat_id_str}_{get_form_str(form_id)}.mamodel"
    mamodel_data = editor.read_bytes(mamodel_file)
    if mamodel_data is None:
        helper.colored_text("Could not read mamodel file")
        return

    mamodel_data = editor.parse_file(mamodel_file)
    if mamodel_data is None:
        helper.colored_text("Could not parse mamodel file")
        return
    mamodel_data[0][0] = "[modelanim:model]"
    #total_models = mamodel_data[2][0]
    #scaling_index = total_models + 3
    #if len(mamodel_data[scaling_index]) == 3:
    #    mamodel_data[scaling_index].append(1)
    editor.write_csv(final_mamodel_file, mamodel_data, False)


def import_sprites(dir_name: str) -> None:
    if not os.path.exists(dir_name):
        helper.colored_text("Directory not found")
        return
    editor = game_file_editor.GameFileEditor("sprite_mod")
    units = helper.get_folders_in_dir(dir_name)
    for unit_dir in units:
        cat_id, form_id = get_cat_id(editor, unit_dir)
        import_sprite(editor, unit_dir, cat_id, form_id)

def import_sprite(editor: game_file_editor.GameFileEditor, dir_name: str, cat_id: int, form_id: int) -> None:
    make_deploy_file(editor, dir_name, cat_id, form_id)
    make_display_file(editor, dir_name, cat_id, form_id)
    make_maanim_files(editor, dir_name, cat_id, form_id)
    make_sprite_file(editor, dir_name, cat_id, form_id)
    make_mamodel_file(editor, dir_name, cat_id, form_id)
    make_imgcut_file(editor, dir_name, cat_id, form_id)

def import_from_bcu():
    helper.colored_text(
        "Select a folder containing bcu files files (normally in the workspace directory where BCU is installed)"
    )
    dir_name = helper.select_dir("Select folder with BCU files (in workspace)", "")
    if dir_name is None:
        return
    import_pack_json(dir_name, os.path.join(dir_name, "animations"))

def import_pack_json(dir_name: str, animations_dir: str):
    file_path = os.path.join(dir_name, "pack.json")
    if not os.path.exists(file_path):
        helper.colored_text("pack.json not found")
        return
    pack_data = json.loads(helper.read_file_bytes(file_path))
    import_units(pack_data, animations_dir)

def import_units(pack_data: Any, animations_dir: str) -> None:
    editor = game_file_editor.GameFileEditor("unit_mod")
    units: list[Any] = pack_data["units"]["data"]
    for unit_data in units:
        unit_anim_name = unit_data["val"]["forms"][0]["anim"]["id"]
        cat_id, form = get_cat_id(editor, os.path.join(animations_dir, unit_anim_name))
        import_sprite(editor, os.path.join(animations_dir, unit_anim_name), cat_id, form)
        import_unit(editor, unit_data, animations_dir)

def import_unit(editor: game_file_editor.GameFileEditor, unit_data: dict[str, Any], animations_dir: str):
    csv_data: list[list[int]] = []
    cat_id = -1
    for form_data in unit_data["val"]["forms"]:
        unit_anim_name = form_data["anim"]["id"]
        cat_id, form = get_cat_id(editor, os.path.join(animations_dir, unit_anim_name))
        import_sprite(editor, os.path.join(animations_dir, unit_anim_name), cat_id, form)
        unit_csv = get_unit_csv_data(form_data)
        csv_data.append(unit_csv)
    if cat_id == -1:
        return
    copy_count = 3 - len(csv_data)
    for _ in range(copy_count):
        csv_data.append(csv_data[-1])
    editor.write_csv(f"unit{str(cat_id+1).zfill(3)}.csv", csv_data)

def get_unit_csv_data(unit_data: dict[str, Any]) -> list[int]:
    base_stats = unit_data["du"]
    traits = base_stats["traits"]
    procs = base_stats["rep"]["proc"]
    # sort by trait id
    traits = sorted(traits, key=lambda x: x["id"])
    csv_data: list[int] = [
        base_stats["hp"], # hp
        base_stats["hb"], # knockbacks
        base_stats["speed"], # move speed
        base_stats["atks"]["pool"][0]["atk"], # attack damage
        base_stats["tba"], # time between attacks
        base_stats["range"], # attack range
        base_stats["price"], # price to use
        base_stats["resp"], # recharge time
        0, # hit box pos
        base_stats["width"], # width of hit box
        get_trait_by_id(traits, 0), # red
        0, # always 0
        int(base_stats["atks"]["pool"][0]["range"]), # is area attack
        base_stats["atks"]["pool"][0]["pre"], # attack pre
        base_stats["front"], # min z-layer
        base_stats["back"], # max z-layer
        get_trait_by_id(traits, 1), # float
        get_trait_by_id(traits, 2), # black
        get_trait_by_id(traits, 3), # metal
        get_trait_by_id(traits, 9), # traitless
        get_trait_by_id(traits, 4), # angel
        get_trait_by_id(traits, 5), # alien
        get_trait_by_id(traits, 6), # zombie
        check_ability(base_stats["abi"], 0), # strong against
        get_proc_prob(procs, "KB"), # knockback probability
        get_proc_prob(procs, "STOP"), # freeze probability
        get_proc_time(procs, "STOP"), # freeze duration
        get_proc_prob(procs, "SLOW"), # slow probability
        get_proc_time(procs, "SLOW"), # slow duration
        check_ability(base_stats["abi"], 1), # resist
        check_ability(base_stats["abi"], 2), # triple
        get_proc_prob(procs, "CRIT"), # crit probability
        check_ability(base_stats["abi"], 3), # only attacks
        get_proc_mult(procs, "BOUNTY") // 100, # exta money mult
        get_proc_mult(procs, "ATKBASE") // 300, # base destroyer mult
        max(get_proc_prob(procs, "WAVE"), get_proc_prob(procs, "MINIWAVE")), # wave probability
        max(get_proc_level(procs, "WAVE"), get_proc_level(procs, "MINIWAVE")), # wave level
        get_proc_prob(procs, "WEAK"), # weaken probability
        get_proc_time(procs, "WEAK"), # weaken duration
        get_proc_mult(procs, "WEAK"), # weaken level
        get_proc_health(procs, "STRONG"), # hp remain strength
        get_proc_mult(procs, "STRONG"), # boost health mult
        get_proc_prob(procs, "LETHAL"), # survive lethal hit probability
        check_ability(base_stats["abi"], 4), # metal
        base_stats["atks"]["pool"][0]["ld0"], # long distance start
        base_stats["atks"]["pool"][0]["ld1"], # long distance range
        get_proc_mult(procs, "IMUWAVE") // 100, # immunity to waves wave mult
        check_ability(base_stats["abi"], 5), # block waves
        get_proc_mult(procs, "IMUKB") // 100, # immunity to knockbacks probability
        get_proc_mult(procs, "IMUSTOP") // 100, # immunity to freeze probability
        get_proc_mult(procs, "IMUSLOW") // 100, # immunity to slow probability
        get_proc_mult(procs, "IMUWEAK") // 100, # immunity to weaken probability
        check_ability(base_stats["abi"], 9), # zombie killer
        check_ability(base_stats["abi"], 10), # witch killer
        check_ability(base_stats["abi"], 10), # witch killer effective?
        base_stats["loop"],
        0,
        -1,
        2 if check_ability(base_stats["abi"], 11) else 0, # death after attack
        get_attack(base_stats["atks"]["pool"], 1, "atk"), # second attack
        get_attack(base_stats["atks"]["pool"], 2, "atk"), # third attack
        get_attack(base_stats["atks"]["pool"], 1, "pre"), # second attack pre
        get_attack(base_stats["atks"]["pool"], 2, "pre"), # third attack pre
        1, # use ability on first hit
        1, # use ability on second hit
        1, # use ability on third hit
        -1, # spawn animation
        base_stats["death"]["id"], # soul animation
        0, # unique spawn animation
        0, # gudetama soul animation
        get_proc_prob(procs, "BREAK"), # barrier break probability
        0, # warp chance
        0, # warp duration
        0, # min warp distance
        0, # max warp distance
        get_proc_mult(procs, "IMUWARP") // 100, # warp blocker
        check_ability(base_stats["abi"], 13), # eva angel effective
        check_ability(base_stats["abi"], 13), # eva angel killer
        get_trait_by_id(traits, 8), # relic
        get_proc_mult(procs, "IMUCURSE") // 100, # curse immunity
        check_ability(base_stats["abi"], 15), # insanely tough
        check_ability(base_stats["abi"], 16), # insane damage
        get_proc_prob(procs, "SATK"), # savage blow probability
        get_proc_mult(procs, "SATK"), # savage blow level
        get_proc_prob(procs, "IMUATK"), # dodge attack chance
        get_proc_time(procs, "IMUATK"), # dodge attack duration
        get_proc_prob(procs, "VOLC"), # surge attack chance
        int(get_proc_value(procs, "VOLC", "dis_0") * 4), # surge attack min range
        int(get_proc_value(procs, "VOLC", "dis_1") * 4), # surge attack max range
        get_proc_time(procs, "VOLC") // 20, # surge attack duration
        get_proc_mult(procs, "IMUPOIATK") // 100, # toxic immunity
        get_proc_mult(procs, "IMUVOLC") // 100, # surge immunity
        get_proc_prob(procs, "CURSE"), # curse probability
        get_proc_time(procs, "CURSE"), # curse duration
        1 if get_proc_prob(procs, "MINIWAVE") != 0 else 0, # miniwave
        get_proc_prob(procs, "SHIELDBREAK"), # aku shield break probability
        get_trait_by_id(traits, 7), # aku effective
        check_ability(base_stats["abi"], 17), # colossus slayer
        check_ability(base_stats["abi"], 18), # corpse killer
        1 if get_attack(base_stats["atks"]["pool"], 1, "ld1") != 0 else 0, # second attack long distance flag
        get_attack(base_stats["atks"]["pool"], 1, "ld0"), # long distance start 2
        get_attack(base_stats["atks"]["pool"], 1, "ld1"), # long distance range 2
        1 if get_attack(base_stats["atks"]["pool"], 2, "ld1") != 0 else 0, # third attack long distance flag
        get_attack(base_stats["atks"]["pool"], 2, "ld0"), # long distance start 3
        get_attack(base_stats["atks"]["pool"], 2, "ld1"), # long distance range 3
        1 if get_proc_prob(procs, "BSTHUNT") > 0 else 0, # behemoth slayer
        get_proc_prob(procs, "BSTHUNT"), # behemoth slayer probability
        get_proc_time(procs, "BSTHUNT"), # behemoth slayer duration
    ]
    return csv_data

def get_attack(attack_data: list[dict[str, Any]], attack_id: int, key: str) -> int:
    try:
        return int(attack_data[attack_id][key])
    except IndexError:
        return 0

def get_trait_by_id(traits: list[dict[str, Any]], id: int) -> int:
    for trait in traits:
        if trait["id"] == id:
            return 1
    return 0

def check_ability(ability_abi: int, ability_id: int) -> int:
    has_ability = ability_abi & (1 << ability_id) != 0
    return 1 if has_ability else 0

def get_proc_prob(procs: dict[str, dict[str, int]], proc_name: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name]["prob"])
    return 0

def get_proc_time(procs: dict[str, dict[str, int]], proc_name: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name]["time"])
    return 0

def get_proc_mult(procs: dict[str, dict[str, int]], proc_name: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name]["mult"])
    return 0

def get_proc_level(procs: dict[str, dict[str, int]], proc_name: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name]["lv"])
    return 0

def get_proc_health(procs: dict[str, dict[str, int]], proc_name: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name]["health"])
    return 0

def get_proc_value(procs: dict[str, dict[str, int]], proc_name: str, key: str) -> int:
    if proc_name in procs:
        return int(procs[proc_name][key])
    return 0