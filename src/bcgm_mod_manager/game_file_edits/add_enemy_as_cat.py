import io
import os
import shutil
from multiprocessing import Process
from typing import Optional

import bs4
import requests
from bs4 import BeautifulSoup
from PIL import Image
from alive_progress import alive_bar # type: ignore

from .. import game_file_editor, helper
from . import import_from_bcu


def mirror(
    editor: game_file_editor.GameFileEditor,
    mamodel_path: str,
    cat_mamodel_path: str,
    maanim_file_paths: list[str],
    cat_maanim_file_paths: list[str],
    cat_id: int,
) -> None:
    """
    Mirror a file

    Args:
        mamodel_path (str): path to the mamodel file
        maanim_file_paths (list[str]): path to the maanim files
    """
    mamodel_data = helper.parse_csv(mamodel_path)
    mamodel_data[3][8] *= -1  # flip x scale
    for i in range(4, len(mamodel_data)):
        if len(mamodel_data[i]) > 9:
            mamodel_data[i][10] *= -1  # flip angle
            mamodel_data[i][1] = cat_id
    mamodel_data[-2][0] = 2
    mamodel_data.append(mamodel_data[-1])

    for i, maanim_file_path in enumerate(maanim_file_paths):
        maanim_data = helper.parse_csv(maanim_file_path)
        for j, part in enumerate(maanim_data):
            if len(part) >= 5:
                if part[1] == 11:
                    for k in range(maanim_data[j + 1][0]):
                        maanim_data[j + 2 + k][1] *= -1
        editor.write_csv(cat_maanim_file_paths[i], maanim_data, False, text=False)

    editor.write_csv(cat_mamodel_path, mamodel_data, False, text=False)


def convert_imgcut(imgcut_path: str, cat_id: int) -> str:
    """
    Convert an enemy imgcut to a unit one

    Args:
        imgcut_path (str): the path to the imgcut

    Returns:
        str: the converted imgcut data
    """
    cat_id_str = str(cat_id).zfill(3)
    imgcut_data = helper.read_file_str(imgcut_path).splitlines()
    imgcut_data = helper.write_val_in_csv(helper.read_file_str(imgcut_path), 2, 0, cat_id_str + "_f.png")
    return imgcut_data


def get_uni_image() -> Optional[bytes]:
    """
    Get the uni image

    Returns:
        bytes: the uni image
    """
    uni_path = helper.get_file("uni_f.png")
    img = Image.open(uni_path).convert("RGBA", colors=2**32)
    data = save_image(img)
    return data


def save_image(image: Image.Image) -> bytes:
    """
    Save an image

    Args:
        image (Image.Image): the image
    """
    with io.BytesIO() as output:
        image.save(output, format="PNG")
        data = output.getvalue()
    return data


def insert_battle_icon(battle_icon_path: str) -> Optional[bytes]:
    """
    Insert a battle icon into the battle icon file

    Args:
        battle_icon_path (str): the path to the battle icon

    Returns:
        bytes: the battle icon file data
    """
    uni_data = get_uni_image()
    if uni_data is None:
        return None
    battle_icon_data = import_from_bcu.scale_height_display_file(battle_icon_path, 2)
    if battle_icon_data is None:
        return None
    battle_icon = Image.open(io.BytesIO(battle_icon_data)).convert(
        "RGBA", colors=2**32
    )
    uni_image_img = Image.open(io.BytesIO(uni_data)).convert("RGBA", colors=2**32)
    uni_image_img.paste(battle_icon, (-35, 10), battle_icon)

    uni_border = Image.open(helper.get_file("uni_box.png")).convert(
        "RGBA", colors=2**32
    )
    uni_image_img.paste(uni_border, (0, 0), uni_border)

    data = save_image(uni_image_img)
    data = crop_image_top(data, 106)
    data = crop_image_bottom(data, 85)
    data = crop_image_right(data, 119)
    uni_image_img = Image.open(io.BytesIO(uni_data)).convert("RGBA", colors=2**32)
    new_uni_image = Image.open(io.BytesIO(data)).convert("RGBA", colors=2**32)
    uni_image_img.paste(new_uni_image, (9, 21), new_uni_image)
    data = save_image(uni_image_img)
    return data


def crop_image_top(image_data: bytes, new_height: int) -> bytes:
    """
    Crop the top of an image

    Args:
        image_data (bytes): the image data
        new_height (int): the new height

    Returns:
        bytes: the cropped image data
    """
    img = Image.open(io.BytesIO(image_data)).convert("RGBA", colors=2**32)
    img = img.crop((0, 0, img.width, new_height))
    data = save_image(img)
    return data


def crop_image_bottom(image_data: bytes, new_height: int) -> bytes:
    """
    Crop the bottom of an image

    Args:
        image_data (bytes): the image data
        new_height (int): the new height

    Returns:
        bytes: the cropped image data
    """
    img = Image.open(io.BytesIO(image_data)).convert("RGBA", colors=2**32)
    img = img.crop((0, img.height - new_height, img.width, img.height))
    data = save_image(img)
    return data


def crop_image_left(image_data: bytes, new_width: int) -> bytes:
    """
    Crop the left of an image

    Args:
        image_data (bytes): the image data
        new_width (int): the new width

    Returns:
        bytes: the cropped image data
    """
    img = Image.open(io.BytesIO(image_data)).convert("RGBA", colors=2**32)
    img = img.crop((0, 0, new_width, img.height))
    data = save_image(img)
    return data


def crop_image_right(image_data: bytes, new_width: int) -> bytes:
    """
    Crop the right of an image

    Args:
        image_data (bytes): the image data
        new_width (int): the new width

    Returns:
        bytes: the cropped image data
    """
    img = Image.open(io.BytesIO(image_data)).convert("RGBA", colors=2**32)
    img = img.crop((img.width - new_width, 0, img.width, img.height))
    data = save_image(img)
    return data


def import_icon_battle(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int
) -> None:
    """
    Import a battle icon

    Args:
        editor (game_file_editor.GameFileEditor): the editor
        enemy_id (int): the enemy id
        cat_id (int): the cat id
    """
    unit_id_str = str(cat_id).zfill(3)
    enemy_id_str = str(enemy_id - 2).zfill(3)
    cat_icon_path = editor.get_file_path(f"uni{unit_id_str}_f00.png")
    enemy_icon_path = editor.get_file_path(f"enemy_icon_{enemy_id_str}.png", True)

    if cat_icon_path is None:
        helper.colored_text(
            f"Could not find icon file for cat {cat_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    if enemy_icon_path is None:
        helper.colored_text(
            f"Could not find icon file for enemy {enemy_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    data = insert_battle_icon(enemy_icon_path)
    if data is None:
        return
    editor.write_bytes(cat_icon_path, data, text=False)


def set_nyanko_picture_book(
    editor: game_file_editor.GameFileEditor, cat_ids: list[int]
) -> None:
    """
    Set the nyanko picture book for a cat

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        cat_ids (list[int]): the cat ids
    """
    picture_book_data = editor.parse_file("nyankoPictureBookData.csv")
    unit_buy_data = editor.parse_file("unitbuy.csv")
    if picture_book_data is None:
        helper.colored_text(
            "Could not find nyankoPictureBookData.csv",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    if unit_buy_data is None:
        helper.colored_text(
            "Could not find unitbuy.csv",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    for cat_id in cat_ids:
        picture_book_data[cat_id][0] = 1  # make cat appear in cat guide

        if unit_buy_data[cat_id][57] == -1:
            unit_buy_data[cat_id][57] = 0  # make cat appear in upgrade menu
    editor.write_csv("nyankoPictureBookData.csv", picture_book_data, text=False)
    editor.write_csv("unitbuy.csv", unit_buy_data, text=False)


def import_enemy_anims(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int
):
    """
    Import enemy anims as cats

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        enemy_id (int): the enemy id to be imported
        cat_id (int): the cat id to be replaced
    """
    enemy_id_str = str(enemy_id - 2).zfill(3)
    unit_id_str = str(cat_id).zfill(3)

    imgcut_path = editor.get_file_path(f"{enemy_id_str}_e.imgcut", True)
    cat_imgcut_path = editor.get_file_path(f"{unit_id_str}_f.imgcut")

    if imgcut_path is None:
        helper.colored_text(
            f"Could not find imgcut for enemy {enemy_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    if cat_imgcut_path is None:
        helper.colored_text(
            f"Could not find imgcut for cat {cat_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return

    imgcut_data = convert_imgcut(imgcut_path, cat_id)
    editor.write_bytes(cat_imgcut_path, imgcut_data.encode("utf-8"), False, text=False)

    mamodel_path = editor.get_file_path(f"{enemy_id_str}_e.mamodel", True)
    cat_mamodel_path = editor.get_file_path(f"{unit_id_str}_f.mamodel")

    if mamodel_path is None:
        helper.colored_text(
            f"Could not find mamodel for enemy {enemy_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    if cat_mamodel_path is None:
        helper.colored_text(
            f"Could not find mamodel for cat {cat_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return

    maanim_paths: list[str] = []
    cat_maanim_paths: list[str] = []
    for i in range(4):
        maanim_path = editor.get_file_path(
            f"{enemy_id_str}_e{str(i).zfill(2)}.maanim", True
        )
        cat_maanim_path = editor.get_file_path(
            f"{unit_id_str}_f{str(i).zfill(2)}.maanim"
        )
        if maanim_path is None:
            helper.colored_text(
                f"Could not find maanim for enemy {enemy_id}",
                helper.Color.RED,
                helper.Color.WHITE,
            )
            return
        if cat_maanim_path is None:
            helper.colored_text(
                f"Could not find maanim for cat {cat_id}",
                helper.Color.RED,
                helper.Color.WHITE,
            )
            return

        maanim_paths.append(maanim_path)
        cat_maanim_paths.append(cat_maanim_path)

    mirror(
        editor, mamodel_path, cat_mamodel_path, maanim_paths, cat_maanim_paths, cat_id
    )

    png_path = editor.get_file_path(f"{enemy_id_str}_e.png", True)
    cat_png_path = editor.get_file_path(f"{unit_id_str}_f.png")
    if png_path is None:
        helper.colored_text(
            f"Could not find png for enemy {enemy_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    if cat_png_path is None:
        helper.colored_text(
            f"Could not find png for cat {cat_id}",
            helper.Color.RED,
            helper.Color.WHITE,
        )
        return
    editor.write_bytes(cat_png_path, helper.read_file_bytes(png_path), text=False)


def import_enemy():
    """
    Import enemy as cats
    """
    editor = game_file_editor.GameFileEditor("add_enemy_as_cat")
    enemy_ids = editor.get_range(
        helper.colored_input(
            "Enter enemy ids (Look up enemy release order battle cats to find ids)(You can enter a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"
        )
    )
    cat_ids = editor.get_range(
        helper.colored_input(
            "Enter cat ids to be replaced (Look up cat release order battle cats to find ids)(You can enter a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"
        )
    )
    if os.path.exists("temp_images"):
        shutil.rmtree("temp_images")
    import_enemy_mult(editor, enemy_ids, cat_ids)


def import_enemy_data(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int, enemy_name: str
):
    """
    Import enemy data as cats

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        enemy_id (int): the enemy id to be imported
        cat_id (int): the cat id to be replaced
        enemy_name (str): the enemy name
    """
    import_enemy_anims(editor, enemy_id, cat_id)
    import_stats(editor, enemy_id, cat_id)
    import_name(editor, enemy_id, cat_id, enemy_name)
    import_icon(editor, enemy_id, cat_id)


def import_enemy_mult(
    editor: game_file_editor.GameFileEditor,
    enemy_ids: list[int],
    cat_ids: list[int],
):
    """
    Import enemy anims as cats

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        enemy_ids (list[int]): the enemy ids to be imported
        cat_ids (list[int]): the cat ids to be replaced
        total_enemies (int): the total number of enemies
    """
    enemy_names = get_enemy_names()
    get_enemy_icons(enemy_ids)
    set_nyanko_picture_book(editor, cat_ids)

    with alive_bar(len(enemy_ids), title="Importing Enemies: ") as bar: # type: ignore
        for enemy_id, cat_id in zip(enemy_ids, cat_ids):
            import_enemy_data(
                editor,
                enemy_id,
                cat_id,
                enemy_names[enemy_id],
            )
            bar()
    file_path = os.path.abspath(
        os.path.join(
            editor.apk.output_path,
            "Modified Files",
        )
    )
    helper.colored_text(
        f"\nDone. Files can be found at &{file_path}&",
        helper.Color.GREEN,
        helper.Color.WHITE,
    )


def import_name(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int, enemy_name: str
):
    """
    Import enemy name as cat name

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        enemy_id (int): the enemy id to be imported
        cat_id (int): the cat id to be replaced
        enemy_name (str): the enemy name to be imported
    """
    cc = "en"
    delimeter = "|"
    if editor.is_jp:
        cc = "ja"
        delimeter = ","
    enemy_picture_book_path = editor.get_file_path(f"EnemyPictureBook_{cc}.csv")
    if enemy_picture_book_path is None:
        helper.colored_text(
            f"Can't find EnemyPictureBook file: EnemyPictureBook_{cc}.csv",
            helper.Color.RED,
        )
        return

    enemy_picture_book = helper.get_row_from_csv(helper.read_file_str(enemy_picture_book_path), enemy_id - 2, delimeter=delimeter)
    enemy_description = enemy_picture_book[1:]

    unit_explanation = editor.parse_file(
        f"Unit_Explanation{cat_id+1}_{cc}.csv", delimeter
    )
    if unit_explanation is None:
        helper.colored_text(
            f"Can't find Unit_Explanation file: Unit_Explanation{cat_id+1}_{cc}.csv",
            helper.Color.RED,
        )
        return
    unit_explanation[0][0] = enemy_name
    unit_explanation[0][1:] = enemy_description
    editor.write_csv(
        f"Unit_Explanation{cat_id+1}_{cc}.csv",
        unit_explanation,
        delimeter=delimeter,
        text=False,
    )


def has_any_effects(enemy_stats: list[int]) -> bool:
    """
    Check if enemy has any effects

    Args:
        enemy_stats (list[int]): the enemy stats

    Returns:
        bool: True if enemy has any effects, False otherwise
    """
    indexes_to_check = [
        20,  # kb chance
        21,  # freeze chance
        23,  # slow chance
        29,  # weaken chance
        73,  # curse chance
        77,  # dodge chance
    ]
    for index in indexes_to_check:
        if enemy_stats[index] != 0:
            return True
    return False


def import_stats(editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int):
    """
    Import enemy stats as cat stats

    Args:
        editor (game_file_editor.GameFileEditor): the game file editor
        enemy_id (int): the enemy id to be imported
        cat_id (int): the cat id to be replaced
    """
    cat_id_str = str(cat_id + 1).zfill(3)
    file_name = editor.get_file_path(f"unit{cat_id_str}.csv")
    if file_name is None:
        helper.colored_text(f"Can't find unit{cat_id_str}.csv", helper.Color.RED)
        return
    cat_stats = editor.parse_file(f"unit{cat_id_str}.csv")
    if cat_stats is None:
        helper.colored_text(f"Can't find unit{cat_id_str}.csv", helper.Color.RED)
        return
    t_unit_path = editor.get_file_path("t_unit.csv")
    if t_unit_path is None:
        helper.colored_text(f"Can't find t_unit.csv", helper.Color.RED)
        return
    enemy_stats = helper.str_list_to_int_list(helper.get_row_from_csv(helper.read_file_str(t_unit_path), enemy_id))
    effect_flag = 1 if has_any_effects(enemy_stats) else 0
    cat_stats_first = cat_stats[0]
    cat_stats_first = [
        enemy_stats[0],  # hp
        enemy_stats[1],  # knockbacks
        enemy_stats[2],  # atk power
        enemy_stats[3],  # atk power
        enemy_stats[4],  # time between attacks
        enemy_stats[5],  # attack range
        enemy_stats[6] // 2,  # money drop / price
        0,  # recharge time
        0,  # hitbox pos
        enemy_stats[8],  # width
        effect_flag,  # red effective flag
        0,  # always 0
        enemy_stats[11],  # area attack flag
        enemy_stats[12],  # foreswing
        0,  # min z-layer
        9,  # max z-layer
        effect_flag,  # floating effective
        effect_flag,  # black effective
        effect_flag,  # metal effective
        effect_flag,  # traitless effective
        effect_flag,  # angel effective
        effect_flag,  # alien effective
        effect_flag,  # zombie effective
        0,  # strong against
        enemy_stats[20],  # knock back chance
        enemy_stats[21],  # freeze chance
        enemy_stats[22],  # freeze duration
        enemy_stats[23],  # slow chance
        enemy_stats[24],  # slow duration
        0,  # resistant against
        0,  # triple damage flag
        enemy_stats[25],  # crit chance
        0,  # attack only
        0,  # extra money
        enemy_stats[26],  # base destroyer
        enemy_stats[27],  # wave chance
        enemy_stats[28],  # wave level
        enemy_stats[29],  # weaken chance
        enemy_stats[30],  # weaken duration
        enemy_stats[31],  # weaken %
        enemy_stats[32],  # strength activation health
        enemy_stats[33],  # strength mult
        enemy_stats[34],  # survive chance
        enemy_stats[15],  # is metal
        enemy_stats[35],  # ld start
        enemy_stats[36],  # ld range
        enemy_stats[37],  # wave immunity
        enemy_stats[38],  # block waves
        enemy_stats[39],  # knockback immunity
        enemy_stats[40],  # freeze immunity
        enemy_stats[41],  # slow immunity
        enemy_stats[42],  # weaken immunity
        0,  # zombie killer
        0,  # witch killer
        0,  # witch effective
        enemy_stats[50],  # loop
        0,  # frames before dying?
        -1,  # -1
        enemy_stats[52],  # death after attack
        enemy_stats[55],  # second attack power
        enemy_stats[56],  # third attack power
        enemy_stats[57],  # second attack start frame
        enemy_stats[58],  # third attack start frame
        enemy_stats[59],  # use ability on first hit
        enemy_stats[60],  # second attack flag
        enemy_stats[61],  # third attack flag
        -1,  # -1
        enemy_stats[54],  # soul animation
        enemy_stats[62],  # unique spawn anim?
        enemy_stats[63],  # gudetama soul animation
        0,  # barrier break chance
        enemy_stats[65],  # warp chance
        enemy_stats[66],  # warp duration
        enemy_stats[67],  # warp min range
        enemy_stats[68],  # warp max range
        0,  # warp blocker
        0,  # eva angel effective
        0,  # eva angel killer
        effect_flag,  # relic effective
        0,  # immune to curse
        0,  # insanely tough
        0,  # insane damage
        enemy_stats[75],  # savage blow chance
        enemy_stats[76],  # savage blow mult
        enemy_stats[77],  # dodge chance
        enemy_stats[78],  # dodge duration
        enemy_stats[81],  # surge chance
        enemy_stats[82],  # surge min range
        enemy_stats[83],  # surge max range
        enemy_stats[85],  # surge level
        0,  # toxic immunity
        0,  # surge immunity
        enemy_stats[73],  # curse chance
        enemy_stats[74],  # curse duration
        enemy_stats[86],  # mini wave
        0,  # shield break chance
        effect_flag,  # aku effective
        0,  # colussus slayer
        0,  # corpse killer
        enemy_stats[95],  # ld flag 2
        enemy_stats[96],  # ld start 2
        enemy_stats[97],  # ld range 2
        enemy_stats[98],  # ld flag 3
        enemy_stats[99],  # ld start 3
        enemy_stats[100],  # ld range 3
        0,  # behemoth slayer
        0,  # behemoth slayer chance
        0,  # behemoth dodge duration
    ]

    cat_stats[0] = cat_stats_first
    editor.write_csv(file_name, cat_stats, text=False)


def get_enemy_names() -> list[str]:
    """
    Get all enemy names

    Returns:
        list[str]: all enemy names
    """
    page_data = requests.get(
        "https://battle-cats.fandom.com/wiki/Enemy_Release_Order"
    ).content
    soup = BeautifulSoup(page_data, "html.parser")
    table_body = soup.find("tbody")
    if table_body is None:
        return []
    enemy_rows: list[bs4.element.Tag] = table_body.find_all("tr")[2:]  # type: ignore
    enemy_names: list[str] = []
    for enemy_row in enemy_rows:
        enemy_name: bs4.element.Tag = enemy_row.find_all("td")[1]
        if enemy_name is None:
            enemy_names.append("")
            continue
        enemy_names.append(enemy_name.text.strip("\n"))
    enemy_names.pop(55)  # remove duplicate enemy
    return enemy_names


def get_enemy_icons(enemy_ids: list[int]) -> None:
    """
    Get enemy icons with given ids

    Args:
        editor (game_file_editor.GameFileEditor): editor to use
        enemy_ids (list[int]): enemy ids to get icons for
    """
    output_path = helper.get_file("enemy_icons")
    helper.check_dir(output_path)
    urls: list[str] = []
    output_paths: list[str] = []
    for enemy_id in enemy_ids:
        enemy_id_str = str(enemy_id - 2).zfill(3)
        image_out_path = os.path.join(output_path, f"udi{enemy_id_str}_e.png")
        if not os.path.exists(image_out_path):
            url = f"https://onestoppress.com/images/edi_{enemy_id_str}.png"
            urls.append(url)
            output_paths.append(image_out_path)
    get_files_parallel(urls, output_paths)


def get_files_parallel(urls: list[str], output_paths: list[str]):
    """
    Get data from urls in parallel

    Args:
        urls (list[str]): urls to get
        output_paths (list[str]): output paths to write to
    """
    counter = helper.Counter()
    functions: list[Process] = []
    urls_chunked = list(helper.chunks(urls, 50))
    output_paths_chunked = list(helper.chunks(output_paths, 50))
    for url_chunk, output_path_chunk in zip(urls_chunked, output_paths_chunked):
        functions.append(
            Process(
                target=get_files,
                args=(url_chunk, output_path_chunk, counter, len(urls)),
            )
        )
    helper.run_in_parallel(functions)


def get_files(
    urls: list[str], output_paths: list[str], counter: helper.Counter, total: int
):
    for url, output_path in zip(urls, output_paths):
        get_file(url, output_path, counter, total)


def get_file(url: str, output_path: str, counter: helper.Counter, total: int):
    """
    Get file from url

    Args:
        url (str): url to get
        output_path (str): output path to write to
    """
    response = requests.get(url)
    with open(output_path, "wb") as file:
        file.write(response.content)
    counter.increment()
    helper.colored_text(
        f"Downloaded icon: &{counter.value}&/&{total}&",
        helper.Color.GREEN,
        helper.Color.WHITE,
    )


def import_icon_display(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int
):
    """
    Import enemy icon with given id and cat id

    Args:
        editor (game_file_editor.GameFileEditor): editor to use
        enemy_id (int): enemy id to import
        cat_id (int): cat id to import to
    """
    enemy_id_str = str(enemy_id - 2).zfill(3)
    path = os.path.join(helper.get_file("enemy_icons"), f"udi{enemy_id_str}_e.png")
    cat_id_str = str(cat_id).zfill(3)
    final_display_file = f"udi{cat_id_str}_f.png"
    data = import_from_bcu.insert_display_image(path)
    if data is None:
        return
    editor.write_bytes(final_display_file, data, text=False)


def import_icon(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int
) -> None:
    """
    Import enemy icon with given id and cat id

    Args:
        editor (game_file_editor.GameFileEditor): editor to use
        enemy_id (int): enemy id to import
        cat_id (int): cat id to import to
    """
    import_icon_display(editor, enemy_id, cat_id)
    import_icon_battle(editor, enemy_id, cat_id)
