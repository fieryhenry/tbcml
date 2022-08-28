from typing import Any
from .. import helper, game_file_editor


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
    mamodel_data.append([0, 0, 0, 0, 5, 0, "ガチャ配置用"])

    for i, maanim_file_path in enumerate(maanim_file_paths):
        maanim_data = helper.parse_csv(maanim_file_path)
        for j, part in enumerate(maanim_data):
            if len(part) >= 5:
                if part[1] == 11:
                    for k in range(maanim_data[j + 1][0]):
                        maanim_data[j + 2 + k][1] *= -1
        editor.write_csv(cat_maanim_file_paths[i], maanim_data, False)

    editor.write_csv(cat_mamodel_path, mamodel_data, False)


def convert_imgcut(imgcut_path: str, cat_id: int) -> list[list[Any]]:
    """
    Convert an enemy imgcut to a unit one

    Args:
        imgcut_path (str): the path to the imgcut

    Returns:
        list[list[Any]]: the converted imgcut data
    """
    cat_id_str = str(cat_id).zfill(3)
    imgcut_data = helper.parse_csv(imgcut_path)
    imgcut_data[2][0] = cat_id_str + "_f.png"
    return imgcut_data


def import_enemy_anims(
    editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int
):
    enemy_id_str = str(enemy_id - 2).zfill(3)
    unit_id_str = str(cat_id).zfill(3)

    imgcut_path = editor.get_file_path(f"{enemy_id_str}_e.imgcut", True)
    cat_imgcut_path = editor.get_file_path(f"{unit_id_str}_f.imgcut")

    if imgcut_path is None or cat_imgcut_path is None:
        helper.colored_text("Can't find imgcut file")
        return

    imgcut_data = convert_imgcut(imgcut_path, cat_id)
    editor.write_csv(cat_imgcut_path, imgcut_data, False)

    mamodel_path = editor.get_file_path(f"{enemy_id_str}_e.mamodel", True)
    cat_mamodel_path = editor.get_file_path(f"{unit_id_str}_f.mamodel")

    if mamodel_path is None or cat_mamodel_path is None:
        helper.colored_text("Can't find mamodel file")
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
        if maanim_path is None or cat_maanim_path is None:
            helper.colored_text(f"Can't find maanim_file: {maanim_path}")
            return

        maanim_paths.append(maanim_path)
        cat_maanim_paths.append(cat_maanim_path)

    mirror(
        editor, mamodel_path, cat_mamodel_path, maanim_paths, cat_maanim_paths, cat_id
    )

    png_path = editor.get_file_path(f"{enemy_id_str}_e.png", True)
    cat_png_path = editor.get_file_path(f"{unit_id_str}_f.png")
    if png_path is None or cat_png_path is None:
        helper.colored_text(f"Can't find png file")
        return
    editor.write_bytes(cat_png_path, helper.read_file_bytes(png_path))


def import_enemy():
    editor = game_file_editor.GameFileEditor("add_enemy_as_cat")
    enemy_ids = editor.get_range(helper.colored_input("Enter enemy ids (Look up enemy release order battle cats to find ids)(You can enter &all& to get all, a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"))
    cat_ids = editor.get_range(helper.colored_input("Enter cat ids to be replaced (Look up cat release order battle cats to find ids)(You can enter &all& to get all, a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"))
    for enemy_id, cat_id in zip(enemy_ids, cat_ids):
        import_enemy_anims(editor, enemy_id, cat_id)
        import_stats(editor, enemy_id, cat_id)
        import_name(editor, enemy_id, cat_id)

def import_name(editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int):
    enemy_names = editor.read_bytes("Enemyname.tsv")
    if enemy_names is None:
        helper.colored_text("Can't find enemy names")
        return
    enemy_names = helper.remove_pkcs7_padding(enemy_names).decode("utf-8").splitlines()
    enemy_name = enemy_names[enemy_id - 2].strip(" ")
    cc = "en"
    delimeter = "|"
    if editor.is_jp:
        cc = "ja"
        delimeter = ","
    enemy_picture_book = editor.parse_file(f"EnemyPictureBook_{cc}.csv", delimeter)
    if enemy_picture_book is None:
        helper.colored_text("Can't find enemy descriptions")
        return
    enemy_description_data = enemy_picture_book[enemy_id - 2]
    enemy_description = enemy_description_data[1:]

    unit_explanation = editor.parse_file(f"Unit_Explanation{cat_id+1}_{cc}.csv", delimeter)
    if unit_explanation is None:
        helper.colored_text("Can't find cat name / description")
        return
    unit_explanation[0][0] = enemy_name
    unit_explanation[0][1:] = enemy_description
    editor.write_csv(f"Unit_Explanation{cat_id+1}_{cc}.csv", unit_explanation, delimeter=delimeter)


def import_stats(editor: game_file_editor.GameFileEditor, enemy_id: int, cat_id: int):
    cat_id_str = str(cat_id + 1).zfill(3)
    file_name = editor.get_file_path(f"unit{cat_id_str}.csv")
    if file_name is None:
        helper.colored_text("Can't find unit data")
        return
    cat_stats = editor.parse_file(f"unit{cat_id_str}.csv")
    all_enemy_stats = editor.parse_file(f"t_unit.csv")
    if cat_stats is None or all_enemy_stats is None:
        helper.colored_text("Failed to get cat / enemy stats")
        return

    enemy_stats = all_enemy_stats[enemy_id]
    cat_stats_first = cat_stats[0]
    cat_stats_first = [
        enemy_stats[0],  # hp
        enemy_stats[1],  # knockbacks
        enemy_stats[2],  # atk power
        enemy_stats[3],  # atk power
        enemy_stats[4],  # time between attacks
        enemy_stats[5],  # attack range
        enemy_stats[6] // 4,  # money drop / price
        0,  # recharge time
        0,  # hitbox pos
        enemy_stats[8],  # width
        1,  # red effective flag
        0,  # always 0
        enemy_stats[11],  # area attack flag
        enemy_stats[12],  # foreswing
        0,  # min z-layer
        9,  # max z-layer
        1,  # floating effective
        1,  # black effective
        1,  # metal effective
        1,  # traitless effective
        1,  # angel effective
        1,  # alien effective
        1,  # zombie effective
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
        1,  # relic effective
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
        1,  # aku effective
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
    editor.write_csv(file_name, cat_stats)