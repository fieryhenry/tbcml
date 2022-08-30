from .. import game_file_editor, helper


def edit_enemy():
    """
    Edit enemy files.
    """
    editor = game_file_editor.GameFileEditor("enemy_mod")

    folder = editor.get_directory_from_file("t_unit.csv")
    if folder is None:
        folder = "."

    enemy_file_path = helper.select_file(
        "Select tunit file to edit", [("Enemy File", "t_unit.csv")], folder
    )
    data = editor.parse_file(enemy_file_path)
    if data is None:
        helper.colored_text("Error: Could not parse enemy file.", helper.Color.RED)
        return
    values: list[str] = editor.get_json_info()

    ids = editor.get_range(
        helper.colored_input(
            "Enter enemy ids (Look up enemy release order battle cats to find ids)(You can enter a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"
        ),
        len(data),
    )
    for id in ids:
        enemy_data = data[id]
        helper.colored_text(f"Editing enemy id: &{id}&")
        enemy_data = editor.edit_array(values, enemy_data, "Stats")
        data[id] = enemy_data
    editor.write_csv(enemy_file_path, data)
    helper.colored_text("Done editing enemy file", helper.Color.GREEN)
