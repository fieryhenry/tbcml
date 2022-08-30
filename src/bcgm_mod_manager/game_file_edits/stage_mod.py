from .. import game_file_editor, helper


def edit_stage():
    """
    Edits the stage files.
    """
    editor = game_file_editor.GameFileEditor("stage_mod")

    folder = editor.get_directory_from_file("stage00.csv")
    if folder is None:
        folder = "."

    unit_file_path = helper.select_file(
        "Select stage files to edit", [("Stage Files", "stage*.csv")], folder
    )
    data = editor.parse_file(unit_file_path)
    if data is None:
        helper.colored_text("Error: Could not parse unit file.", helper.Color.RED)
        return
    values: dict[str, list[str]] = editor.get_json_info()
    main_data = data
    stage_id = None

    if len(data[0]) < 9:
        stage_id = helper.int_list_to_str(data[0])
        main_data = data[1:]

    stage_data = main_data[0]
    enemy_slot_data = main_data[1:]
    magnification = False
    if len(enemy_slot_data[0]) > 9:
        magnification = True
    options = ["Edit stage data", "Edit enemy slot data"]
    if stage_id != None:
        options.append("Edit stage id")
    helper.colored_list(options)
    option = helper.colored_input("Select an option:")
    if not option:
        helper.colored_text("No option selected.", helper.Color.RED)
        return
    if option == "1":
        stage_data = editor.edit_array(values["stage"], stage_data, "Stage data")
    elif option == "2":
        full_slots = get_full_slots(enemy_slot_data)
        ids = editor.select_options(
            helper.get_elements(full_slots, 0), all_at_once=False
        )
        for id in ids:
            id = helper.check_int(str(id))
            if id is None:
                helper.colored_text("Invalid id selected.", helper.Color.RED)
                continue
            if id > len(enemy_slot_data):
                if magnification:
                    enemy_slot_data.append([0, 0, 0, 0, 0, 0, 0, 9, 0, 100])
                else:
                    enemy_slot_data.append([0, 0, 0, 0, 0, 0, 0, 9, 0])
                id = len(enemy_slot_data)
            id -= 1
            enemy_values_trim = values["enemy"]
            if len(enemy_slot_data[id]) < len(values["enemy"]):
                enemy_values_trim = values["enemy"][:-1]
            helper.colored_text(f"Editing enemy slot &{id + 1}&", helper.Color.GREEN)
            enemy_slot_data[id] = editor.edit_array(
                enemy_values_trim, enemy_slot_data[id], "Enemy slot data"
            )
    elif option == "3" and stage_id:
        stage_id = helper.colored_input(
            f"Current stage id: &{stage_id}&\nEnter new stage id:"
        )
        if not stage_id:
            helper.colored_text("No id entered.", helper.Color.RED)
            return
    new_csv_data: list[list[str]] = []
    if stage_id != None:
        new_csv_data.append(helper.str_to_chars(stage_id))
    new_csv_data.append(stage_data)
    new_csv_data.extend(enemy_slot_data)
    editor.write_csv(unit_file_path, new_csv_data)


def get_full_slots(enemy_slot_data: list[list[int]]):
    full_slots: list[list[int]] = []
    for slot in enemy_slot_data:
        if slot[0] != 0:
            full_slots.append(slot)
    return full_slots
