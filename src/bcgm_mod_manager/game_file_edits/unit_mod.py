import os
from .. import game_file_editor, helper

FORMS = ["First Form", "Second Form", "Third Form"]


def edit_unit() -> None:
    """
    Edit unit files.
    """
    editor = game_file_editor.GameFileEditor("unit_mod")
    
    folder = editor.get_directory_from_file("unit001.csv")
    if folder is None:
        folder = "."
    
    unit_file_path = helper.select_file("Select unit files to edit", [("Unit Files", "unit*.csv")], folder)
    data = editor.parse_file(unit_file_path)
    if data is None:
        helper.colored_text("Error: Could not parse unit file.", helper.Color.RED)
        return
    values: list[str] = editor.get_json_info()

    try:
        unit_id = int(os.path.basename(unit_file_path).split(".")[0][4:]) - 1
    except ValueError:
        unit_id = "ERROR"
    
    helper.colored_text(
        f"Editing &{os.path.basename(unit_file_path)} : &cat unit &{unit_id}&",
        helper.Color.GREEN,
        helper.Color.WHITE,
    )
    choices = editor.select_options(FORMS)
    for choice in choices:
        form_id = helper.get_int(str(choice))
        if form_id == None:
            helper.colored_text("Invalid input", helper.Color.RED)
            return
        form_id -= 1
        if form_id < 0 or form_id >= len(FORMS):
            helper.colored_text("Invalid input", helper.Color.RED)
            return
        form_data = data[form_id]
        form_data = helper.extend_list(form_data, values)
        form_data = set_required(form_data)

        helper.colored_text(f"Editing {FORMS[form_id]}", helper.Color.GREEN)
        form_data = editor.edit_array(values, form_data, "Stats")
        data[form_id] = form_data
    editor.write_csv(unit_file_path, data)

def set_required(form_data: list[int]) -> list[int]:
    """
    Set the required values for the unit to work correctly.

    Args:
        form_data (list[int]): The form data.

    Returns:
        list[int]: The form data with the required values set.
    """    

    required_vals = [(55, -1), (57, -1), (63, 1), (66, -1)]
    for val in required_vals:
        form_data[val[0]] = val[1]
    return form_data
