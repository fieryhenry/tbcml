import json
import os
from typing import Any, Optional

from . import apk_handler, config_handler, helper


class GameFileEditor:
    def __init__(self, name: str) -> None:
        """
        Initialize the game file editor.

        Args:
            game_version (str): The game version.
            is_jp (bool): True if the game is Japanese, False if the game is not.
            name (str): The name of the mod.
        """
        values = helper.get_vals_from_user(
            [
                "Enter game version (e.g 11.7.1):",
                "Are you using the jp version (&y&/&n&)?:",
                "Do you want a fresh download and decryption of the game files - (If no, game files must already be decrypted and extracted before hand) - (&y&/&n&):",
            ]
        )
        self.game_version = values[0]
        self.is_jp = values[1] == "y"
        self.fresh_download = values[2] == "y"
        self.apk = apk_handler.BC_APK(
            self.game_version,
            self.is_jp,
            config_handler.get_config_setting("apk_folder"),
            not self.fresh_download,
        )
        self.name = name
        self.load_apk()
        self.lists = self.apk.get_lists()
        self.files = self.apk.get_files(self.lists)

    def load_apk(self) -> None:
        """
        Prepare the game file editor, by downloading, extracting and decrypting the apk.
        """
        if not self.fresh_download:
            return

        helper.colored_text(
            "Downloading and extracting the apk...", helper.Color.GREEN
        )
        self.apk.download()
        self.apk.extract()
        helper.colored_text("Decrypting the game files...", helper.Color.GREEN)
        self.apk.decrypt()
        apk_handler.download_server_files(self.is_jp)
        self.apk.copy_decrypt_server_files()

    def get_decrypted_path(self) -> str:
        """
        Get the path to the decrypted game files.

        Returns:
            str: The path to the decrypted game files.
        """
        return self.apk.decrypted_path

    def parse_file(
        self, file_name: str, delimeter: str = ",", remove_empty: bool = False
    ) -> Optional[list[list[Any]]]:
        """
        Parse the specified file.

        Args:
            file_name (str): The name of the file.
            delimeter (str): What to split on

        Returns:
            Optional[list[list[Any]]]: The parsed file.
        """
        if not os.path.exists(file_name):
            file_path = self.get_file_path(file_name)
            if file_path is None:
                return None
            file_name = file_path
        return helper.parse_csv(file_name, delimiter=delimeter, r_empty=remove_empty)

    def read_bytes(self, file_name: str) -> Optional[bytes]:
        """
        Read the specified file.

        Args:
            file_name (str): The name of the file.

        Returns:
            Optional[bytes]: The data of the specified file, or None if the file does not exist.
        """
        file_path = self.get_file_path(file_name)
        if file_path is None:
            return None
        return helper.read_file_bytes(file_path)

    def write_csv(
        self,
        file_name: str,
        file_data: list[list[Any]],
        add_padding: bool = True,
        delimeter: str = ",",
        text: bool = True,
    ) -> None:
        """
        Write the specified file.

        Args:
            file_name (str): The name of the file.
            file_data (list[list[Any]]): The data to write.
            add_padding (bool): True if the file should be padded, False if not.
            delimeter (str): The char to split on. Defaults to ",".

        """
        data = helper.list_to_csv(file_data, delimeter)
        self.write_bytes(file_name, data.encode("utf-8"), add_padding, text)

    def write_bytes(
        self,
        file_name: str,
        file_data: bytes,
        add_padding: bool = True,
        text: bool = True,
    ) -> None:
        """
        Write the specified file.

        Args:
            file_name (str): The name of the file.
            file_data (bytes): The data to write.
            add_padding (bool): True if the file should be padded, False if not.
        """
        file_path = os.path.join(helper.get_modified_files_dir(), os.path.basename(file_name))
        helper.check_dir(os.path.dirname(file_path))

        if add_padding:
            file_data = helper.add_pkcs7_padding(file_data)
        helper.write_file_bytes(file_path, file_data)
        if text:
            helper.colored_text(
                f"Wrote {os.path.basename(file_name)} to {file_path}",
                helper.Color.GREEN,
            )

    def get_file_path(
        self, file_name: str, return_server: bool = False
    ) -> Optional[str]:
        """
        Get the path to the specified file.

        Args:
            file_name (str): The name of the file.

        Returns:
            Optional[str]: The path to the specified file, or None if the file does not exist.
        """
        if os.path.exists(file_name):
            return file_name
        list_name = self.files.get(file_name)
        if list_name is None:
            return None
        if not return_server:
            list_name = self.apk.convert_server_to_local(list_name)
        return os.path.join(
            self.apk.decrypted_path, list_name.replace(".list", ".pack"), file_name
        )

    def get_directory_from_file(self, file_name: str) -> Optional[str]:
        """
        Get the directory of the specified file.

        Args:
            file_name (str): The name of the file.

        Returns:
            Optional[str]: The directory of the specified file, or None if the file does not exist.
        """
        file_path = self.get_file_path(file_name)
        if file_path is None:
            return None
        return os.path.dirname(file_path)

    def get_json_info(self) -> Any:
        """
        Get the JSON info.

        Returns:
            Any: The JSON info.
        """
        path = os.path.join(helper.get_file(os.path.join("Edits", f"{self.name}.json")))
        return json.loads(helper.read_file_bytes(path))

    @staticmethod
    def get_range(input: str, length: Optional[int] = None, min: int = 0) -> list[int]:
        """
        Procces an input string to a list of integers.

        Args:
            input (str): The input string.
            length (Optional[int], optional): The length of the list. Defaults to None.
            min (int, optional): The minimum value of the list. Defaults to 0.

        Returns:
            list[int]: The list of integers.
        """

        ids: list[int] = []
        if length != None and input.lower() == "all":
            return list(range(min, length))
        if "-" in input:
            start, end = input.split("-")
            start = helper.get_int(start)
            end = helper.get_int(end)
            if start == None or end == None:
                helper.colored_text(
                    "Invalid input. Please enter a valid range of numbers separated by a dash.",
                    helper.Color.RED,
                )
                return ids
            if start > end:
                start, end = end, start
            ids = list(range(start, end + 1))
        else:
            content = input.split(" ")
            for id in content:
                id = helper.get_int(id)
                if id == None:
                    helper.colored_text(
                        "Invalid input. Please enter a valid integer.", helper.Color.RED
                    )
                    return ids
                ids.append(id)
        return ids

    @staticmethod
    def edit_array(
        names: list[str],
        data: list[Any],
        group_name: str,
        range: bool = False,
        length: Optional[int] = None,
        type_name: str = "value",
        offset: int = 0,
    ) -> list[Any]:
        """Edit an array with user input and return the edited array of ints"""
        min_len = min(len(names), len(data))
        names = names[:min_len]
        individual = True
        if range:
            ids = GameFileEditor.get_range(
                helper.colored_input(
                    f"Enter {group_name} ids(You can enter &all& to get all, a range e.g &1&-&50&, or ids separate by spaces e.g &5 4 7&):"
                ),
                length,
            )
            if len(ids) > 1:
                individual = (
                    helper.colored_input(
                        "Do you want to edit each id individually? (&y&/&n&):"
                    ).lower()
                    == "y"
                )
        else:
            ids = GameFileEditor.select_options(names, include=True, extra_data=data)
            individual = ids[1]
            ids = ids[0]
        first = True
        val = None
        for id in ids:
            id = helper.get_int(str(id))
            if id == None:
                helper.colored_text(
                    "Invalid id. Please enter a valid integer.", helper.Color.RED
                )
                continue
            id -= 1
            if not individual and first:
                val = helper.colored_input(
                    f"What &{type_name}& do you want to set your &{group_name}& to?:"
                )
                val = helper.get_int(val)
                if val == None:
                    helper.colored_text(
                        "Invalid input. Please enter a valid integer.", helper.Color.RED
                    )
                    continue
                first = False
            if individual:
                val = helper.colored_input(
                    f"What &{type_name}& do you want to set your &{names[id]}& to?:"
                )
                val = helper.get_int(val)
                if val == None:
                    helper.colored_text(
                        "Invalid input. Please enter a valid integer.", helper.Color.RED
                    )
                    continue
            if val is not None:
                data[id] = val - offset
        return data

    @staticmethod
    def select_options(
        options: list[str],
        index: bool = True,
        all_at_once: bool = True,
        extra_data: Optional[list[Any]] = None,
        mode: str = "edit",
        include: bool = False,
    ) -> Any:
        """
        Select options from a list.

        Args:
            options (list[str]): The options.
            index (bool, optional): True if the options should be indexed, False if not. Defaults to True.
            all_at_once (bool, optional): True if all options should be selected at once, False if not. Defaults to True.
            extra_data (Optional[list[Any]], optional): The extra data to include alongside the options. Defaults to None.
            mode (str, optional): The mode to use. Defaults to "edit".
            include (bool, optional): Whether to include if it was edited all at once or individually. Defaults to False.

        Returns:
            Any: The selected options.
        """
        helper.colored_list(options, extra_data=extra_data, index=index)
        total = len(options)
        if all_at_once:
            helper.colored_text(f"{total+1}. &Select all&")
        ids = helper.colored_input(
            f"What do you want to {mode} (You can enter multiple values separated by spaces to {mode} multiple at once):"
        ).split(" ")
        individual = True
        if str(total + 1) in ids and all_at_once:
            ids = list(range(1, total + 1))
            individual = False
            ids = helper.int_to_str_ls(ids)
        if include:
            return ids, individual
        return ids
