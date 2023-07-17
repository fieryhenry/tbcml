"""Module for handling battle cats mods."""
import copy
import zipfile
from typing import Any, Optional, Union

from tbcml import core


class ModEdit:
    """A class to represent a game edit."""

    def __init__(self, tree: list[Any], content: Any):
        """Initializes a new instance of the ModEdit class.

        Args:
            tree (list[Any]): The tree of the edit
            content (Any): The content of the edit
        """
        self.tree = tree
        self.content = content

    def tree_to_dict(self) -> dict[Any, Any]:
        """Converts the tree to a dictionary.

        Returns:
            dict[Any, Any]: The tree as a dictionary
        """
        tree_dict: dict[Any, Any] = {}
        temp_dict = tree_dict
        for i, item in enumerate(self.tree):
            if i == len(self.tree) - 1:
                temp_dict[item] = self.content
            else:
                temp_dict[item] = {}
                temp_dict = temp_dict[item]
        return tree_dict


class ModEditValueHandler:
    """A class to handle mod edit values."""

    def __init__(self, mod_edit_value: Any, current_value: Any):
        """Initializes a new instance of the ModEditValueHandler class.

        Args:
            mod_edit_value (Any): The mod edit value
            current_value (Any): The current value
        """
        self.mod_edit_value = str(mod_edit_value)
        self.current_value = current_value

    def get_value(self) -> int:
        """Gets the value of the mod edit.

        Returns:
            int: The value of the mod edit
        """
        whitelist = [
            "+",
            "-",
            "*",
            "/",
            "%",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "(",
            ")",
            " ",
            ".",
        ]
        expression = self.mod_edit_value.replace("x", str(self.current_value))
        for char in expression:
            if char not in whitelist:
                try:
                    return int(self.mod_edit_value)
                except ValueError:
                    return self.current_value
        try:
            return int(eval(expression))
        except:
            return self.current_value


class ModEditDictHandler:
    """A class to handle mod edit dictionaries."""

    def __init__(
        self,
        mod_edit_dict: dict[Any, Any],
        current: Union[dict[Any, Any], list[Any]],
    ):
        """Initializes a new instance of the ModEditDictHandler class.

        Args:
            mod_edit_dict (dict[Any, Any]): The mod edit dictionary
            current (Union[dict[Any, Any], list[Any]]): The current dictionary
        """
        self.mod_edit_dict = mod_edit_dict
        self.current = current

    def get_dict(self, convert_int: bool = False) -> dict[Any, Any]:
        """Turns the mod edit dictionary into a dictionary.

        Args:
            convert_int (bool, optional): Whether to convert the keys to integers. Defaults to False.

        Returns:
            dict[Any, Any]: The dictionary of the mod edit
        """
        dict_data: dict[Any, Any] = {}
        if "*" in self.mod_edit_dict:
            if isinstance(self.current, list):
                for i in range(len(self.current)):
                    dict_data[i] = self.mod_edit_dict["*"]
            else:
                for key in self.current:
                    if convert_int:
                        try:
                            key = int(key)
                        except ValueError:
                            pass
                    dict_data[key] = self.mod_edit_dict["*"]

        for key, value in self.mod_edit_dict.items():
            if key == "*":
                continue
            if convert_int:
                try:
                    key = int(key)
                except ValueError:
                    pass
            if isinstance(value, dict):
                dict_data = Mod.merge_dicts(dict_data, {key: value})
            else:
                dict_data[key] = value

        return dict_data


class Dependency:
    """A class to represent a mod dependency."""

    def __init__(self, mod_id: str, mod_version: str):
        """Initializes a new instance of the Dependency class.

        Args:
            mod_id (str): The mod id of the dependency
            mod_version (str): The mod version of the dependency
        """
        self.mod_id = mod_id
        self.mod_version = mod_version

    def to_dict(self) -> dict[str, Any]:
        """Converts the dependency to a dictionary.

        Returns:
            dict[str, Any]: The dependency as a dictionary
        """
        return {"mod_id": self.mod_id, "mod_version": self.mod_version}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Dependency":
        """Converts a dictionary to a dependency.

        Args:
            data (dict[str, Any]): The dictionary to convert

        Returns:
            Dependency: The dependency
        """
        return Dependency(data["mod_id"], data["mod_version"])

    def to_html(self) -> str:
        """Converts the dependency to HTML.

        Returns:
            str: The dependency as HTML
        """
        return f"<a href='https://tbcml.net/mod/{self.mod_id}'>{self.mod_id}</a> v{self.mod_version}"

    @staticmethod
    def from_str_str_list(data: list[tuple[str, str]]) -> list["Dependency"]:
        """Converts a list of tuples of strings to a list of dependencies.

        Returns:
            list[Dependency]: The list of dependencies
        """
        dependencies: list[Dependency] = []
        for mod_id, mod_version in data:
            dependencies.append(Dependency(mod_id, mod_version))
        return dependencies


class Mod:
    """A class to represent a mod."""

    def __init__(
        self,
        name: str,
        author: str,
        description: str,
        mod_id: str,
        mod_version: str,
        contributors: Optional[list[str]] = None,
        dependencies: Optional[list[Dependency]] = None,
        long_description: str = "",
        icon: Optional["core.BCImage"] = None,
        password: Optional[str] = None,
        encrypt: bool = True,
    ):
        """Initializes a new instance of the Mod class.

        Args:
            name (str): Name of the mod
            author (str): Author of the mod
            description (str): Description of the mod
            mod_id (str): Mod id of the mod
            mod_version (str): Mod version of the mod
            contributors (Optional[list[str]], optional): Contributors of the mod. Defaults to None.
            dependencies (Optional[list[Dependency]], optional): Dependencies of the mod. Defaults to None.
            long_description (str, optional): Long description of the mod. Defaults to "".
            icon (Optional[core.BCImage], optional): Icon of the mod. Defaults to None.
            password (Optional[str], optional): Password of the mod. Defaults to None.
        """
        self.name = name
        self.author = author
        self.description = description
        self.mod_id = mod_id
        self.mod_version = mod_version
        self.contributors = contributors if contributors is not None else []
        self.dependencies = dependencies if dependencies is not None else []
        self.long_description = long_description
        self.icon = icon if icon is not None else core.BCImage.from_size(512, 512)
        self.password = password
        self.encrypt = encrypt

        self.mod_edits: dict[str, Any] = {}
        self.game_files: dict[str, core.Data] = {}
        self.apk_files: dict[str, core.Data] = {}

        self.init_audio()
        self.init_scripts()
        self.init_patches()
        self.init_smali()

    def add_apk_file(self, file_name: str, data: "core.Data"):
        """Adds an APK file to the mod.

        Args:
            file_name (str): The name of the file
            data (core.Data): The data of the file
        """
        self.apk_files[file_name] = data

    def add_contributor(self, contributor: str):
        """Adds a contributor to the mod.

        Args:
            contributor (str): The contributor to add
        """
        if contributor not in self.contributors:
            self.contributors.append(contributor)

    def add_bcu_contributor(self, contributor: str):
        """Adds a BCU contributor to the mod.

        Args:
            contributor (str): The BCU contributor to add
        """
        if contributor not in self.contributors:
            self.add_contributor(f"{contributor} (BCU)")

    @staticmethod
    def get_extension() -> str:
        """Gets the extension of the mod.

        Returns:
            str: The extension of the mod
        """
        return ".bcmod"

    def get_full_mod_name(self) -> str:
        """Gets the full name of the mod.

        Returns:
            str: The full name of the mod
        """
        return f"{self.name}-{self.mod_id}{self.get_extension()}"

    def get_file_name(self) -> str:
        """Gets the file name of the mod.

        Returns:
            str: The file name of the mod
        """
        return f"{self.mod_id}{self.get_extension()}"

    def init_scripts(self):
        """Initializes the scripts of the mod."""
        self.scripts: core.FridaScripts = core.FridaScripts(
            [],
        )

    def init_patches(self):
        self.patches = core.LibPatches([])

    def init_audio(self):
        """Initializes the audio of the mod."""
        self.audio = core.Audio.create_empty()

    def init_smali(self):
        """Initializes the smali of the mod."""
        self.smali = core.SmaliSet.create_empty()

    def create_mod_json(self) -> dict[str, Any]:
        """Creates the mod.json file.

        Returns:
            dict[str, Any]: The mod.json file
        """
        return {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "mod_id": self.mod_id,
            "mod_version": self.mod_version,
            "contributors": self.contributors,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "long_description": self.long_description,
            "encrypt": self.encrypt,
        }

    def save(self, path: "core.Path"):
        """Saves the mod to a file.

        Args:
            path (core.Path): The path to save the mod to
        """
        data = self.to_data()
        path.write(data)

    def to_zip(self) -> "core.Zip":
        """Converts the mod to a zip file.

        Returns:
            core.Zip: The zip file
        """
        zip_file = core.Zip(encrypted=self.encrypt, password=self.password)

        self.audio.add_to_zip(zip_file)
        self.scripts.add_to_zip(zip_file)
        self.patches.add_to_zip(zip_file)
        self.smali.add_to_zip(zip_file)

        orignal_mod_edits = copy.deepcopy(self.mod_edits)

        self.add_images(zip_file, self.mod_edits)
        self.remove__image__(self.mod_edits)

        self.add_mod_edits_to_zip(zip_file, self.mod_edits)

        self.mod_edits = orignal_mod_edits

        for file_name, data in self.game_files.items():
            zip_file.add_file(core.Path("game_files/" + file_name), data)

        for file_name, data in self.apk_files.items():
            zip_file.add_file(core.Path("apk_files/" + file_name), data)

        icon = self.icon
        zip_file.add_file(core.Path("icon.png"), icon.to_data())

        json = core.JsonFile.from_object(self.create_mod_json())
        zip_file.add_file(core.Path("mod.json"), json.to_data())

        return zip_file

    def to_data(self) -> "core.Data":
        """Converts the mod to data.

        Returns:
            core.Data: The mod as data
        """
        zip_file = self.to_zip()

        return zip_file.to_data()

    def add_mod_edits_to_zip(
        self,
        zip: "core.Zip",
        dict_data: dict[Any, Any],
        parent: str = "mod_edits/",
    ):
        """Adds the mod edits to the zip.

        Args:
            zip (core.Zip): The zip to add the mod edits to
            dict_data (dict[Any, Any]): The mod edits
            parent (str, optional): The parent directory. Defaults to "mod_edits/".
        """
        for key, value in dict_data.items():
            if key == "*":
                key = "all"
            if self.is_dict_of_dicts(value):
                self.add_mod_edits_to_zip(zip, value, f"{parent}{key}/")
            else:
                zip.add_file(
                    core.Path(f"{parent}{key}.json"),
                    core.JsonFile.from_object(value).to_data(),
                )

    def add_images(
        self,
        zip: "core.Zip",
        dict_data: dict[Any, Any],
        parent: str = "mod_edits/",
    ):
        """Adds the images to the zip.

        Args:
            zip (core.Zip): Zip to add the images to
            dict_data (dict[Any, Any]): The mod edits
            parent (str, optional): The parent directory. Defaults to "mod_edits/".
        """
        for key, value in dict_data.items():
            if key == "*":
                key = "all"
            if isinstance(value, dict):
                self.add_images(zip, value, f"{parent}{key}/")  # type: ignore
            else:
                if key != "__image__":
                    continue
                zip.add_file(
                    core.Path(f"{parent[:-1]}.png"),
                    core.BCImage.from_base_64(value).to_data(),
                )

    def remove__image__(self, dict_data: dict[Any, Any]):
        """Removes the __image__ key from the mod edits.

        Args:
            dict_data (dict[Any, Any]): The mod edits
        """
        keys = list(dict_data.keys())
        for key in keys:
            if key == "__image__":
                del dict_data[key]
            elif isinstance(dict_data[key], dict):
                self.remove__image__(dict_data[key])

    def get_mod_edits_from_zip(self, zip: "core.Zip", only_images: bool = False):
        """Gets the mod edits from the zip.

        Args:
            zip (core.Zip): The zip to get the mod edits from
            only_images (bool, optional): Whether to only get the images. Defaults to False.
        """
        for file in zip.get_paths():
            if file.path.startswith("mod_edits/"):
                path = file.path.split("/")
                path = path[1:]
                path = path[: len(path) - 1]
                zip_file = zip.get_file(file)
                path.append(file.get_file_name_without_extension())
                if zip_file is not None:
                    self.add_mod_edit_path(
                        path,
                        zip_file,
                        file,
                        self.mod_edits,
                        only_images,
                    )

    def add_mod_edit_path(
        self,
        path: list[str],
        file: "core.Data",
        file_path: "core.Path",
        parent: Optional[dict[Any, Any]] = None,
        only_images: bool = False,
    ):
        """Adds a mod edit path to the mod edits.

        Args:
            path (list[str]): The path to add
            file (core.Data): The file to add
            file_path (core.Path): The path of the file
            parent (Optional[dict[Any, Any]], optional): The parent. Defaults to None.
            only_images (bool, optional): Whether to only add images. Defaults to False.
        """
        if parent is None:
            parent = self.mod_edits
        key = path[0]
        if key == "all":
            key = "*"
        if len(path) == 1:
            if file_path.get_extension() == "json" and not only_images:
                parent[key] = core.JsonFile.from_data(file).get_json()
            elif file_path.get_extension() == "png" and only_images:
                parent[key] = {"__image__": core.BCImage(file).to_base_64()}
        else:
            if key not in parent:
                parent[key] = {}
            self.add_mod_edit_path(path[1:], file, file_path, parent[key], only_images)

    def is_dict_of_dicts(self, data: dict[Any, Any]) -> bool:
        """Checks if the data is a dict of dicts.

        Args:
            data (dict[Any, Any]): The data to check

        Returns:
            bool: Whether the data is a dict of dicts
        """
        for key in data:
            if not isinstance(data[key], dict):
                return False
        return True

    @staticmethod
    def load(path: "core.Path") -> Optional["Mod"]:
        """Loads a mod from a path.

        Returns:
            Optional[Mod]: The loaded mod
        """
        try:
            zip_file = core.Zip.from_file(path, encrypted=True, validate_password=False)
        except zipfile.BadZipFile:
            return None
        return Mod.load_from_zip(zip_file)

    @staticmethod
    def load_from_zip(zip_file: "core.Zip") -> Optional["Mod"]:
        """Loads a mod from a zip.

        Returns:
            Optional[Mod]: The loaded mod
        """
        json_file = zip_file.get_file(core.Path("mod.json"))
        if json_file is None:
            return None
        json = core.JsonFile.from_data(json_file)

        icon = zip_file.get_file(core.Path("icon.png"))
        icon = core.BCImage(icon)

        mod = Mod.from_mod_json(json.get_json(), icon)

        mod.audio = core.Audio.from_zip(zip_file)
        mod.scripts = core.FridaScripts.from_zip(zip_file, mod)
        mod.patches = core.LibPatches.from_zip(zip_file)
        mod.smali = core.SmaliSet.from_zip(zip_file)

        mod.mod_edits = {}
        mod.get_mod_edits_from_zip(zip_file, False)
        mod.get_mod_edits_from_zip(zip_file, True)

        mod.game_files = {}
        for file in zip_file.get_paths():
            if file.path.startswith("game_files/"):
                file_zip = zip_file.get_file(file)
                if file_zip is not None:
                    mod.game_files[file.get_file_name()] = file_zip

        mod.apk_files = {}
        for file in zip_file.get_paths():
            if file.path.startswith("apk_files/"):
                file_zip = zip_file.get_file(file)
                if file_zip is not None:
                    mod.apk_files[file.get_file_name()] = file_zip
        return mod

    @staticmethod
    def from_mod_json(
        data: dict[str, Any],
        icon: Optional["core.BCImage"] = None,
    ) -> "Mod":
        """Creates a mod from a mod.json.

        Args:
            data (dict[str, Any]): The mod.json data
            icon (Optional[core.BCImage], optional): The mod icon. Defaults to None.

        Returns:
            Mod: The created mod
        """
        return Mod(
            data["name"],
            data["author"],
            data["description"],
            data["mod_id"],
            data["mod_version"],
            data.get("contributors", []),
            [Dependency.from_dict(x) for x in data.get("dependencies", [])],
            data.get("long_description", ""),
            icon,
        )

    @staticmethod
    def create_mod_id() -> str:
        """Creates a mod id.

        Returns:
            str: The created mod id
        """
        return core.Random.get_alpha_string(16)

    def import_mod(self, other: "Mod"):
        """Imports another mod into this mod.

        Args:
            other (Mod): The other mod
        """
        self.audio.import_audio(other.audio)
        self.scripts.import_scripts(other.scripts)
        self.patches.import_patches(other.patches)
        self.smali.import_smali(other.smali)
        self.game_files = self.merge_dicts(self.game_files, other.game_files)
        self.apk_files = self.merge_dicts(self.apk_files, other.apk_files)
        self.add_mod_edit(other.mod_edits)

    def import_mods(self, others: list["Mod"]):
        """Imports other mods into this mod.

        Args:
            others (list[Mod]): The other mods
        """
        for other in others:
            self.import_mod(other)

    def get_hash(self) -> str:
        """Gets the hash of the mod.

        Returns:
            str: The hash of the mod
        """
        return core.Hash(core.HashAlgorithm.SHA256).get_hash(self.to_data()).to_hex()

    def add_mod_edit(self, mod_edit: Union[dict[str, Any], "ModEdit"]):
        """Adds a mod edit to the mod.

        Args:
            mod_edit (Union[dict[str, Any], ModEdit]): The mod edit
        """
        if isinstance(mod_edit, dict):
            self.mod_edits = self.merge_dicts(self.mod_edits, mod_edit)
        else:
            self.mod_edits = self.merge_dicts(self.mod_edits, mod_edit.tree_to_dict())

        self.mod_edits_key_int_to_str(self.mod_edits)

    def add_mod_edits(self, mod_edits: Union[list[dict[str, Any]], list["ModEdit"]]):
        """Adds mod edits to the mod.

        Args:
            mod_edits (Union[list[dict[str, Any]], list[ModEdit]]): The mod edits
        """
        for mod_edit in mod_edits:
            self.add_mod_edit(mod_edit)

    def mod_edits_key_int_to_str(self, mod_edits: dict[str, Any]):
        """Converts the keys of the mod edits from int to str.

        Args:
            mod_edits (dict[str, Any]): The mod edits
        """
        new_mod_edits: dict[str, Any] = {}
        for key, value in mod_edits.items():
            if isinstance(key, int):
                new_mod_edits[str(key)] = value
            else:
                new_mod_edits[key] = value
        for key, value in new_mod_edits.items():
            if isinstance(value, dict):
                self.mod_edits_key_int_to_str(value)  # type: ignore
        self.mod_edits = new_mod_edits

    @staticmethod
    def merge_dicts(dict_1: dict[Any, Any], dict_2: dict[Any, Any]) -> dict[Any, Any]:
        """Merges two dicts.

        Args:
            dict_1 (dict[Any, Any]): First dict
            dict_2 (dict[Any, Any]): Second dict

        Returns:
            dict[Any, Any]: The merged dict
        """
        for key, value in dict_2.copy().items():
            if (
                key in dict_1
                and isinstance(dict_1[key], dict)
                and isinstance(value, dict)
            ):
                dict_1[key] = Mod.merge_dicts(dict_1[key].copy(), value.copy())  # type: ignore
            else:
                dict_1[key] = value

        return dict_1

    def is_risky(self) -> bool:
        """Checks if the mod could contain malware.

        Returns:
            bool: True if the mod could contain malware, False otherwise
        """
        if not self.scripts.is_empty():
            return True
        if not self.patches.is_empty():
            return True
        if not self.smali.is_empty():
            return True
        for name in self.apk_files:
            if name.endswith(".so"):
                return True
            if name.endswith(".dex"):
                return True
            if name.endswith(".jar"):
                return True
        return False
