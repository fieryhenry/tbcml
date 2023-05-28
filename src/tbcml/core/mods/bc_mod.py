from typing import Any, Optional, Union
import zipfile
from tbcml.core import io, crypto, mods
import copy


class ModEdit:
    def __init__(self, tree: list[Any], content: Any):
        self.tree = tree
        self.content = content

    def tree_to_dict(self):
        tree_dict: dict[Any, Any] = {}
        temp_dict = tree_dict
        for i in range(len(self.tree)):
            if i == len(self.tree) - 1:
                temp_dict[self.tree[i]] = self.content
            else:
                temp_dict[self.tree[i]] = {}
                temp_dict = temp_dict[self.tree[i]]
        return tree_dict


class ModEditValueHandler:
    def __init__(self, mod_edit_value: Any, current_value: Any):
        self.mod_edit_value = str(mod_edit_value)
        self.current_value = current_value

    def get_value(self) -> int:
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
    def __init__(
        self, mod_edit_dict: dict[Any, Any], current: Union[dict[Any, Any], list[Any]]
    ):
        self.mod_edit_dict = mod_edit_dict
        self.current = current

    def get_dict(self, convert_int: bool = False) -> dict[Any, Any]:
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
    def __init__(self, mod_id: str, mod_version: str):
        self.mod_id = mod_id
        self.mod_version = mod_version

    def to_dict(self):
        return {"mod_id": self.mod_id, "mod_version": self.mod_version}

    @staticmethod
    def from_dict(data: dict[str, Any]):
        return Dependency(data["mod_id"], data["mod_version"])

    def to_html(self):
        return f"<a href='https://tbcml.net/mod/{self.mod_id}'>{self.mod_id}</a> v{self.mod_version}"

    @staticmethod
    def from_str_str_list(data: list[tuple[str, str]]):
        dependencies: list[Dependency] = []
        for mod_id, mod_version in data:
            dependencies.append(Dependency(mod_id, mod_version))
        return dependencies


class Mod:
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
        icon: Optional["io.bc_image.BCImage"] = None,
    ):
        self.name = name
        self.author = author
        self.description = description
        self.mod_id = mod_id
        self.mod_version = mod_version
        self.contributors = contributors if contributors is not None else []
        self.dependencies = dependencies if dependencies is not None else []
        self.long_description = long_description
        self.icon = icon

        self.mod_edits: dict[str, Any] = {}
        self.game_files: dict[str, io.data.Data] = {}
        self.apk_files: dict[str, io.data.Data] = {}

        self.init_audio()
        self.init_scripts()
        self.init_smali()

    @staticmethod
    def get_extension() -> str:
        return ".bcmod"

    def get_full_mod_name(self) -> str:
        return f"{self.name}-{self.mod_id}{self.get_extension()}"

    def get_file_name(self) -> str:
        return f"{self.mod_id}{self.get_extension()}"

    def init_scripts(self):
        self.scripts: mods.frida_script.Scripts = mods.frida_script.Scripts(
            [],
        )

    def init_audio(self):
        self.audio = io.audio.Audio.create_empty()

    def init_smali(self):
        self.smali = mods.smali.SmaliSet.create_empty()

    def create_mod_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "mod_id": self.mod_id,
            "mod_version": self.mod_version,
            "contributors": self.contributors,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
            "long_description": self.long_description,
        }

    def save(self, path: "io.path.Path"):
        data = self.to_data()
        path.write(data)

    def to_data(self):
        zip_file = io.zip.Zip()

        self.audio.add_to_zip(zip_file)
        self.scripts.add_to_zip(zip_file)
        self.smali.add_to_zip(zip_file)

        orignal_mod_edits = copy.deepcopy(self.mod_edits)

        self.add_images(zip_file, self.mod_edits)
        self.remove__image__(self.mod_edits)

        self.add_mod_edits_to_zip(zip_file, self.mod_edits)

        self.mod_edits = orignal_mod_edits

        for file_name, data in self.game_files.items():
            zip_file.add_file(io.path.Path("game_files/" + file_name), data)

        for file_name, data in self.apk_files.items():
            zip_file.add_file(io.path.Path("apk_files/" + file_name), data)

        icon = self.icon
        if icon is None:
            icon = io.bc_image.BCImage.create_empty()
        zip_file.add_file(io.path.Path("icon.png"), icon.to_data())

        json = io.json_file.JsonFile.from_object(self.create_mod_json())
        zip_file.add_file(io.path.Path("mod.json"), json.to_data())
        return zip_file.to_data()

    def add_mod_edits_to_zip(
        self, zip: "io.zip.Zip", dict_data: dict[Any, Any], parent: str = "mod_edits/"
    ):
        for key, value in dict_data.items():
            if key == "*":
                key = "all"
            if self.is_dict_of_dicts(value):
                self.add_mod_edits_to_zip(zip, value, f"{parent}{key}/")
            else:
                zip.add_file(
                    io.path.Path(f"{parent}{key}.json"),
                    io.json_file.JsonFile.from_object(value).to_data(),
                )

    def add_images(
        self, zip: "io.zip.Zip", dict_data: dict[Any, Any], parent: str = "mod_edits/"
    ):
        for key, value in dict_data.items():
            if key == "*":
                key = "all"
            if isinstance(value, dict):
                self.add_images(zip, value, f"{parent}{key}/")  # type: ignore
            else:
                if key != "__image__":
                    continue
                zip.add_file(
                    io.path.Path(f"{parent[:-1]}.png"),
                    io.bc_image.BCImage.from_base_64(value).to_data(),
                )

    def remove__image__(self, dict_data: dict[Any, Any]):
        keys = list(dict_data.keys())
        for key in keys:
            if key == "__image__":
                del dict_data[key]
            elif isinstance(dict_data[key], dict):
                self.remove__image__(dict_data[key])

    def get_mod_edits_from_zip(self, zip: "io.zip.Zip", only_images: bool = False):
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
        file: "io.data.Data",
        file_path: "io.path.Path",
        parent: Optional[dict[Any, Any]] = None,
        only_images: bool = False,
    ):
        if parent is None:
            parent = self.mod_edits
        key = path[0]
        if key == "all":
            key = "*"
        if len(path) == 1:
            if file_path.get_extension() == "json" and not only_images:
                parent[key] = io.json_file.JsonFile.from_data(file).get_json()
            elif file_path.get_extension() == "png" and only_images:
                parent[key] = {"__image__": io.bc_image.BCImage(file).to_base_64()}
        else:
            if key not in parent:
                parent[key] = {}
            self.add_mod_edit_path(path[1:], file, file_path, parent[key], only_images)

    def is_dict_of_dicts(self, data: dict[Any, Any]) -> bool:
        for key in data:
            if not isinstance(data[key], dict):
                return False
        return True

    @staticmethod
    def load(path: "io.path.Path") -> Optional["Mod"]:
        try:
            zip_file = io.zip.Zip.from_file(path)
        except zipfile.BadZipFile:
            return None
        json_file = zip_file.get_file(io.path.Path("mod.json"))
        if json_file is None:
            return None
        json = io.json_file.JsonFile.from_data(json_file)

        icon = zip_file.get_file(io.path.Path("icon.png"))
        if icon is not None:
            icon = io.bc_image.BCImage(icon)

        mod = Mod.from_mod_json(json.get_json(), icon)

        mod.audio = io.audio.Audio.from_zip(zip_file)
        mod.scripts = mods.frida_script.Scripts.from_zip(zip_file, mod)
        mod.smali = mods.smali.SmaliSet.from_zip(zip_file)

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
        data: dict[str, Any], icon: Optional["io.bc_image.BCImage"] = None
    ) -> "Mod":
        return Mod(
            data["name"],
            data.get("authors", []),
            data["description"],
            data["mod_id"],
            data["mod_version"],
            data.get("credits", []),
            [Dependency.from_dict(x) for x in data.get("dependencies", [])],
            data.get("long_description", ""),
            icon,
        )

    @staticmethod
    def create_mod_id() -> str:
        return crypto.Random.get_alpha_string(16)

    def import_mod(self, other: "Mod"):
        self.audio.import_audio(other.audio)
        self.scripts.import_scripts(other.scripts)
        self.smali.import_smali(other.smali)
        self.game_files = self.merge_dicts(self.game_files, other.game_files)
        self.apk_files = self.merge_dicts(self.apk_files, other.apk_files)
        self.add_mod_edit(other.mod_edits)

    def import_mods(self, others: list["Mod"]):
        for other in others:
            self.import_mod(other)

    def get_hash(self) -> str:
        return (
            crypto.Hash(crypto.HashAlgorithm.SHA256).get_hash(self.to_data()).to_hex()
        )

    def add_mod_edit(self, mod_edit: Union[dict[str, Any], "ModEdit"]):
        if isinstance(mod_edit, dict):
            self.mod_edits = self.merge_dicts(self.mod_edits, mod_edit)
        else:
            self.mod_edits = self.merge_dicts(self.mod_edits, mod_edit.tree_to_dict())

        self.mod_edits_key_int_to_str(self.mod_edits)

    def mod_edits_key_int_to_str(self, mod_edits: dict[str, Any]):
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
