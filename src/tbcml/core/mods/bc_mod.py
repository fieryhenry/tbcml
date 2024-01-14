import enum
from typing import Any, Optional, Sequence, TypeVar, Union
from tbcml import core
import json
from dataclasses import fields


class ModificationType(enum.Enum):
    CAT = "cat"
    ENEMY = "enemy"
    SHOP = "shop"
    LOCALIZABLE = "localizable"

    @staticmethod
    def from_str_value(string: str) -> Optional["ModificationType"]:
        for type in ModificationType:
            if type.value == string:
                return type
        return None

    def get_cls(self) -> type:
        if self == ModificationType.CAT:
            return core.Cat
        if self == ModificationType.ENEMY:
            return core.Enemy
        if self == ModificationType.SHOP:
            return core.ItemShop
        if self == ModificationType.LOCALIZABLE:
            return core.Localizable
        raise NotImplementedError()


class ModPath(enum.Enum):
    MODIFICATIONS = "modifications"
    SCRIPTS = "scripts"
    METADATA = "metadata.json"
    SMALI = "smali"
    GAME_FILES = "game_files"
    APK_FILES = "apk_files"
    LIB_PATCHES = "lib_patches"


T = TypeVar("T")


class Modification:
    Schema: Any

    def __init__(self, modification_type: ModificationType):
        self.modification_type = modification_type

    def to_json(self) -> str:
        self.pre_to_json()
        return self.Schema().dumps(self)  # type: ignore

    @staticmethod
    def from_json(obj: type[T], data: str) -> T:
        return obj.Schema().loads(data)  # type: ignore

    def apply(self, game_data: "core.GamePacks"):
        ...

    @staticmethod
    def apply_csv_fields(
        obj: Any,
        csv: "core.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
        remove_others: bool = True,
        field_offset: int = 0,
    ):
        if not hasattr(obj, "__dataclass_fields__"):
            raise ValueError("obj is not a dataclass!")
        if required_values is None:
            required_values = []

        csv_fields: list[core.CSVField[Any]] = []
        for field in fields(obj):
            name = field.name
            value = getattr(obj, name)
            if isinstance(value, core.CSVField):
                value.col_index += field_offset
                csv_fields.append(value)  # type: ignore

        if remove_others:
            for value in csv_fields:
                value.initialize_csv(csv, writing=True)
                csv.set_line([], csv.index)
                value.uninitialize_csv(csv)

        for value in csv_fields:
            original_len = len(csv.get_current_line() or [])
            for ind, val in required_values:
                if ind < original_len:
                    continue
                csv.set_str(val, ind)

            value.write_to_csv(csv)
            value.col_index -= field_offset

    @staticmethod
    def read_csv_fields(
        obj: Any,
        csv: "core.CSV",
        field_offset: int = 0,
    ):
        if not hasattr(obj, "__dataclass_fields__"):
            raise ValueError("obj is not a dataclass!")

        for field in fields(obj):
            name = field.name
            value = getattr(obj, name)
            if isinstance(value, core.CSVField):
                value.col_index += field_offset
                value.read_from_csv(csv)
                value.col_index -= field_offset

    def pre_to_json(self) -> None:
        raise NotImplementedError

    def get_custom_html(self) -> str:
        return ""


class Mod:
    def __init__(
        self,
        name: str = "",
        authors: Union[str, list[str]] = "",
        description: str = "",
        custom_html: Optional[str] = None,
    ):
        """Initialize a mod

        Args:
            name (str, optional): The name of the mod, should be relatively short. Defaults to "".
            authors (Union[str, list[str]], optional): The authors of the mod, can either be a single string e.g `"fieryhenry"`, but can be a list of names e.g `["fieryhenry", "enderelijas"]`. Defaults to "".
            description (str, optional): Description of the mod, can be a longer string. Defaults to "".
            custom_html (Optional[str], optional): The HTML to load when the user clicks this mod in the transfer menu mod list. Defaults to None which means that tbcml will create a basic page for you.
        """
        self.name = name
        if isinstance(authors, str):
            authors = [authors]
        self.authors = authors
        self.description = description
        self.custom_html = custom_html

        self.modifications: list[Modification] = []
        self.scripts: list[core.FridaScript] = []

        self.game_files: dict[str, core.Data] = {}
        self.apk_files: dict[core.Path, core.Data] = {}

        self.smali: core.SmaliSet = core.SmaliSet.create_empty()
        self.patches: core.LibPatches = core.LibPatches.create_empty()

    def metadata_to_json(self) -> str:
        data = {
            "name": self.name,
            "authors": self.authors,
            "description": self.description,
            "custom_html": self.custom_html,
        }
        return json.dumps(data)

    @staticmethod
    def metadata_from_json(data: str) -> "Mod":
        obj = json.loads(data)
        name = obj.get("name", "")
        authors = obj.get("authors", "")
        description = obj.get("description", "")
        custom_html = obj.get("custom_html", None)
        return Mod(
            name=name,
            authors=authors,
            description=description,
            custom_html=custom_html,
        )

    def to_zip(self) -> "core.Data":
        zipfile = core.Zip()
        metadata_json = self.metadata_to_json()
        metadata_file_name = core.Path(ModPath.METADATA.value)
        zipfile.add_file(metadata_file_name, core.Data(metadata_json))

        self.add_modifications_to_zip(zipfile)
        self.add_scripts_to_zip(zipfile)
        self.add_game_files_to_zip(zipfile)
        self.add_apk_files_to_zip(zipfile)

        self.smali.add_to_zip(zipfile)
        self.patches.add_to_zip(zipfile)

        return zipfile.to_data()

    def add_apk_files_to_zip(self, zipfile: "core.Zip"):
        for name, data in self.apk_files.items():
            path = core.Path(ModPath.APK_FILES.value).add(name)
            zipfile.add_file(path, data)

    def add_game_files_to_zip(self, zipfile: "core.Zip"):
        for name, data in self.game_files.items():
            path = core.Path(ModPath.GAME_FILES.value).add(name)
            zipfile.add_file(path, data)

    def add_scripts_to_zip(self, zipfile: "core.Zip"):
        for i, script in enumerate(self.scripts):
            script.add_to_zip(i, zipfile)

    def add_modifications_to_zip(self, zipfile: "core.Zip"):
        for i, modification in enumerate(self.modifications):
            filepath = (
                core.Path(ModPath.MODIFICATIONS.value)
                .add(modification.modification_type.value)
                .add(f"{i}.json")
            )
            json_data = modification.to_json()
            zipfile.add_file(filepath, core.Data(json_data))

    @staticmethod
    def from_zip(data: "core.Data") -> "Mod":
        zipfile = core.Zip(data)
        metadata_file_name = core.Path(ModPath.METADATA.value)
        metadata_json = zipfile.get_file(metadata_file_name)
        if metadata_json is None:
            return Mod()
        mod = Mod.metadata_from_json(metadata_json.to_str())

        Mod.modifications_from_zip(zipfile, mod)
        Mod.scripts_from_zip(zipfile, mod)
        Mod.game_files_from_zip(zipfile, mod)
        Mod.apk_files_from_zip(zipfile, mod)

        mod.smali = core.SmaliSet.from_zip(zipfile)
        mod.patches = core.LibPatches.from_zip(zipfile)

        return mod

    @staticmethod
    def get_files_in_mod_path(zipfile: "core.Zip", path_type: ModPath):
        return zipfile.get_paths_in_folder(core.Path(path_type.value))

    @staticmethod
    def apk_files_from_zip(zipfile: "core.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.APK_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                key = path.remove_prefix(ModPath.APK_FILES.value)
                mod.apk_files[key] = data

    @staticmethod
    def game_files_from_zip(zipfile: "core.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.GAME_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                mod.game_files[path.basename()] = data

    @staticmethod
    def scripts_from_zip(zipfile: "core.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.SCRIPTS):
            script = core.FridaScript.from_json(path.read().to_str())
            mod.add_script(script)

    @staticmethod
    def modifications_from_zip(zipfile: "core.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.MODIFICATIONS):
            if not path.get_extension() == "json":
                continue
            modification_type = path.parent().basename()
            dt = zipfile.get_file(path)
            if dt is None:
                continue
            modifiction = Mod.modification_from_json((modification_type, dt.to_str()))
            mod.add_modification(modifiction)

    def save(self, path: "core.Path"):
        self.to_zip().to_file(path)

    def add_modification(self, modification: "Modification"):
        self.modifications.append(modification)

    def add_script(self, script: "core.FridaScript"):
        self.scripts.append(script)

    def add_smali(self, smali: "core.Smali"):
        self.smali.add(smali)

    def get_scripts_str(self, apk: "core.Apk") -> tuple[dict[str, str], bool]:
        scripts_dict: dict[str, str] = {}
        inject_smali = False
        for script in self.scripts:
            scripts_str, inj = script.get_scripts_str(apk, self.name, self.authors)
            if inj:
                inject_smali = True
            for arc, string in scripts_str.items():
                if arc not in scripts_dict:
                    scripts_dict[arc] = ""
                scripts_dict[arc] += string + "\n"
        return scripts_dict, inject_smali

    def apply_modifications(self, game_packs: "core.GamePacks"):
        for modification in self.modifications:
            modification.apply(game_packs)

    def apply_game_files(self, game_packs: "core.GamePacks"):
        for file, data in self.game_files.items():
            game_packs.set_file(file, data)

    def apply_apk_files(self, apk: "core.Apk"):
        for file, data in self.apk_files.items():
            path = apk.extracted_path.add(file)
            path.parent().generate_dirs()
            path.write(data)

    def apply_to_game_data(self, game_packs: "core.GamePacks"):
        self.apply_modifications(game_packs)
        self.apply_game_files(game_packs)

    def apply_to_apk(self, apk: "core.Apk"):
        self.apply_apk_files(apk)

    def modifications_to_json(self) -> list[tuple[str, str]]:
        data: list[tuple[str, str]] = []
        for modification in self.modifications:
            data.append((modification.modification_type.value, modification.to_json()))
        return data

    @staticmethod
    def modifications_from_json(data: list[tuple[str, str]]):
        modifications: list[Modification] = []
        for dt in data:
            modifications.append(Mod.modification_from_json(dt))

    @staticmethod
    def modification_from_json(data: tuple[str, str]):
        mod_type, modification_dt = data
        cls = None

        type = ModificationType.from_str_value(mod_type)
        if type is None:
            raise ValueError("Invalid Modification")

        cls = type.get_cls()
        return Modification.from_json(cls, modification_dt)

    def get_custom_html(self) -> str:
        if self.custom_html is not None:
            return self.custom_html
        base_mod = (
            core.AssetLoader.get_asset_file_path(core.Path("html").add("base_mod.html"))
            .read()
            .to_str()
        )

        base_mod = base_mod.replace("{{MOD_NAME}}", self.name)
        base_mod = base_mod.replace("{{MOD_AUTHORS}}", ", ".join(self.authors))
        base_mod = base_mod.replace("{{MOD_DESCRIPTION}}", self.description)

        modifications_str = ""

        for modification in self.modifications:
            html = modification.get_custom_html()
            modifications_str += f'<br><span class="iro">[{modification.modification_type.name}] </span>{html}<br>'

        base_mod = base_mod.replace("{{MODIFICATIONS}}", modifications_str)

        script_str = ""
        for script in self.scripts:
            html = script.get_custom_html()
            script_str += "<br>" + html + "<br>"

        base_mod = base_mod.replace("{{SCRIPTS}}", script_str)

        return base_mod
