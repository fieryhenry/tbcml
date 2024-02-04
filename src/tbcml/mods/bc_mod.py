import dataclasses
import enum
from typing import Any, Optional, Sequence, TypeVar, Union
import tbcml
import json


class ModificationType(enum.Enum):
    CAT = "cat"
    ENEMY = "enemy"
    SHOP = "shop"
    LOCALIZABLE = "localizable"
    MAP = "map"

    @staticmethod
    def from_str_value(string: str) -> Optional["ModificationType"]:
        for type in ModificationType:
            if type.value == string:
                return type
        return None

    def get_cls(self) -> type:
        if self == ModificationType.CAT:
            return tbcml.Cat
        if self == ModificationType.ENEMY:
            return tbcml.Enemy
        if self == ModificationType.SHOP:
            return tbcml.ItemShop
        if self == ModificationType.LOCALIZABLE:
            return tbcml.Localizable
        if self == ModificationType.MAP:
            return tbcml.Map
        raise NotImplementedError()


class ModPath(enum.Enum):
    MODIFICATIONS = "modifications"
    SCRIPTS = "scripts"
    METADATA = "metadata.json"
    SMALI = "smali"
    GAME_FILES = "game_files"
    APK_FILES = "apk_files"
    LIB_PATCHES = "lib_patches"
    COMPILATION_TARGETS = "compiled_game_files"


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
        cls = obj.Schema().loads(data)  # type: ignore
        cls.post_from_json()  # type: ignore
        return cls  # type: ignore

    def apply(self, game_data: "tbcml.GamePacks"): ...

    @staticmethod
    def apply_csv_fields(
        obj: Any,
        csv: "tbcml.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
        remove_others: bool = True,
        field_offset: int = 0,
        length: Optional[int] = None,
    ):
        csv_name_len = len("csv__")

        cleared_lines: dict[int, bool] = {}

        for name, value in obj.__dict__.items():
            if isinstance(value, tbcml.CSVField):
                value.col_index += field_offset
                new_name = name[csv_name_len:]
                new_value = getattr(obj, new_name)
                value.value = new_value

                if remove_others:
                    value.initialize_csv(csv, writing=True)
                    if not cleared_lines.get(csv.index):
                        cleared_lines[csv.index] = True
                        if csv.index >= len(csv.lines) or csv.lines[csv.index]:
                            csv.set_line([], csv.index)
                    value.uninitialize_csv(csv)

                if required_values:
                    value.initialize_csv(csv, writing=True)
                    original_len = 0
                    if csv.index < len(csv.lines):
                        original_len = len(csv.lines[csv.index])

                    for ind, val in required_values:
                        if ind < original_len:
                            continue
                        csv.set_str(val, ind, length)
                    value.uninitialize_csv(csv)

                value.write_to_csv(csv, length)
                value.col_index -= field_offset

    @staticmethod
    def read_csv_fields(
        obj: Any,
        csv: "tbcml.CSV",
        required_values: Optional[Sequence[tuple[int, Union[str, int]]]] = None,
        field_offset: int = 0,
    ):
        csv_str_len = len("csv__")

        for name, value in obj.__dict__.items():
            if isinstance(value, tbcml.CSVField):
                value.col_index += field_offset
                if not required_values:
                    value.read_from_csv(csv)
                else:
                    for ind, val in required_values:
                        if ind == value.col_index:
                            value.read_from_csv(csv, default=val)
                            break
                    else:
                        value.read_from_csv(csv)

                value.col_index -= field_offset

                new_name = name[csv_str_len:]
                setattr(obj, new_name, value.value)  # type: ignore

    def pre_to_json(self) -> None: ...

    def post_from_json(self) -> None: ...

    def get_custom_html(self) -> str:
        return ""

    @staticmethod
    def sync(curr: Any, new: Any):
        if not dataclasses.is_dataclass(curr) or not dataclasses.is_dataclass(new):
            return
        for field in dataclasses.fields(curr):
            curr_value = getattr(curr, field.name)
            new_value = getattr(new, field.name)
            if curr_value is None:
                setattr(curr, field.name, new_value)
                continue
            if isinstance(curr_value, list) and not curr_value:
                setattr(curr, field.name, new_value)
                continue

            Modification.sync(curr_value, new_value)


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
        self.scripts: list[tbcml.FridaScript] = []

        self.game_files: dict[str, tbcml.Data] = {}
        self.apk_files: dict[tbcml.Path, tbcml.Data] = {}

        self.smali: tbcml.SmaliSet = tbcml.SmaliSet.create_empty()
        self.patches: tbcml.LibPatches = tbcml.LibPatches.create_empty()

        self.compilation_targets: list[tbcml.CompilationTarget] = []

    def add_compilation_target(self, target: "tbcml.CompilationTarget"):
        self.compilation_targets.append(target)

    def add_apk_file(
        self,
        apk_path: "tbcml.PathStr",
        file_data: Optional["tbcml.Data"] = None,
        local_path: Optional["tbcml.PathStr"] = None,
    ):
        data = None
        if local_path is not None:
            data = tbcml.Path(local_path).read()
        if file_data is not None:
            data = file_data
        if data is None:
            raise ValueError("Either local_path or data must be specified!")
        path = tbcml.Path(apk_path)
        self.apk_files[path] = data

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

    def to_zip(self) -> "tbcml.Data":
        zipfile = tbcml.Zip()
        metadata_json = self.metadata_to_json()
        metadata_file_name = tbcml.Path(ModPath.METADATA.value)
        zipfile.add_file(metadata_file_name, tbcml.Data(metadata_json))

        self.add_modifications_to_zip(zipfile)
        self.add_scripts_to_zip(zipfile)
        self.add_game_files_to_zip(zipfile)
        self.add_apk_files_to_zip(zipfile)
        self.add_compilation_targets_to_zip(zipfile)

        self.smali.add_to_zip(zipfile)
        self.patches.add_to_zip(zipfile)

        return zipfile.to_data()

    def add_compilation_targets_to_zip(self, zipfile: "tbcml.Zip"):
        for i, target in enumerate(self.compilation_targets):
            target.add_to_zip(i, zipfile)

    def add_apk_files_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.apk_files.items():
            path = tbcml.Path(ModPath.APK_FILES.value).add(name)
            zipfile.add_file(path, data)

    def add_game_files_to_zip(self, zipfile: "tbcml.Zip"):
        for name, data in self.game_files.items():
            path = tbcml.Path(ModPath.GAME_FILES.value).add(name)
            zipfile.add_file(path, data)

    def add_scripts_to_zip(self, zipfile: "tbcml.Zip"):
        for i, script in enumerate(self.scripts):
            script.add_to_zip(i, zipfile)

    def add_modifications_to_zip(self, zipfile: "tbcml.Zip"):
        for i, modification in enumerate(self.modifications):
            filepath = (
                tbcml.Path(ModPath.MODIFICATIONS.value)
                .add(modification.modification_type.value)
                .add(f"{i}.json")
            )
            json_data = modification.to_json()
            zipfile.add_file(filepath, tbcml.Data(json_data))

    @staticmethod
    def from_file(path: "tbcml.PathStr"):
        return Mod.from_zip(tbcml.Path(path).read())

    @staticmethod
    def from_zip(data: "tbcml.Data") -> "Mod":
        zipfile = tbcml.Zip(data)
        metadata_file_name = tbcml.Path(ModPath.METADATA.value)
        metadata_json = zipfile.get_file(metadata_file_name)
        if metadata_json is None:
            return Mod()
        mod = Mod.metadata_from_json(metadata_json.to_str())

        Mod.modifications_from_zip(zipfile, mod)
        Mod.scripts_from_zip(zipfile, mod)
        Mod.game_files_from_zip(zipfile, mod)
        Mod.apk_files_from_zip(zipfile, mod)
        Mod.compilation_targets_from_zip(zipfile, mod)

        mod.smali = tbcml.SmaliSet.from_zip(zipfile)
        mod.patches = tbcml.LibPatches.from_zip(zipfile)

        return mod

    @staticmethod
    def compilation_targets_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for i in range(
            len(Mod.get_files_in_mod_path(zipfile, ModPath.COMPILATION_TARGETS))
        ):
            target = tbcml.CompilationTarget.from_zip(i, zipfile)
            if target is None:
                continue
            mod.add_compilation_target(target)

    @staticmethod
    def get_files_in_mod_path(zipfile: "tbcml.Zip", path_type: ModPath):
        return zipfile.get_paths_in_folder(tbcml.Path(path_type.value))

    @staticmethod
    def apk_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.APK_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                key = path.remove_prefix(ModPath.APK_FILES.value)
                mod.apk_files[key] = data

    @staticmethod
    def game_files_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.GAME_FILES):
            data = zipfile.get_file(path)
            if data is not None:
                mod.game_files[path.basename()] = data

    @staticmethod
    def scripts_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.SCRIPTS):
            script = tbcml.FridaScript.from_json(path.read().to_str())
            mod.add_script(script)

    @staticmethod
    def modifications_from_zip(zipfile: "tbcml.Zip", mod: "Mod"):
        for path in Mod.get_files_in_mod_path(zipfile, ModPath.MODIFICATIONS):
            if not path.get_extension() == "json":
                continue
            modification_type = path.parent().basename()
            dt = zipfile.get_file(path)
            if dt is None:
                continue
            modifiction = Mod.modification_from_json((modification_type, dt.to_str()))
            mod.add_modification(modifiction)

    def save(self, path: "tbcml.PathStr"):
        path = tbcml.Path(path)
        self.to_zip().to_file(path)

    def add_modification(self, modification: "Modification"):
        if not isinstance(modification, Modification):  # type: ignore
            raise ValueError("modification does not inherit Modification!")
        self.modifications.append(modification)

    def add_script(self, script: "tbcml.FridaScript"):
        self.scripts.append(script)

    def add_smali(self, smali: "tbcml.Smali"):
        self.smali.add(smali)

    def add_smali_set(self, smali_set: "tbcml.SmaliSet"):
        for smali in smali_set.get_list():
            self.add_smali(smali)

    def get_scripts_str(self, apk: "tbcml.Apk") -> tuple[dict[str, str], bool]:
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

    def apply_modifications(self, game_packs: "tbcml.GamePacks"):
        for modification in self.modifications:
            modification.apply(game_packs)

    def compile_modifications(
        self,
        game_packs: "tbcml.GamePacks",
        existing_target: Optional["tbcml.CompilationTarget"] = None,
        clear_modifications: bool = True,
        add_target: bool = True,
    ):
        game_packs.clear_log()
        game_packs.set_log_enabled(True)

        self.apply_modifications(game_packs)

        if existing_target is None:
            existing_target = tbcml.CompilationTarget(
                game_packs.country_code.get_code(), game_packs.gv.to_string(), {}
            )

        for file, data in game_packs.log.items():
            existing_target.set_file(file, data)

        game_packs.set_log_enabled(False)
        game_packs.clear_log()

        if clear_modifications:
            self.modifications.clear()

        if add_target:
            self.add_compilation_target(existing_target)

        return existing_target

    def apply_game_files(self, game_packs: "tbcml.GamePacks"):
        for file, data in self.game_files.items():
            game_packs.set_file(file, data)

    def apply_compilations(self, game_packs: "tbcml.GamePacks"):
        for target in self.compilation_targets:
            if not target.check_game_data(game_packs):
                continue
            for file, data in target.files.items():
                game_packs.set_file(file, data)

    def apply_apk_files(self, apk: "tbcml.Apk"):
        for file, data in self.apk_files.items():
            path = apk.extracted_path.add(file)
            path.parent().generate_dirs()
            path.write(data)

    def apply_to_game_data(self, game_packs: "tbcml.GamePacks"):
        self.apply_game_files(game_packs)
        self.apply_compilations(game_packs)
        self.apply_modifications(game_packs)

    def apply_to_apk(self, apk: "tbcml.Apk"):
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
            tbcml.Path.get_asset_file_path(tbcml.Path("html").add("base_mod.html"))
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
