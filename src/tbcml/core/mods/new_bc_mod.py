import enum
from typing import Any, Optional, Sequence, TypeVar, Union
from tbcml import core
import json
from dataclasses import fields


class ModificationType(enum.Enum):
    CAT = "cat"


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

    @staticmethod
    def read_csv_fields(
        obj: Any,
        csv: "core.CSV",
    ):
        if not hasattr(obj, "__dataclass_fields__"):
            raise ValueError("obj is not a dataclass!")

        for field in fields(obj):
            name = field.name
            value = getattr(obj, name)
            if isinstance(value, core.CSVField):
                value.read_from_csv(csv)

    def pre_to_json(self) -> None:
        raise NotImplementedError


class NewMod:
    def __init__(
        self,
        name: str = "",
        author: str = "",
        description: str = "",
    ):
        self.name = name
        self.author = author
        self.description = description
        self.modifications: list[Modification] = []

    def metadata_to_json(self) -> str:
        data = {
            "name": self.name,
            "author": self.author,
            "description": self.description,
        }
        return json.dumps(data)

    @staticmethod
    def metadata_from_json(data: str):
        obj = json.loads(data)
        name = obj.get("name", "")
        author = obj.get("author", "")
        description = obj.get("description", "")
        return NewMod(
            name=name,
            author=author,
            description=description,
        )

    def to_zip(self) -> "core.Data":
        zipfile = core.Zip()
        metadata_json = self.metadata_to_json()
        metadata_file_name = core.Path("metadata.json")
        zipfile.add_file(metadata_file_name, core.Data(metadata_json))

        for i, modification in enumerate(self.modifications):
            filepath = (
                core.Path("modifications")
                .add(modification.modification_type.value)
                .add(f"{i}.json")
            )
            json_data = modification.to_json()
            zipfile.add_file(filepath, core.Data(json_data))

        return zipfile.to_data()

    @staticmethod
    def from_zip(data: "core.Data") -> "NewMod":
        zipfile = core.Zip(data)
        metadata_file_name = core.Path("metadata.json")
        metadata_json = zipfile.get_file(metadata_file_name)
        if metadata_json is None:
            return NewMod()
        mod = NewMod.metadata_from_json(metadata_json.to_str())

        for path in zipfile.get_paths_in_folder(core.Path("modifications")):
            if not path.get_extension() == "json":
                continue
            modification_type = path.parent().basename()
            dt = zipfile.get_file(path)
            if dt is None:
                continue
            modifiction = NewMod.modification_from_json(
                (modification_type, dt.to_str())
            )
            mod.add_modification(modifiction)

        return mod

    def save(self, path: "core.Path"):
        self.to_zip().to_file(path)

    def add_modification(self, modification: "Modification"):
        self.modifications.append(modification)

    def apply_modifications(self, game_packs: "core.GamePacks"):
        for modification in self.modifications:
            modification.apply(game_packs)

    def modifications_to_json(self) -> list[tuple[str, str]]:
        data: list[tuple[str, str]] = []
        for modification in self.modifications:
            data.append((modification.modification_type.value, modification.to_json()))
        return data

    @staticmethod
    def modifications_from_json(data: list[tuple[str, str]]):
        modifications: list[Modification] = []
        for dt in data:
            modifications.append(NewMod.modification_from_json(dt))

    @staticmethod
    def modification_from_json(data: tuple[str, str]):
        mod_type, modification_dt = data
        cls = None

        if mod_type == ModificationType.CAT.value:
            cls = core.CustomCat

        if cls is None:
            raise ValueError("Invalid Modification")

        return Modification.from_json(cls, modification_dt)
