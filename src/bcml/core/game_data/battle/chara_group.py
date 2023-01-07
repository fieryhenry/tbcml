import enum
from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class GroupType(enum.Enum):
    EXCLUDE = 0
    INCLUDE = 2


class CharaGroupSet:
    def __init__(
        self, group_id: int, text_id: str, group_type: GroupType, chara_ids: list[int]
    ):
        self.group_id = group_id
        self.text_id = text_id
        self.group_type = group_type
        self.chara_ids = chara_ids

    def serialize(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "text_id": self.text_id,
            "group_type": self.group_type.value,
            "chara_ids": self.chara_ids,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CharaGroupSet":
        return CharaGroupSet(
            data["group_id"],
            data["text_id"],
            GroupType(data["group_type"]),
            data["chara_ids"],
        )


class CharaGroups:
    def __init__(self, groups: dict[int, CharaGroupSet]):
        self.groups = groups

    @staticmethod
    def get_file_name() -> str:
        return "Charagroup.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CharaGroups":
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            raise FileNotFoundError(f"Could not find {file_name} in game data")
        csv = io.bc_csv.CSV(file.dec_data)
        groups: dict[int, CharaGroupSet] = {}
        for line in csv.lines[1:]:
            id = line[0].to_int()
            text_id = line[1].to_str()
            group_type = GroupType(line[2].to_int())
            chara_ids = [line[i].to_int() for i in range(3, len(line))]
            groups[id] = CharaGroupSet(id, text_id, group_type, chara_ids)
        return CharaGroups(groups)


    def to_game_data(self, game_data: "pack.GamePacks"):
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            raise FileNotFoundError(f"Could not find {file_name} in game data")
        csv = io.bc_csv.CSV(file.dec_data)
        remaining_groups = set(self.groups.keys())
        for i, line in enumerate(csv.lines[1:]):
            id = line[0].to_int()
            try:
                group = self.groups[id]
            except KeyError:
                continue
            line[1].set(group.text_id)
            line[2].set(group.group_type.value)
            for j, chara_id in enumerate(group.chara_ids):
                line[j + 3].set(chara_id)
            csv.set_line(i + 1, line)
            remaining_groups.remove(id)
        
        for id in remaining_groups:
            group = self.groups[id]
            line = [id, group.text_id, group.group_type.value]
            for chara_id in group.chara_ids:
                line.append(chara_id)
            csv.add_line(line)

        game_data.set_file(file_name, csv.to_data())

    def serialize(self) -> dict[str, Any]:
        return {
            "groups": {str(k): v.serialize() for k, v in self.groups.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CharaGroups":
        return CharaGroups(
            {int(k): CharaGroupSet.deserialize(v) for k, v in data["groups"].items()}
        )
    
    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        return io.path.Path("battle").add("chara_group.json")
    
    def add_to_zip(self, zip: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(self.get_zip_json_file_path(), json.to_data())
    
    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> Optional["CharaGroups"]:
        file = zip.get_file(CharaGroups.get_zip_json_file_path())
        if file is None:
            return None
        
        json = io.json_file.JsonFile.from_data(file)
        return CharaGroups.deserialize(json.get_json())
    
    @staticmethod
    def create_empty() -> "CharaGroups":
        return CharaGroups({})
    
    def import_chara_groups(self, other: "CharaGroups"):
        self.groups.update(other.groups)