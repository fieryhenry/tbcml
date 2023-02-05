import enum
from typing import Any
from bcml.core.game_data import pack
from bcml.core import io


class GroupType(enum.Enum):
    """The type of restriction that the group imposes on the lineup."""

    EXCLUDE = 0
    """The group cannot be in the lineup."""
    INCLUDE = 2
    """Only units in the group can be in the lineup."""


class CharaGroupSet:
    def __init__(
        self,
        group_id: int,
        text_id: str,
        group_type: GroupType,
        chara_ids: list[int],
    ):
        """Initializes a new CharaGroupSet.

        Args:
            group_id (int): The ID of the group.
            text_id (str): The text ID of the group. This is used to display the restriction message in the game. Found in resLocal/localizable.tsv.
            group_type (GroupType): The type of restriction that the group imposes on the lineup.
            chara_ids (list[int]): The IDs of the units in the group.
        """
        self.group_id = group_id
        self.text_id = text_id
        self.group_type = group_type
        self.chara_ids = chara_ids

    def serialize(self) -> dict[str, Any]:
        """Serializes the CharaGroupSet to a dictionary.

        Returns:
            dict[str, Any]: The serialized CharaGroupSet.
        """
        return {
            "group_id": self.group_id,
            "text_id": self.text_id,
            "group_type": self.group_type.value,
            "chara_ids": self.chara_ids,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CharaGroupSet":
        """Deserializes a CharaGroupSet from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize.

        Returns:
            CharaGroupSet: The deserialized CharaGroupSet.
        """
        return CharaGroupSet(
            data["group_id"],
            data["text_id"],
            GroupType(data["group_type"]),
            data["chara_ids"],
        )


class CharaGroups:
    def __init__(self, groups: dict[int, CharaGroupSet]):
        """Initializes a new CharaGroups.

        Args:
            groups (dict[int, CharaGroupSet]): The groups in the CharaGroups.
        """
        self.groups = groups

    @staticmethod
    def get_file_name() -> str:
        """Gets the name of the file that the CharaGroups are stored in.

        Returns:
            str: The name of the file that the CharaGroups are stored in.
        """
        return "Charagroup.csv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "CharaGroups":
        """Loads the CharaGroups from the game data.

        Returns:
            CharaGroups: The CharaGroups loaded from the game data.
        """
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return CharaGroups.create_empty()
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
        """Writes the CharaGroups to the game data.

        Args:
            game_data (pack.GamePacks): The game data to write to.
        """
        file_name = CharaGroups.get_file_name()
        file = game_data.find_file(file_name)
        if file is None:
            return
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
            a_line = [id, group.text_id, group.group_type.value]
            for chara_id in group.chara_ids:
                a_line.append(chara_id)
            csv.add_line(a_line)

        game_data.set_file(file_name, csv.to_data())

    def serialize(self) -> dict[str, Any]:
        """Serializes the CharaGroups to a dictionary.

        Returns:
            dict[str, Any]: The serialized CharaGroups.
        """
        return {
            "groups": {str(k): v.serialize() for k, v in self.groups.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "CharaGroups":
        """Deserializes a CharaGroups from a dictionary.

        Args:
            data (dict[str, Any]): The dictionary to deserialize.

        Returns:
            CharaGroups: The deserialized CharaGroups.
        """
        return CharaGroups(
            {int(k): CharaGroupSet.deserialize(v) for k, v in data["groups"].items()}
        )

    @staticmethod
    def get_zip_json_file_path() -> "io.path.Path":
        """Gets the path to the CharaGroups in the mod zip file.

        Returns:
            io.path.Path: The path to the CharaGroups in the mod zip file.
        """
        return io.path.Path("battle").add("chara_group.json")

    def add_to_zip(self, zip: "io.zip.Zip"):
        """Adds the CharaGroups to a mod zip file.

        Args:
            zip (io.zip.Zip): The mod zip file to add the CharaGroups to.
        """
        json = io.json_file.JsonFile.from_json(self.serialize())
        zip.add_file(self.get_zip_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "CharaGroups":
        """Loads the CharaGroups from a mod zip file.

        Args:
            zip (io.zip.Zip): The mod zip file to load the CharaGroups from.

        Returns:
            CharaGroups: The CharaGroups, or None if the file could not be found.
        """
        file = zip.get_file(CharaGroups.get_zip_json_file_path())
        if file is None:
            return CharaGroups.create_empty()

        json = io.json_file.JsonFile.from_data(file)
        return CharaGroups.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "CharaGroups":
        """Creates an empty CharaGroups.

        Returns:
            CharaGroups: The empty CharaGroups.
        """
        return CharaGroups({})

    def import_chara_groups(self, other: "CharaGroups"):
        """Imports the CharaGroups from another CharaGroups object.

        Args:
            other (CharaGroups): The CharaGroups to import from.
        """
        self.groups.update(other.groups)
