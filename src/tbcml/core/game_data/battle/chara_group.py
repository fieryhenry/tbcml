import enum
from tbcml.core.game_data import pack
from tbcml.core import io


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
            id = int(line[0])
            text_id = line[1]
            group_type = GroupType(int(line[2]))
            chara_ids = [int(line[i]) for i in range(3, len(line))]
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
            id = int(line[0])
            try:
                group = self.groups[id]
            except KeyError:
                continue
            line[1] = str(group.text_id)
            line[2] = str(group.group_type.value)
            for j, chara_id in enumerate(group.chara_ids):
                line[j + 3] = str(chara_id)
            csv.lines[i + 1] = line
            remaining_groups.remove(id)

        for id in remaining_groups:
            group = self.groups[id]
            a_line = [
                str(id),
                str(group.text_id),
                str(group.group_type.value),
            ]
            for chara_id in group.chara_ids:
                a_line.append(str(chara_id))
            csv.lines.append(a_line)

        game_data.set_file(file_name, csv.to_data())

    @staticmethod
    def create_empty() -> "CharaGroups":
        """Creates an empty CharaGroups.

        Returns:
            CharaGroups: The empty CharaGroups.
        """
        return CharaGroups({})
