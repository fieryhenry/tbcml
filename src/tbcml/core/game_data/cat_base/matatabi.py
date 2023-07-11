from typing import Any, Optional

from tbcml import core


class Matatabi:
    def __init__(
        self,
        index: int,
        gatya_id: int,
        seed: bool,
        group: int,
        sort: int,
        require: Optional[int] = None,
        text: Optional[str] = None,
        growup: Optional[list[int]] = None,
    ):
        self.index = index
        self.gatya_id = gatya_id
        self.seed = seed
        self.group = group
        self.sort = sort
        self.require = require
        self.text = text
        self.growup = growup

    def apply_dict(self, dict_data: dict[str, Any]):
        self.index = dict_data.get("index", self.index)
        self.gatya_id = dict_data.get("gatya_id", self.gatya_id)
        self.seed = dict_data.get("seed", self.seed)
        self.group = dict_data.get("group", self.group)
        self.sort = dict_data.get("sort", self.sort)
        self.require = dict_data.get("require", self.require)
        self.text = dict_data.get("text", self.text)
        self.growup = dict_data.get("growup", self.growup)

    @staticmethod
    def create_empty(id: int) -> "Matatabi":
        return Matatabi(
            index=id,
            gatya_id=-0,
            seed=False,
            group=0,
            sort=0,
        )


class MatatabiData(core.EditableClass):
    def __init__(self, matatabis: dict[int, Matatabi]):
        self.data = matatabis
        super().__init__(matatabis)

    @staticmethod
    def get_file_name() -> str:
        return "Matatabi.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks"):
        if game_data.matatabi is not None:
            return game_data.matatabi
        file = game_data.find_file(MatatabiData.get_file_name())
        if file is None:
            return MatatabiData.create_empty()

        csv = core.CSV(file.dec_data)

        matatabis: dict[int, Matatabi] = {}
        for i, line in enumerate(csv.lines[1:]):
            gatya_id = int(line[0])
            seed = bool(int(line[1]))
            group = int(line[2])
            sort = int(line[3])
            require = None
            text = None
            growup = None

            if len(line) > 4:
                require = int(line[4])
            if len(line) > 5:
                text = line[5]
            if len(line) > 6:
                growup = [int(item) for item in line[6:]]

            matatabis[i] = Matatabi(
                index=i,
                gatya_id=gatya_id,
                seed=seed,
                group=group,
                sort=sort,
                require=require,
                text=text,
                growup=growup,
            )

        mata_data = MatatabiData(matatabis)
        game_data.matatabi = mata_data
        return mata_data

    @staticmethod
    def create_empty() -> "MatatabiData":
        return MatatabiData(matatabis={})

    def to_game_data(self, game_data: "core.GamePacks"):
        file = game_data.find_file(MatatabiData.get_file_name())
        if file is None:
            return
        csv = core.CSV(file.dec_data)
        remaining_matatabis = self.data.copy()
        for i, line in enumerate(csv.lines[1:]):
            try:
                matatabi = self.data[i]
            except KeyError:
                continue
            del remaining_matatabis[i]
            line[0] = str(matatabi.gatya_id)
            line[1] = str(int(matatabi.seed))
            line[2] = str(matatabi.group)
            line[3] = str(matatabi.sort)
            if matatabi.require is not None:
                line[4] = str(matatabi.require)
            if matatabi.text is not None:
                line[5] = matatabi.text
            if matatabi.growup is not None:
                for j, item in enumerate(matatabi.growup):
                    line[6 + j] = str(item)
            csv.lines[i + 1] = line
        for i in remaining_matatabis:
            new_line: list[str] = [
                str(self.data[i].gatya_id),
                str(int(self.data[i].seed)),
                str(self.data[i].group),
                str(self.data[i].sort),
            ]
            if self.data[i].require is not None:
                new_line.append(str(self.data[i].require))
            text = self.data[i].text
            if text is not None:
                new_line.append(text)
            growup = self.data[i].growup
            if growup is not None:
                for item in growup:
                    new_line.append(str(item))
            csv.lines.append(new_line)

        game_data.set_file(MatatabiData.get_file_name(), csv.to_data())
