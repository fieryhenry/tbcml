from typing import Any, Optional
from bcml.core.game_data import pack
from bcml.core import io


class Reward:
    def __init__(self, reward_id: int, reward_amout: int):
        self.reward_id = reward_id
        self.reward_amout = reward_amout

    def serialize(self) -> dict[str, Any]:
        return {
            "reward_id": self.reward_id,
            "reward_amout": self.reward_amout,
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "Reward":
        return Reward(
            data["reward_id"],
            data["reward_amout"],
        )

    def __str__(self) -> str:
        return f"Reward {self.reward_id} x{self.reward_amout}"

    def __repr__(self) -> str:
        return f"Reward({self.reward_id}, {self.reward_amout})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Reward):
            return False
        return (
            self.reward_id == other.reward_id
            and self.reward_amout == other.reward_amout
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class RewardSet:
    def __init__(
        self, index: int, reward_threshold: int, rewards: list[Reward], text: str
    ):
        self.index = index
        self.reward_threshold = reward_threshold
        self.rewards = rewards
        self.text = text

    def serialize(self) -> dict[str, Any]:
        return {
            "reward_threshold": self.reward_threshold,
            "rewards": [v.serialize() for v in self.rewards],
            "text": self.text,
        }

    @staticmethod
    def deserialize(data: dict[str, Any], index: int) -> "RewardSet":
        return RewardSet(
            index,
            data["reward_threshold"],
            [Reward.deserialize(v) for v in data["rewards"]],
            data["text"],
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RewardSet):
            return False
        return (
            self.index == other.index
            and self.reward_threshold == other.reward_threshold
            and self.rewards == other.rewards
            and self.text == other.text
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class UserRankReward:
    def __init__(self, reward_sets: dict[int, RewardSet]):
        self.reward_sets = reward_sets

    def serialize(self) -> dict[str, Any]:
        return {
            "reward_sets": {str(k): v.serialize() for k, v in self.reward_sets.items()},
        }

    @staticmethod
    def deserialize(data: dict[str, Any]) -> "UserRankReward":
        return UserRankReward(
            {
                int(k): RewardSet.deserialize(v, int(k))
                for k, v in data["reward_sets"].items()
            },
        )

    @staticmethod
    def get_file_name() -> str:
        return "rankGift.csv"

    @staticmethod
    def get_file_name_text() -> str:
        return "rankGiftMessage.tsv"

    @staticmethod
    def from_game_data(game_data: "pack.GamePacks") -> "UserRankReward":
        csv_data = game_data.find_file(UserRankReward.get_file_name())

        if csv_data is None:
            return UserRankReward.create_empty()

        name_text_data = game_data.find_file(UserRankReward.get_file_name_text())
        if name_text_data is None:
            return UserRankReward.create_empty()

        tsv = io.bc_csv.CSV(name_text_data.dec_data, delimeter="\t")

        reward_sets: dict[int, RewardSet] = {}
        csv = io.bc_csv.CSV(csv_data.dec_data)
        for i, line in enumerate(csv):
            reward_threshold = line[0].to_int()
            try:
                text = tsv.lines[i][0].to_str()
            except IndexError:
                text = ""
            rewards: list[Reward] = []
            for i in range(1, len(line), 2):
                reward_id = line[i].to_int()
                if reward_id == -1:
                    break
                reward_amout = line[i + 1].to_int()
                rewards.append(Reward(reward_id, reward_amout))
            reward_sets[i] = RewardSet(i, reward_threshold, rewards, text)

        return UserRankReward(reward_sets)

    def to_game_data(self, game_data: "pack.GamePacks") -> None:
        csv_data = game_data.find_file(UserRankReward.get_file_name())
        if csv_data is None:
            return

        name_text_data = game_data.find_file(UserRankReward.get_file_name_text())
        if name_text_data is None:
            return

        tsv = io.bc_csv.CSV(name_text_data.dec_data, delimeter="\t")

        csv = io.bc_csv.CSV(csv_data.dec_data)
        remaining_rewards = self.reward_sets.copy()
        for i, line in enumerate(csv):
            reward_threshold = line[0].to_int()
            try:
                rewards = self.reward_sets[i].rewards
            except KeyError:
                continue
            line_n: list[int] = []
            line_n.append(reward_threshold)
            for j, reward in enumerate(rewards):
                line_n.append(reward.reward_id)
                line_n.append(reward.reward_amout)
                if j == len(rewards) - 1:
                    line_n.append(-1)

            csv.set_line(i, line_n)
            del remaining_rewards[i]

            tsv_line_n = [self.reward_sets[i].text]
            tsv.set_line(i, tsv_line_n)

        for reward_set in remaining_rewards.values():
            line_i: list[int] = [reward_set.reward_threshold]
            for reward in reward_set.rewards:
                line_i.append(reward.reward_id)
                line_i.append(reward.reward_amout)
            line_i.append(-1)
            csv.add_line(line_i)

            tsv_line_i = [reward_set.text]
            tsv.add_line(tsv_line_i)

        game_data.set_file(UserRankReward.get_file_name(), csv.to_data())
        game_data.set_file(UserRankReward.get_file_name_text(), tsv.to_data())

    @staticmethod
    def get_json_file_path() -> "io.path.Path":
        return io.path.Path("catbase").add("user_rank_reward.json")

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        json = io.json_file.JsonFile.from_object(self.serialize())
        zip_file.add_file(UserRankReward.get_json_file_path(), json.to_data())

    @staticmethod
    def from_zip(zip: "io.zip.Zip") -> "UserRankReward":
        json_data = zip.get_file(UserRankReward.get_json_file_path())
        if json_data is None:
            return UserRankReward.create_empty()
        json = io.json_file.JsonFile.from_data(json_data)
        return UserRankReward.deserialize(json.get_json())

    @staticmethod
    def create_empty() -> "UserRankReward":
        return UserRankReward({})

    def get_reward(self, index: int) -> Optional[RewardSet]:
        return self.reward_sets.get(index)

    def set_reward(self, index: int, reward: RewardSet) -> None:
        reward.index = index
        self.reward_sets[index] = reward

    def import_user_rank_rewards(
        self, other: "UserRankReward", game_data: "pack.GamePacks"
    ) -> None:
        """_summary_

        Args:
            other (UserRankReward): _description_
            game_data (pack.GamePacks): The game data to check if the imported data is different from the game data. This is used to prevent overwriting the current data with base game data.
        """
        gd_rewards = self.from_game_data(game_data)
        all_keys = set(gd_rewards.reward_sets.keys())
        all_keys.update(other.reward_sets.keys())
        all_keys.update(self.reward_sets.keys())

        for id in all_keys:
            gd_reward = gd_rewards.get_reward(id)
            other_reward = other.get_reward(id)
            if other_reward is None:
                continue
            if gd_reward is not None:
                if gd_reward != other_reward:
                    self.set_reward(id, other_reward)
            else:
                self.set_reward(id, other_reward)
