from typing import Optional
from tbcml.core.game_data import pack
from tbcml.core import io


class Reward:
    def __init__(self, reward_id: int, reward_amout: int):
        self.reward_id = reward_id
        self.reward_amout = reward_amout


class RewardSet:
    def __init__(
        self, index: int, reward_threshold: int, rewards: list[Reward], text: str
    ):
        self.index = index
        self.reward_threshold = reward_threshold
        self.rewards = rewards
        self.text = text


class UserRankReward:
    def __init__(self, reward_sets: dict[int, RewardSet]):
        self.reward_sets = reward_sets

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
            reward_threshold = int(line[0])
            try:
                text = tsv.lines[i][0]
            except IndexError:
                text = ""
            rewards: list[Reward] = []
            for i in range(1, len(line), 2):
                reward_id = int(line[i])
                if reward_id == -1:
                    break
                reward_amout = int(line[i + 1])
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
            reward_threshold = int(line[0])
            try:
                rewards = self.reward_sets[i].rewards
            except KeyError:
                continue
            line_n: list[str] = []
            line_n.append(str(reward_threshold))
            for j, reward in enumerate(rewards):
                line_n.append(str(reward.reward_id))
                line_n.append(str(reward.reward_amout))
                if j == len(rewards) - 1:
                    line_n.append(str(-1))

            csv.lines[i] = line_n
            del remaining_rewards[i]

            tsv_line_n = [self.reward_sets[i].text]
            tsv.lines[i] = tsv_line_n

        for reward_set in remaining_rewards.values():
            line_i: list[str] = [str(reward_set.reward_threshold)]
            for reward in reward_set.rewards:
                line_i.append(str(reward.reward_id))
                line_i.append(str(reward.reward_amout))
            line_i.append(str(-1))
            csv.lines.append(line_i)

            tsv_line_i = [reward_set.text]
            tsv.lines.append(tsv_line_i)

        game_data.set_file(UserRankReward.get_file_name(), csv.to_data())
        game_data.set_file(UserRankReward.get_file_name_text(), tsv.to_data())

    @staticmethod
    def create_empty() -> "UserRankReward":
        return UserRankReward({})

    def get_reward(self, index: int) -> Optional[RewardSet]:
        return self.reward_sets.get(index)

    def set_reward(self, index: int, reward: RewardSet) -> None:
        reward.index = index
        self.reward_sets[index] = reward
