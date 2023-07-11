from typing import Any, Optional
from tbcml import core


class Reward:
    def __init__(self, reward_id: int, reward_amout: int):
        self.reward_id = reward_id
        self.reward_amout = reward_amout

    def apply_dict(self, dict_data: dict[str, Any]):
        self.reward_id = dict_data.get("reward_id", self.reward_id)
        self.reward_amout = dict_data.get("reward_amout", self.reward_amout)

    @staticmethod
    def create_empty() -> "Reward":
        return Reward(0, 0)


class RewardSet:
    def __init__(
        self, index: int, reward_threshold: int, rewards: list[Reward], text: str
    ):
        self.index = index
        self.reward_threshold = reward_threshold
        self.rewards = rewards
        self.text = text

    def apply_dict(self, dict_data: dict[str, Any]):
        self.index = dict_data.get("index", self.index)
        self.reward_threshold = dict_data.get("reward_threshold", self.reward_threshold)
        rewards = dict_data.get("rewards")
        if rewards is not None:
            current_rewards = {i: reward for i, reward in enumerate(self.rewards)}
            modded_rewards = core.ModEditDictHandler(rewards, current_rewards).get_dict(
                convert_int=True
            )
            for reward_id, modded_reward in modded_rewards.items():
                reward = current_rewards.get(reward_id)
                if reward is None:
                    reward = Reward.create_empty()
                    self.rewards.append(reward)
                reward.apply_dict(modded_reward)
        self.text = dict_data.get("text", self.text)

    @staticmethod
    def create_empty(id: int) -> "RewardSet":
        return RewardSet(id, 0, [], "")


class UserRankReward(core.EditableClass):
    def __init__(self, reward_sets: dict[int, RewardSet]):
        self.data = reward_sets
        super().__init__(self.data)

    @staticmethod
    def get_file_name() -> str:
        return "rankGift.csv"

    @staticmethod
    def get_file_name_text() -> str:
        return "rankGiftMessage.tsv"

    @staticmethod
    def from_game_data(game_data: "core.GamePacks") -> "UserRankReward":
        if game_data.user_rank_reward is not None:
            return game_data.user_rank_reward
        csv_data = game_data.find_file(UserRankReward.get_file_name())

        if csv_data is None:
            return UserRankReward.create_empty()

        name_text_data = game_data.find_file(UserRankReward.get_file_name_text())
        if name_text_data is None:
            return UserRankReward.create_empty()

        tsv = core.CSV(name_text_data.dec_data, delimeter="\t")

        reward_sets: dict[int, RewardSet] = {}
        csv = core.CSV(csv_data.dec_data)
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

        urr = UserRankReward(reward_sets)
        game_data.user_rank_reward = urr
        return urr

    def to_game_data(self, game_data: "core.GamePacks") -> None:
        csv_data = game_data.find_file(UserRankReward.get_file_name())
        if csv_data is None:
            return

        name_text_data = game_data.find_file(UserRankReward.get_file_name_text())
        if name_text_data is None:
            return

        tsv = core.CSV(name_text_data.dec_data, delimeter="\t")

        csv = core.CSV(csv_data.dec_data)
        remaining_rewards = self.data.copy()
        for i, line in enumerate(csv):
            reward_threshold = int(line[0])
            try:
                rewards = self.data[i].rewards
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

            tsv_line_n = [self.data[i].text]
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
        return self.data.get(index)

    def set_reward(self, index: int, reward: RewardSet) -> None:
        reward.index = index
        self.data[index] = reward
