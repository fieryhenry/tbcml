from __future__ import annotations

try:
    import ffmpeg  # type: ignore
except ImportError:
    ffmpeg = None

import enum

from marshmallow_dataclass import dataclass

import tbcml


class AudioID(enum.Enum):
    OPENING = 0
    TITLE = 1
    CATBASE = 2
    BATTLE_1 = 3
    BATTLE_2 = 4
    ENDING = 5
    BATTLE_CHALLENGE = 6
    BATTLE_START = 7
    BATTLE_WIN = 8
    BATTLE_LOSE = 9
    BUTTON_HOVER = 10
    BUTTON_PRESS = 11
    UNUSED_1 = 12
    UNUSED_2 = 13
    ITEM_USE = 14
    BLOCKED_ACTION = 15
    CATSHRINE_DONATE_1 = 16
    CATSHRINE_DONATE_2 = 17
    UNUSED_3 = 18
    UNIT_DEPLOY = 19
    ATTACK_1 = 20
    ATTACK_2 = 21
    ATTACK_BASE = 22
    UNIT_KILL_1 = 23
    UNIT_KILL_2 = 24
    CANNON_PRE_ATTACK = 25
    WAVE_ATTACK = 26
    UNIT_RECHARGED = 27
    CANNON_RECHARGED = 28
    REWARD_OBTAINED = 29
    BATTLE_3 = 30
    BATTLE_4 = 31
    BATTLE_5 = 32
    BATTLE_6 = 33
    BATTLE_7 = 34
    CATGOD_WRATH = 35
    THUNDERBOLT_FIRE = 36
    THUNDERBOLT_ATTACK = 37
    CATGOD_BLESS_YOU = 38
    CATGOD_HEALING_OASIS = 39
    CATGOD_BABY_BOOM = 40
    CATSTAMP = 41
    NOTIFICATION = 42
    CAT_CAPSULE_OPEN = 43
    CRITICAL_HIT = 44
    BOSS_SHOCKWAVE = 45
    CATBASE_DOOR_OPEN_1 = 46
    BATTLE_8 = 47
    BATTLE_9 = 48
    SURVIVE_ABILITY = 50
    TRUE_FORM_UNLOCK = 51
    GAMATOTO_BGM = 52
    GAMATOTO_XP = 53
    GAMATOTO_LOG = 54
    GAMATOTO_ORGANIZE = 55
    CATBASE_DOOR_OPEN_COLLAB_1 = 56
    TRIAL_END = 57
    BATTLE_DOJO = 58
    ZOMBIE_KILLER = 59
    SLOW_BEAM_FIRE = 60
    IRON_WALL_FIRE = 61
    BATTLE_10 = 62
    CATBASE_DOOR_OPEN_2 = 63
    RANKING_RECIEVED = 64
    WATERBLAST_FIRE = 65
    BATTLE_11 = 66
    BATTLE_12 = 67
    BATTLE_13 = 68
    BATTLE_14 = 69
    BARRIER_BREAK_ABILITY = 70
    BARRIER_ATTACK = 71
    BARRIER_BREAK_PASSIVE = 72
    WARP_ENTER = 73
    WARP_EXIT = 74
    BATTLE_15 = 75
    BATTLE_16 = 76
    BATTLE_17 = 77
    BATTLE_18 = 78
    BATTLE_19 = 79
    BATTLE_20 = 80
    BATTLE_21 = 81
    BATTLE_22 = 82
    WATERBLAST_ATTACK = 83
    HOLY_BLAST_FIRE = 84
    HOLY_BLAST_ATTACK = 85
    BREAKERBLAST_ATTACK = 86
    BATTLE_23 = 87
    MENU_CC_1 = 88
    BATTLE_24 = 89
    SAVAGE_BLOW = 90
    MENU_CC_2 = 91
    CATBASE_DOOR_OPEN_COLLAB_2 = 92
    CATBASE_DOOR_OPEN_COLLAB_3 = 93
    CATBASE_DOOR_OPEN_COLLAB_4 = 94
    CATBASE_DOOR_OPEN_COLLAB_5 = 95
    CATBASE_DOOR_OPEN_COLLAB_6 = 96
    BATTLE_25 = 97
    BATTLE_26 = 98
    BATTLE_27 = 99
    BATTLE_28 = 100
    BATTLE_29 = 101
    BATTLE_30 = 102
    BATTLE_31 = 103
    BATTLE_32 = 104
    BATTLE_START_CC_1 = 105
    BATTLE_WIN_CC_1 = 106
    MEOW_MEDAL_UNLOCK = 107
    WILCAT_SLOTS_1 = 108
    WILCAT_SLOTS_2 = 109
    TOXIC = 110
    SURGE_START = 111
    SURGE_PROGRESS = 112
    CATBASE_MENU_CC_3 = 113
    CATBASE_DOOR_OPEN_COLLAB_7 = 114
    CATBASE_DOOR_OPEN_COLLAB_8 = 115
    REWARD_OBTAINED_CC_1 = 116
    BATTLE_33 = 117
    BATTLE_34 = 118
    BATTLE_35 = 119
    BATTLE_36 = 120
    CATBASE_MENU_CC_4 = 121
    BATTLE_37 = 122
    BATTLE_38 = 123
    CURSEBLAST_FIRE = 124
    BATTLE_39 = 125
    BATTLE_40 = 126
    BATTLE_41 = 127
    BATTLE_42 = 128
    BATTLE_43 = 129
    BATTLE_44 = 130
    BATTLE_45 = 131
    BATTLE_46 = 132
    BATTLE_47 = 133
    CATBASE_DOOR_OPEN_COLLAB_9 = 134
    CAT_SCRATCHER = 135
    SHIELD_ATTACK = 136
    SHIELD_PIERCE = 137
    SHIELD_REGEN = 138
    SHIELD_BREAK = 139
    BATTLE_48 = 140
    BATTLE_49 = 141
    BATTLE_50 = 142
    DEATH_SURGE = 143
    BATTLE_51 = 144
    BATTLE_52 = 145
    BATTLE_53 = 146
    BATTLE_54 = 147
    BATTLE_55 = 148
    BATTLE_56 = 149
    BATTLE_57 = 150
    BATTLE_58 = 151
    BATTLE_59 = 152
    BATTLE_60 = 153
    BATTLE_61 = 154
    BATTLE_62 = 155
    BATTLE_63 = 156
    BATTLE_64 = 157
    BATTLE_65 = 158
    COUNTER_SURGE = 159
    BATTLE_66 = 160
    BATTLE_67 = 161
    SPIRIT_SUMMON = 162
    BATTLE_68 = 163
    BATTLE_69 = 164
    BATTLE_70 = 165


@dataclass
class AudioFile:
    id: int
    is_bgm: bool
    data: tbcml.Data

    def get_sound_format(self):
        return AudioFile.get_sound_format_s(self.is_bgm)

    @staticmethod
    def get_sound_format_s(is_bgm: bool):
        if is_bgm:
            return "ogg"
        return "caf"

    @staticmethod
    def get_is_bgm(sound_format: str):
        if sound_format == "ogg":
            return True
        return False

    def caf_to_little_endian(self) -> AudioFile:
        """Converts a CAF audio file to little endian. Stuff like audacity saves CAF files as big endian and the game doesn't support that.

        Returns:
            AudioFile: The audio file.
        """
        extension = self.get_sound_format()
        if extension != "caf":
            return self
        if ffmpeg is None:
            print("ffmpeg not installed, skipping conversion")
            return self
        with tbcml.TempFile(extension=extension) as input_temp:
            input_temp.write(self.data)

            stream = ffmpeg.input(input_temp.path)  # type: ignore
            with tbcml.TempFile(extension=extension) as output_temp:
                stream = ffmpeg.output(  # type: ignore
                    stream, output_temp.path, acodec="pcm_s16le", loglevel="quiet"  # type: ignore
                )
                ffmpeg.run(stream)  # type: ignore

                self.data = output_temp.read()

        return self

    def get_apk_file_name(self) -> str:
        id_str = str(self.id).zfill(3)
        ext = self.get_sound_format()
        return f"snd{id_str}.{ext}"

    def get_ipa_file_name(self) -> str:
        id_str = str(self.id).zfill(3)
        ext = self.get_sound_format()
        return f"{id_str}.{ext}"
