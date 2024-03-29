"""Contains the Languages enum."""

import enum
from typing import Literal, Union

LanguageStr = Union[
    "Language",
    Literal["fr"],
    Literal["it"],
    Literal["de"],
    Literal["es"],
    Literal["th"],
]


class Language(enum.Enum):
    """Enum for all supported languages in the en version of the game."""

    FR = "fr"
    IT = "it"
    DE = "de"
    ES = "es"
    TH = "th"

    @staticmethod
    def get_all() -> list["Language"]:
        """Gets all languages.

        Returns:
            list[Languages]: All languages.
        """
        return list(Language)

    @staticmethod
    def get_all_strings() -> list[str]:
        """Gets all languages as strings.

        Returns:
            list[str]: All languages as strings.
        """
        return [lang.value for lang in Language.get_all()]

    def get_index(self):
        # im not confident on these numbers, but it's the order in which the filenames are allocated in the binary
        if self == Language.FR:
            return 0
        if self == Language.IT:
            return 1
        if self == Language.DE:
            return 2
        if self == Language.ES:
            return 3
        if self == Language.TH:
            return 4

        raise ValueError("Invalid Language")

    @staticmethod
    def from_langstr(lang: LanguageStr) -> "Language":
        if isinstance(lang, Language):
            return lang
        return Language(lang)
