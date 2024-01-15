"""Contains the Languages enum."""
import enum


class Languages(enum.Enum):
    """Enum for all supported languages in the en version of the game."""

    DE = "de"
    FR = "fr"
    IT = "it"
    ES = "es"
    TH = "th"

    @staticmethod
    def get_all() -> list["Languages"]:
        """Gets all languages.

        Returns:
            list[Languages]: All languages.
        """
        return list(Languages)

    @staticmethod
    def get_all_strings() -> list[str]:
        """Gets all languages as strings.

        Returns:
            list[str]: All languages as strings.
        """
        return [lang.value for lang in Languages.get_all()]
