import enum


class Languages(enum.Enum):
    DE = "de"
    FR = "fr"
    IT = "it"
    ES = "es"
    TH = "th"

    @staticmethod
    def get_all() -> list["Languages"]:
        return list(Languages)

    @staticmethod
    def get_all_strings() -> list[str]:
        return [lang.value for lang in Languages.get_all()]
