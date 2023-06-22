import qtawesome as qta
from PyQt5.QtGui import QIcon


def get_icon(icon_name: str) -> QIcon:
    return qta.icon(f"fa5s.{icon_name}", color="white")  # type: ignore
