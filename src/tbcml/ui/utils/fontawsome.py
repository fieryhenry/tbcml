try:
    import qtawesome as qta
except ImportError:
    qta = None
from PyQt5.QtGui import QIcon


def get_icon(icon_name: str) -> QIcon:
    if qta is None:
        print("Please pip install tbcml[ui] to use this feature")
        return QIcon()

    return qta.icon(f"fa5s.{icon_name}", color="white")  # type: ignore
