from typing import Any, Callable
from PyQt5 import QtWidgets


class Dialog:
    def __init__(self):
        pass

    @staticmethod
    def error_dialog(message: str):
        dialog = QtWidgets.QMessageBox()
        dialog.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        dialog.setText(message)
        dialog.setWindowTitle("Error")
        dialog.exec_()

    @staticmethod
    def yes_no_box(
        icon: QtWidgets.QMessageBox.Icon,
        text: str,
        informative_text: str,
        window_title: str,
        default_button: QtWidgets.QMessageBox.StandardButton,
        on_yes: Callable[..., Any] = lambda: None,
        on_no: Callable[..., Any] = lambda: None,
    ):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(icon)
        msg.setText(text)
        msg.setInformativeText(informative_text)
        msg.setWindowTitle(window_title)
        msg.setStandardButtons(
            QtWidgets.QMessageBox.StandardButton.Yes  # type: ignore
            | QtWidgets.QMessageBox.StandardButton.No
        )
        msg.setDefaultButton(default_button)
        msg.buttonClicked.connect(  # type: ignore
            lambda button: on_yes() if "Yes" in button.text() else on_no()  # type: ignore
        )
        msg.exec_()
