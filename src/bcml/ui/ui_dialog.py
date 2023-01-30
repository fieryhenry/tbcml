from typing import Any, Callable
from PyQt5 import QtWidgets


class Dialog:
    def __init__(self):
        pass

    @staticmethod
    def error_dialog(
        message: str,
        informative_text: str = "",
        title: str = "Error",
    ):
        dialog = QtWidgets.QMessageBox()
        dialog.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        dialog.setText(message)
        dialog.setInformativeText(informative_text)
        dialog.setWindowTitle(title)

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

    @staticmethod
    def three_button_box(
        icon: QtWidgets.QMessageBox.Icon,
        text: str,
        informative_text: str,
        window_title: str,
        default_button: QtWidgets.QMessageBox.StandardButton,
        on_yes: Callable[..., Any] = lambda: None,
        on_no: Callable[..., Any] = lambda: None,
        on_cancel: Callable[..., Any] = lambda: None,
    ):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(icon)
        msg.setText(text)
        msg.setInformativeText(informative_text)
        msg.setWindowTitle(window_title)
        msg.setStandardButtons(
            QtWidgets.QMessageBox.StandardButton.Yes  # type: ignore
            | QtWidgets.QMessageBox.StandardButton.No
            | QtWidgets.QMessageBox.StandardButton.Cancel
        )
        msg.setDefaultButton(default_button)
        msg.buttonClicked.connect(  # type: ignore
            lambda button: on_yes() if "Yes" in button.text() else on_no() if "No" in button.text() else on_cancel()  # type: ignore
        )
        msg.exec_()

    @staticmethod
    def info_dialog(message: str):
        dialog = QtWidgets.QMessageBox()
        dialog.setIcon(QtWidgets.QMessageBox.Icon.Information)
        dialog.setText(message)
        dialog.setWindowTitle("Info")
        dialog.exec_()

    @staticmethod
    def save_changes_dialog(
        on_yes: Callable[..., Any] = lambda: None,
        on_no: Callable[..., Any] = lambda: None,
        on_cancel: Callable[..., Any] = lambda: None,
    ):
        Dialog.three_button_box(
            QtWidgets.QMessageBox.Icon.Warning,
            "Save changes?",
            "You have unsaved changes. Do you want to save them?",
            "Save changes?",
            QtWidgets.QMessageBox.StandardButton.Yes,
            on_yes,
            on_no,
            on_cancel,
        )
