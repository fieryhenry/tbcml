from typing import Any, Callable, Optional

from PyQt5 import QtWidgets

from tbcml.core import locale_handler


class Dialog:
    def __init__(self):
        self.locale_manager = locale_handler.LocalManager.from_config()

    def error_dialog(
        self,
        message: str,
        informative_text: str,
        title: Optional[str] = None,
    ):
        if title is None:
            title = self.locale_manager.search_key("error")
        dialog = QtWidgets.QMessageBox()
        dialog.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        dialog.setText(message)
        dialog.setInformativeText(informative_text)
        dialog.setWindowTitle(title)

        dialog.exec_()

    def yes_no_box(
        self,
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

        def on_button_clicked(button: QtWidgets.QPushButton):
            if button == msg.button(QtWidgets.QMessageBox.StandardButton.Yes):
                on_yes()
            elif button == msg.button(QtWidgets.QMessageBox.StandardButton.No):
                on_no()

        msg.buttonClicked.connect(on_button_clicked)  # type: ignore

        msg.exec_()

    def three_button_box(
        self,
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

        def on_button_click(button: QtWidgets.QPushButton):
            if button == msg.button(QtWidgets.QMessageBox.StandardButton.Yes):
                on_yes()
            elif button == msg.button(QtWidgets.QMessageBox.StandardButton.No):
                on_no()
            elif button == msg.button(QtWidgets.QMessageBox.StandardButton.Cancel):
                on_cancel()

        msg.buttonClicked.connect(on_button_click)  # type: ignore
        msg.exec_()

    def save_changes_dialog(
        self,
        on_yes: Callable[..., Any] = lambda: None,
        on_no: Callable[..., Any] = lambda: None,
        on_cancel: Callable[..., Any] = lambda: None,
    ):
        self.three_button_box(
            QtWidgets.QMessageBox.Icon.Warning,
            self.locale_manager.search_key("save_changes_q"),
            self.locale_manager.search_key("save_changes_info"),
            self.locale_manager.search_key("save_changes_q"),
            QtWidgets.QMessageBox.StandardButton.Yes,
            on_yes,
            on_no,
            on_cancel,
        )
