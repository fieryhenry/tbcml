from typing import Optional

from PyQt5 import QtWidgets


class FileDialog(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)

    def select_file(
        self,
        title: str,
        directory: str,
        filter: str,
        options: Optional[QtWidgets.QFileDialog.Options] = None,
    ) -> str:
        if options is None:
            options = QtWidgets.QFileDialog.Options()
        return QtWidgets.QFileDialog.getOpenFileName(
            self, title, directory, filter, options=options
        )[0]

    def select_files(
        self,
        title: str,
        directory: str,
        filter: str,
        options: Optional[QtWidgets.QFileDialog.Options] = None,
    ) -> list[str]:
        if options is None:
            options = QtWidgets.QFileDialog.Options()

        return QtWidgets.QFileDialog.getOpenFileNames(
            self, title, directory, filter, options=options
        )[0]

    def select_directory(
        self, title: str, directory: str, options: QtWidgets.QFileDialog.Options
    ) -> str:
        return QtWidgets.QFileDialog.getExistingDirectory(
            self, title, directory, options=options
        )

    def select_save_file(
        self,
        title: str,
        directory: str,
        filter: str,
        options: Optional[QtWidgets.QFileDialog.Options],
    ) -> str:
        if options is None:
            options = QtWidgets.QFileDialog.Options()
        return QtWidgets.QFileDialog.getSaveFileName(
            self, title, directory, filter, options=options
        )[0]
