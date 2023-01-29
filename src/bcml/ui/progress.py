from typing import Optional
from PyQt5 import QtWidgets
from bcml.core import io


class ProgressBar(QtWidgets.QWidget):
    def __init__(self, title: str, parent: Optional[QtWidgets.QWidget] = None):
        super(ProgressBar, self).__init__(parent)
        self.title = title
        self.setup_ui()

    def setup_ui(self):
        self.setObjectName("ProgressBar")
        self.resize(400, 100)

        self.vertical_layout = QtWidgets.QVBoxLayout(self)
        self.vertical_layout.setObjectName("vertical_layout")

        self.title_label = QtWidgets.QLabel(self)
        self.title_label.setObjectName("title_label")
        self.title_label.setText(self.title)
        self.vertical_layout.addWidget(self.title_label)

        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setProperty("value", 0)
        self.progress_bar.setObjectName("progress_bar")
        self.progress_bar.setTextVisible(False)
        self.vertical_layout.addWidget(self.progress_bar)

        self.progress_label = QtWidgets.QLabel(self)
        self.progress_label.setObjectName("progress_label")
        self.vertical_layout.addWidget(self.progress_label)

    def set_progress(self, current: int, total: int):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"{current}/{total}")

    def set_progress_full(
        self, progress: float, current: int, total: int, is_file_size: bool = False
    ):
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(int(progress * 100))
        if is_file_size:
            current_str = io.file_handler.FileSize(current).format()
            total_str = io.file_handler.FileSize(total).format()
        else:
            current_str = str(current)
            total_str = str(total)
        self.progress_label.setText(f"{current_str}/{total_str}")
