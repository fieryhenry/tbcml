from typing import Callable, Optional
from PyQt5 import QtWidgets
from bcml.core import io


class ProgressBar(QtWidgets.QWidget):
    def __init__(
        self,
        title: str,
        on_progress: Optional[Callable[[int, int], None]] = None,
        parent: Optional[QtWidgets.QWidget] = None,
    ):
        super(ProgressBar, self).__init__(parent)
        self.title = title
        self.on_progress = on_progress
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
        if total < 0:
            total = 1
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        percent_str = f"{int(current / total * 100)}%"
        self.progress_label.setText(f"{current}/{total} ({percent_str})")
        if self.on_progress:
            self.on_progress(current, total)

    def set_progress_full(
        self, progress: float, current: int, total: int, is_file_size: bool = False
    ):
        if total < 0:
            total = 1
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(int(progress * 100))
        if is_file_size:
            current_str = io.file_handler.FileSize(current).format()
            total_str = io.file_handler.FileSize(total).format()
        else:
            current_str = str(current)
            total_str = str(total)
        percent_str = f"{int(progress * 100)}%"
        self.progress_label.setText(f"{current_str}/{total_str} ({percent_str})")
        if self.on_progress:
            self.on_progress(current, total)
