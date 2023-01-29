from typing import Any, Callable
from PyQt5 import QtCore


class ThreadWorker(QtCore.QThread):
    has_finished = QtCore.pyqtSignal()
    progress = QtCore.pyqtSignal(int, int)
    error = QtCore.pyqtSignal(Exception)

    def __init__(self, func: Callable[..., Any], *args: Any, **kwargs: Any):
        super(ThreadWorker, self).__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception as e:
            self.error.emit(e)
        self.has_finished.emit()

    @staticmethod
    def run_in_thread(
        func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> "ThreadWorker":
        worker = ThreadWorker(func, *args, **kwargs)
        worker.start()
        return worker
