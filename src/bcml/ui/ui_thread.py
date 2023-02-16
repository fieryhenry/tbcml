from typing import Any, Callable, Optional
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
    def run_in_thread_on_finished(
        func: Callable[..., Any],
        on_finished: Optional[Callable[..., Any]] = None,
        *args: Any,
        **kwargs: Any
    ) -> "ThreadWorker":
        return ThreadWorker.run_in_thread_on_finished_args(
            func, on_finished, list(args), list(kwargs.values())
        )

    @staticmethod
    def run_in_thread_on_finished_args(
        func: Callable[..., Any],
        on_finished: Optional[Callable[..., Any]] = None,
        func_args: Optional[list[Any]] = None,
        on_finished_args: Optional[list[Any]] = None,
    ) -> "ThreadWorker":
        if func_args is None:
            func_args = []
        if on_finished_args is None:
            on_finished_args = []
        worker = ThreadWorker(func, *func_args)
        if on_finished:
            worker.has_finished.connect(lambda: on_finished(*on_finished_args))

        worker.error.connect(lambda e: ThreadWorker.handle_error(e))
        worker.start()
        return worker

    @staticmethod
    def run_in_thread(
        func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> "ThreadWorker":
        return ThreadWorker.run_in_thread_on_finished(func, None, *args, **kwargs)

    @staticmethod
    def handle_error(e: Exception):
        raise e
