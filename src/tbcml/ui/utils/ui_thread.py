import enum
from typing import Any, Callable, Optional

from PyQt5 import QtCore


class ProgressMode(enum.Enum):
    NONE = 0
    PRIMARY = 1
    SECONDARY = 2
    TEXT = 3


class ThreadWorker(QtCore.QThread):
    has_finished = QtCore.pyqtSignal()
    progress = QtCore.pyqtSignal(int, int)
    progress_mode = QtCore.pyqtSignal(int, int)
    progress_text = QtCore.pyqtSignal(str, int, int)
    error = QtCore.pyqtSignal(Exception)

    def __init__(self, func: Callable[..., Any], *args: Any, **kwargs: Any):
        super(ThreadWorker, self).__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.progress_md = ProgressMode.NONE

    def run(self):
        if self.progress_md == ProgressMode.SECONDARY:
            self.run_progress_mode()
        elif self.progress_md == ProgressMode.PRIMARY:
            self.run_progress()
        elif self.progress_md == ProgressMode.NONE:
            self.run_normal()
        elif self.progress_md == ProgressMode.TEXT:
            self.run_progress_text()
        else:
            raise Exception("Invalid progress mode")

    def run_normal(self):
        try:
            self.func(*self.args, **self.kwargs)
        except Exception as e:
            self.error.emit(e)
        self.has_finished.emit()

    def run_progress(self):
        try:
            self.func(self.progress, *self.args, **self.kwargs)
        except Exception as e:
            self.error.emit(e)
        self.has_finished.emit()

    def run_progress_mode(self):
        try:
            self.func(self.progress, self.progress_mode, *self.args, **self.kwargs)
        except Exception as e:
            self.error.emit(e)
        self.has_finished.emit()

    def run_progress_text(self):
        try:
            self.func(self.progress_text, *self.args, **self.kwargs)
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

    @staticmethod
    def run_in_thread_progress(
        func: Callable[..., Any], progress_mode: ProgressMode, *args: Any, **kwargs: Any
    ) -> "ThreadWorker":
        return ThreadWorker.run_in_thread_progress_on_finished(
            func, progress_mode, None, *args, **kwargs
        )

    @staticmethod
    def run_in_thread_progress_on_finished(
        func: Callable[..., Any],
        progress_mode: ProgressMode,
        on_finished: Optional[Callable[..., Any]] = None,
        *args: Any,
        **kwargs: Any
    ) -> "ThreadWorker":
        worker = ThreadWorker(func, *args, **kwargs)
        if on_finished:
            worker.has_finished.connect(on_finished)
        worker.error.connect(lambda e: ThreadWorker.handle_error(e))
        worker.progress_md = progress_mode
        worker.start()
        return worker
