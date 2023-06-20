from typing import Any, Callable
from PyQt5.QtCore import QTimer


class FrameClock:
    def __init__(self, fps: int):
        self.fps = fps
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000 // fps)
        self.frame = 0
        self.funcs: list[Callable[..., Any]] = []

    def tick(self):
        self.frame += 1
        for func in self.funcs:
            func()

    def add_func(self, func: Callable[..., Any]):
        self.funcs.append(func)

    def remove_func(self, func: Callable[..., Any]):
        self.funcs.remove(func)

    def get_frame(self) -> int:
        return self.frame
