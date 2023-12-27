from typing import Any, Callable
from PyQt5.QtCore import QTimer


class FrameClock:
    def __init__(self, fps: int):
        self.fps = fps
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        self.frame = 0
        self.perm_frame = 0
        self.funcs: list[Callable[..., Any]] = []
        self.perm_funcs: list[Callable[..., Any]] = []
        self.perm_timer = QTimer()
        self.perm_timer.timeout.connect(self.tick_perm)
        self.perm_timer.start(1000 // fps)
        self.timer.start(1000 // fps)

    def set_tick(self, frame: int):
        self.frame = frame
        self.run_funcs()

    def set_perm(self, frame: int):
        self.perm_frame = frame
        self.run_perm_funcs()

    def set(self, frame: int):
        self.set_tick(frame)
        self.set_perm(frame)

    def advance_tick(self, frames: int):
        self.frame += frames
        self.run_funcs()

    def advance_perm(self, frames: int):
        self.perm_frame += frames
        self.run_perm_funcs()

    def advance(self, frames: int):
        self.advance_tick(frames)
        self.advance_perm(frames)

    def go_back_tick(self, frames: int):
        self.frame -= frames
        self.run_funcs()

    def go_back_perm(self, frames: int):
        self.perm_frame -= frames
        self.run_perm_funcs()

    def go_back(self, frames: int):
        self.go_back_tick(frames)
        self.go_back_perm(frames)

    def tick(self):
        self.frame += 1
        self.run_funcs()

    def run_funcs(self):
        for func in self.funcs:
            if not self.run_func(func):
                self.funcs.remove(func)

    def run_perm_funcs(self):
        for func in self.perm_funcs:
            if not self.run_func(func):
                self.perm_funcs.remove(func)

    def tick_perm(self):
        self.perm_frame += 1
        self.run_perm_funcs()

    def run_func(self, func: Callable[..., Any]) -> bool:
        try:
            func()
        except Exception as e:
            print(e)
            return False
        return True

    def add_func(self, func: Callable[..., Any]):
        self.funcs.append(func)

    def add_perm_func(self, func: Callable[..., Any]):
        self.perm_funcs.append(func)

    def remove_func(self, func: Callable[..., Any]):
        self.funcs.remove(func)

    def remove_perm_func(self, func: Callable[..., Any]):
        self.perm_funcs.remove(func)

    def get_frame(self) -> int:
        return self.frame

    def get_perm_frame(self) -> int:
        return self.perm_frame

    def is_stopped(self) -> bool:
        return not self.timer.isActive()

    def start(self):
        self.timer.start(1000 // self.fps)

    def stop(self):
        self.timer.stop()
