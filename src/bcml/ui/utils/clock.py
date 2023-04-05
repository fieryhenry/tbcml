from typing import Any
from PyQt5 import QtCore


class Clock:
    def __init__(self, fps: int, boost: int = 1):
        self.fps = fps * boost
        self.time = 0
        self.total_funcs = 0
        self.boost = boost
        self._timer = QtCore.QTimer()
        self._timer.timeout.connect(self._tick)

    def start(self):
        self._timer.start(1000 // self.fps)

    def stop(self):
        self._timer.stop()

    def _tick(self):
        self.time += 1

    def get_frame(self):
        frame = self.time // self.boost
        if frame < 0:
            return 0
        if frame > 2**31 - 1:
            return 0
        return frame

    def set_frame(self, frame: int):
        self.time = frame * self.boost

    def connect(self, func: Any):
        self._timer.timeout.connect(func)
        self.total_funcs += 1

    def disconnect(self, func: Any):
        self._timer.timeout.disconnect(func)
        self.total_funcs -= 1

    def is_stopped(self):
        return not self._timer.isActive()

    def is_playing(self):
        return self._timer.isActive()

    def increment(self):
        self.time += self.boost

    def decrement(self):
        self.time -= self.boost
        if self.time < 0:
            self.time = 0
