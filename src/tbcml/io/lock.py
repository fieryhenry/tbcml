import time
from typing import Optional
import tbcml


class LockFile:
    def __init__(self, path: "tbcml.PathStr", duration: int = 120):
        self.path = tbcml.Path(path)
        self.path.parent().generate_dirs()
        self._lock = None
        self.duration = duration

    def __enter__(self) -> Optional["LockFile"]:
        if self.is_locked():
            return None
        stop_time = time.time() + self.duration
        self._lock = open(self.path.to_str(), "w")
        self._lock.write(str(stop_time))
        return self

    def __exit__(self, exc_type: Exception, exc_value: Exception, traceback: Exception):
        if self._lock:
            self._lock.close()
            self.path.remove()

    def is_locked(self) -> bool:
        if not self.path.exists():
            return False
        try:
            with open(self.path.to_str(), "r") as file:
                stop_time = float(file.read())
                return stop_time > time.time()
        except Exception:
            return False
