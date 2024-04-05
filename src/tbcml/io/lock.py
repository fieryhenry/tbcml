from typing import Optional
import tbcml


class LockFile:
    def __init__(self, path: "tbcml.PathStr"):
        self.path = tbcml.Path(path)
        self.path.parent().generate_dirs()
        self._lock = None

    def __enter__(self) -> Optional["LockFile"]:
        if self.is_locked():
            return None
        self._lock = open(self.path.to_str(), "w")
        self._lock.write("LOCKED")
        return self

    def __exit__(self, exc_type: Exception, exc_value: Exception, traceback: Exception):
        if self._lock:
            self._lock.close()
            self.path.remove()

    def is_locked(self) -> bool:
        return self.path.exists()
