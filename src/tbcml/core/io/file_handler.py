from tbcml import core


class FileSize:
    def __init__(self, file_size: int):
        self.file_size = file_size

    def __str__(self) -> str:
        return self.format()

    def __repr__(self) -> str:
        return self.format()

    def format(self) -> str:
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024**2:
            return f"{self.file_size / 1024:.2f} KB"
        elif self.file_size < 1024**3:
            return f"{self.file_size / 1024 ** 2:.2f} MB"
        elif self.file_size < 1024**4:
            return f"{self.file_size / 1024 ** 3:.2f} GB"
        else:
            return f"{self.file_size / 1024 ** 4:.2f} TB"

    @staticmethod
    def from_file(path: "core.Path") -> "FileSize":
        return FileSize(path.get_file_size())
