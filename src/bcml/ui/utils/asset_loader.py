from bcml.core import io
from PyQt5 import QtGui


class AssetLoader:
    def __init__(self, theme: str = "dark"):
        self.theme = theme

    def get_stlye_file_path(self, local_path: str) -> io.path.Path:
        return io.path.Path(is_relative=True).add(
            "assets", "styles", self.theme, local_path
        )

    def load_svg(self, path: str) -> QtGui.QIcon:
        return QtGui.QIcon(str(self.get_stlye_file_path(path)))

    def get_asset_file_path(self, local_path: str) -> io.path.Path:
        return io.path.Path(is_relative=True).add("assets", local_path)

    def load_icon(self, path: str) -> QtGui.QIcon:
        return QtGui.QIcon(str(self.get_asset_file_path(path)))
