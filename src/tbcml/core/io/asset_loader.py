from tbcml import core

try:
    from PyQt5 import QtGui, QtWidgets
except ImportError:
    pass


class AssetLoader:
    def __init__(self, theme: str = "dark"):
        if theme == "default":
            self.style_theme = "dark"
        self.theme = theme

    def get_stlye_file_path(self, local_path: str) -> "core.Path":
        return core.Path(is_relative=True).add(
            "assets", "styles", self.style_theme, local_path
        )

    def load_svg(self, path: str) -> "QtGui.QIcon":
        return QtGui.QIcon(str(self.get_stlye_file_path(path)))

    @staticmethod
    def get_asset_file_path(local_path: str) -> "core.Path":
        return core.Path(is_relative=True).add("assets", local_path)

    def load_icon(self, path: str) -> "QtGui.QIcon":
        return QtGui.QIcon(str(self.get_asset_file_path(path)))

    def load_stylesheet(self, widget: "QtWidgets.QWidget"):
        # themes provided by https://github.com/Alexhuszagh/BreezeStyleSheets
        if self.theme == "default":
            return
        style_path = core.Path(is_relative=True).add(
            "assets", "styles", self.theme, "stylesheet.qss"
        )
        data = style_path.read().to_str()
        data = data.replace(f"url({self.theme}:", f"url({str(style_path.parent())}/")

        widget.setStyleSheet(data)
