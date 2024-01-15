from typing import Optional
import tbcml


class LocalDeviceHandler:
    def __init__(self):
        self.package_name: Optional[str] = None

    def set_package_name(self, package_name: str):
        self.package_name = package_name

    def get_package_name(self) -> str:
        if self.package_name is None:
            raise ValueError("Package name is not set")
        return self.package_name

    def run_cmd(self, command: str) -> "tbcml.CommandResult":
        return tbcml.Command(command, display_output=False).run()

    def close_game(self) -> "tbcml.CommandResult":
        return self.run_cmd(f"am force-stop {self.get_package_name()}")

    def run_game(self) -> "tbcml.CommandResult":
        return self.run_cmd(
            f"monkey -p {self.get_package_name()} -c android.intent.category.LAUNCHER 1"
        )

    def install_apk(self, apk_path: "tbcml.Path") -> "tbcml.CommandResult":
        return self.run_cmd(f"pm install {apk_path}")
