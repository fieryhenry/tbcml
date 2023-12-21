from typing import Optional
from tbcml import core


class DeviceIDNotSet(Exception):
    pass


class AdbHandler:
    def __init__(self, package_name: str, adb_path: Optional["core.Path"] = None):
        if adb_path is None:
            adb_path = core.Path("adb")
        self.adb_path = adb_path
        self.package_name = package_name
        self.start_server()
        self.device_id = None
        self.cc = None

    def adb_root_success(self) -> bool:
        return (
            self.root_result.result.strip()
            != "adbd cannot run as root in production builds"
        )

    def start_server(self) -> "core.CommandResult":
        return self.adb_path.run("start-server")

    def kill_server(self) -> "core.CommandResult":
        return self.adb_path.run("kill-server")

    def root(self) -> "core.CommandResult":
        return self.adb_path.run(f"-s {self.get_device()} root")

    def get_connected_devices(self) -> list[str]:
        devices = self.adb_path.run("devices").result.split("\n")
        devices = [device.split("\t")[0] for device in devices[1:-2]]
        return devices

    def set_device(self, device_id: str):
        self.device_id = device_id
        self.root_result = self.root()

    def get_device(self) -> str:
        if self.device_id is None:
            raise DeviceIDNotSet("Device ID is not set")
        return self.device_id

    def get_device_name(self) -> str:
        return self.run_shell("getprop ro.product.model").result.strip()

    def run_shell(self, command: str) -> "core.CommandResult":
        return self.adb_path.run(f'-s {self.get_device()} shell "{command}"')

    def close_game(self) -> "core.CommandResult":
        return self.run_shell(f"am force-stop {self.package_name}")

    def run_game(self) -> "core.CommandResult":
        return self.run_shell(
            f"monkey -p {self.package_name} -c android.intent.category.LAUNCHER 1"
        )

    def install_apk(self, apk_path: "core.Path") -> "core.CommandResult":
        return self.adb_path.run(f"-s {self.get_device()} install {apk_path}")

    def pull_file(
        self, device_path: "core.Path", local_path: "core.Path"
    ) -> "core.CommandResult":
        if not self.adb_root_success():
            result = self.run_shell(
                f"su -c 'cp {device_path.to_str_forwards()} /sdcard/ && chmod o+rw /sdcard/{device_path.basename()}'"
            )
            if result.exit_code != 0:
                return result
            device_path = core.Path("/sdcard/").add(device_path.basename())

        result = self.adb_path.run(
            f'-s {self.get_device()} pull "{device_path.to_str_forwards()}" "{local_path}"',
        )
        if not result.success:
            return result
        if not self.adb_root_success():
            result2 = self.run_shell(f"su -c 'rm /sdcard/{device_path.basename()}'")
            if result2.exit_code != 0:
                return result2
        return result

    def get_apk_path(self) -> "core.Path":
        return core.Path(
            self.run_shell(f"pm path {self.package_name}").result.strip().split(":")[1]
        )

    def pull_apk_to_file(self, local_path: "core.Path") -> "core.CommandResult":
        return self.pull_file(self.get_apk_path(), local_path)

    def pull_apk(
        self,
        cc_overwrite: Optional["core.CountryCode"] = None,
        gv_overwrite: Optional["core.GameVersion"] = None,
    ) -> Optional["core.Apk"]:
        with core.TempFile() as temp_file:
            result = self.pull_apk_to_file(temp_file)
            if not result.success:
                print(result)
                return None
            return core.Apk.from_apk_path(temp_file, cc_overwrite, gv_overwrite)
