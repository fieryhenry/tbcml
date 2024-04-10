from typing import Any, Callable, Optional
import tbcml


class AdbHandler:
    def __init__(self, adb_path: Optional["tbcml.Path"] = None):
        if adb_path is None:
            adb_path = tbcml.Path("adb")
        self.adb_path = adb_path
        self.start_server()
        self.device_id = None
        self.package_name = None

    def adb_root_success(self) -> bool:
        return (
            self.root_result.result.strip()
            != "adbd cannot run as root in production builds"
        )

    def start_server(self) -> "tbcml.CommandResult":
        return self.adb_path.run("start-server")

    def kill_server(self) -> "tbcml.CommandResult":
        return self.adb_path.run("kill-server")

    def root(self) -> "tbcml.CommandResult":
        return self.adb_path.run(f"-s {self.get_device()} root")

    @staticmethod
    def get_battlecats_path(package_name: str) -> "tbcml.Path":
        return tbcml.Path.get_root().add("data").add("data").add(package_name)

    def get_connected_devices(self) -> list[str]:
        devices = self.adb_path.run("devices").result.split("\n")
        devices = [device.split("\t")[0] for device in devices[1:-2]]
        return devices

    def set_device(self, device_id: str):
        self.device_id = device_id
        self.root_result = self.root()

    def set_package_name(self, package_name: str):
        self.package_name = package_name

    def get_package_name(self) -> str:
        if self.package_name is None:
            raise ValueError("Package name is not set")
        return self.package_name

    def get_device(self) -> str:
        if self.device_id is None:
            raise ValueError("Device ID is not set")
        return self.device_id

    def get_device_name(self) -> str:
        return self.run_shell("getprop ro.product.model").result.strip()

    def run_shell(self, command: str) -> "tbcml.CommandResult":
        return self.adb_path.run(f'-s {self.get_device()} shell "{command}"')

    def close_game(self) -> "tbcml.CommandResult":
        return self.run_shell(f"am force-stop {self.get_package_name()}")

    def run_game(self) -> "tbcml.CommandResult":
        return self.run_shell(
            f"monkey -p {self.get_package_name()} -c android.intent.category.LAUNCHER 1"
        )

    def install_apk(self, apk_path: "tbcml.Path") -> "tbcml.CommandResult":
        return self.adb_path.run(f"-s {self.get_device()} install {apk_path}")

    def pull_file(
        self, device_path: "tbcml.Path", local_path: "tbcml.Path"
    ) -> "tbcml.CommandResult":
        if not self.adb_root_success():
            result = self.run_shell(
                f"su -c 'cp {device_path.to_str_forwards()} /sdcard/ && chmod o+rw /sdcard/{device_path.basename()}'"
            )
            if result.exit_code != 0:
                return result
            device_path = tbcml.Path("/sdcard/").add(device_path.basename())

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

    def push_file(
        self, local_path: "tbcml.Path", device_path: "tbcml.Path"
    ) -> "tbcml.CommandResult":
        orignal_device_path = device_path.copy_object()
        if not self.adb_root_success():
            device_path = tbcml.Path("/sdcard/").add(device_path.basename())

        result = self.adb_path.run(
            f'-s {self.get_device()} push "{local_path}" "{device_path.to_str_forwards()}"'
        )
        if not result.success:
            return result
        if not self.adb_root_success():
            result2 = self.run_shell(
                f"su -c 'cp /sdcard/{device_path.basename()} {orignal_device_path.to_str_forwards()} && chmod o+rw {orignal_device_path.to_str_forwards()}'"
            )
            result3 = self.run_shell(f"rm /sdcard/{device_path.basename()}")
            if result2.exit_code != 0:
                return result2
            if result3.exit_code != 0:
                return result3

        return result

    def push_files(
        self, local_paths: list["tbcml.Path"], device_paths: list["tbcml.Path"]
    ) -> list["tbcml.CommandResult"]:
        results: list["tbcml.CommandResult"] = []
        for local_path, device_path in zip(local_paths, device_paths):
            results.append(self.push_file(local_path, device_path))
        return results

    def push_file_to_folder(
        self, local_path: "tbcml.Path", device_folder_path: "tbcml.Path"
    ) -> "tbcml.CommandResult":
        return self.push_file(local_path, device_folder_path.add(local_path.basename()))

    def push_files_to_folder(
        self, local_paths: list["tbcml.Path"], device_folder_path: "tbcml.Path"
    ) -> list["tbcml.CommandResult"]:
        results: list["tbcml.CommandResult"] = []
        for local_path in local_paths:
            results.append(self.push_file_to_folder(local_path, device_folder_path))
        return results

    def get_apk_path(self) -> "tbcml.Path":
        return tbcml.Path(
            self.run_shell(f"pm path {self.get_package_name()}")
            .result.strip()
            .split(":")[1]
        )

    def pull_apk_to_file(self, local_path: "tbcml.Path") -> "tbcml.CommandResult":
        return self.pull_file(self.get_apk_path(), local_path)

    def pull_apk(
        self,
        cc_overwrite: Optional["tbcml.CountryCode"] = None,
        gv_overwrite: Optional["tbcml.GameVersion"] = None,
    ) -> Optional["tbcml.Apk"]:
        with tbcml.TempFile() as temp_file:
            result = self.pull_apk_to_file(temp_file)
            if not result.success:
                print(result)
                return None
            return tbcml.Apk.from_pkg_path(temp_file, cc_overwrite, gv_overwrite)


class BulkAdbHandler:
    def __init__(
        self,
        default_package_name: Optional[str] = None,
        adb_path: Optional["tbcml.Path"] = None,
    ):
        self.default_package_name = default_package_name
        if adb_path is None:
            adb_path = tbcml.Path("adb")
        self.adb_path = adb_path
        self.adb_handlers: list[AdbHandler] = []

    def add_handler(self, adb_handler: AdbHandler):
        self.adb_handlers.append(adb_handler)

    def remove_handler(self, adb_handler: AdbHandler):
        self.adb_handlers.remove(adb_handler)

    def add_device(self, device_id: str, use_default_package_name: bool = True):
        adb_handler = AdbHandler()
        adb_handler.set_device(device_id)
        if use_default_package_name:
            adb_handler.set_package_name(self.get_default_package_name())
        self.add_handler(adb_handler)

    def add_devices(self, device_ids: list[str], use_default_package_name: bool = True):
        for device_id in device_ids:
            self.add_device(device_id, use_default_package_name)

    def add_all_connected_devices(self, use_default_package_name: bool = True) -> bool:
        devices = self.adb_path.run("devices").result.split("\n")
        devices = [device.split("\t")[0] for device in devices[1:-2]]
        if len(devices) == 0:
            return False
        self.add_devices(devices, use_default_package_name)
        return True

    def remove_device(self, device_id: str):
        adb_handler = self.get_handler(device_id)
        self.remove_handler(adb_handler)

    def remove_devices(self, device_ids: list[str]):
        for device_id in device_ids:
            self.remove_device(device_id)

    def get_handler(self, device_id: str) -> AdbHandler:
        for adb_handler in self.adb_handlers:
            if adb_handler.get_device() == device_id:
                return adb_handler
        raise ValueError("Device ID not found")

    def set_default_package_name(self, package_name: str):
        self.default_package_name = package_name

    def get_default_package_name(self) -> str:
        if self.default_package_name is None:
            raise ValueError("Default package name is not set")
        return self.default_package_name

    def run_adb_handler_function(
        self, function: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> list[Any]:
        results: list[Any] = []
        for adb_handler in self.adb_handlers:
            results.append(function(adb_handler, *args, **kwargs))
        return results
