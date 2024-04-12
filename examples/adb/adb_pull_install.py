import tbcml

adb_handler = tbcml.AdbHandler()
adb_handler.set_package_name("jp.co.ponos.battlecatsen")

devices = adb_handler.get_connected_devices()
print(devices)
if len(devices) == 0:
    raise ValueError("No devices connected")
adb_handler.set_device(devices[0])

apk = adb_handler.pull_apk()
# can overwrite autodetected cc and gv with adb_handler.pull_apk(cc, gv)

if apk is None:
    raise ValueError("Failed to pull apk")

apk.extract()
apk.download_server_files(display=True)

apk.set_app_name("ADB New")
apk.set_package_name("jp.co.ponos.battlecatsen.adb")

apk.load_mods([])

print(apk.final_pkg_path)

adb_handler.install_apk(apk.final_pkg_path)
adb_handler.run_game()

# cProfile.run("do()", sort="cumtime")
