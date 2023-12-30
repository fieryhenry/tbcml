# see https://github.com/fieryhenry/mailboxhack for more information on what this script does
import sys
from tbcml.core import (
    CountryCode,
    GameVersion,
    Apk,
    Mod,
    FridaScript,
    AdbHandler,
    Path,
    TempFile,
)

cc = CountryCode.EN  # change cc to be what you want
gv = GameVersion.from_string_latest(
    "12.3.0", cc
)  # change gv to be what you want (later versions may not work with the current version of tbcml)

apk = Apk(gv, cc, allowed_script_mods=True)

print("Downloading APK...")
apk.download()

print("Extracting APK...")
apk.extract(
    decode_resources=True
)  # later game versions may crash when packing if you set decode_resources to True, so set it to False if that happens. Setting it to False will mean that the package name and the app name will not be set.

print("Creating mod...")
mod = Mod(
    name="Mailbox Hack",
    author="fieryhenry",
    description="A mod that disables signature verification and replaces mailbox server responses with custom ones.",
    mod_id=Mod.create_mod_id(),
    mod_version="1.0.0",
    encrypt=False,
)

script_content = Path(__file__).parent().add("mailbox_hack.js").read().to_str()

args = sys.argv[1:]
if len(args) > 0:
    presents_str = args[0]
else:
    presents_str = "https://raw.githubusercontent.com/fieryhenry/TBCMailServer/main/src/tbcms/files/example.json"

script_content = script_content.replace(
    "{{PRESENTS_URL}}",
    presents_str,
)
is_file = not presents_str.startswith("http")
file_path = None
if is_file:
    script_content = script_content.replace(
        "{{IS_FILE}}",
        "true",
    )
    file_path = TempFile.get_temp_path("presents.json")
    file_path.write(Path(presents_str).read())

    print("Presents loaded from" + file_path.to_str())
else:
    script_content = script_content.replace(
        "{{IS_FILE}}",
        "false",
    )

    print("Presents loaded from " + presents_str)

script_name = "mailbox-hack"
id = FridaScript.create_id()

for arc in apk.get_architectures():
    script = FridaScript(arc, cc, gv, script_content, script_name, id, mod)
    mod.scripts.add_script(script)
    if is_file and file_path is not None:
        apk.add_to_lib_folder(arc, file_path)

if is_file and file_path is not None:
    file_path.remove()

apk.set_app_name("Battle Cats Mailbox Hack")
apk.set_package_name(
    "jp.co.ponos.battlecatsen.mailboxhack"
)  # may not work if you set decode_resources to False when extracting the APK

print("Creating modded APK...")

apk.load_mods([mod])

print(apk.final_apk_path)

# uncomment the lines below to install the APK and run the game if you have a device connected with ADB

# adb_handler = AdbHandler(apk.package_name)
# devices = adb_handler.get_connected_devices()
# print(devices)
# adb_handler.set_device(devices[0])
# adb_handler.install_apk(apk.get_final_apk_path())
# adb_handler.run_game()
