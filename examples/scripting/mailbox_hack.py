# see https://github.com/fieryhenry/mailboxhack for more information on what this script does
import sys
from tbcml.core import (
    NewMod,
    NewFridaScript,
    Path,
    NewModLoader,
)

loader = NewModLoader("en", "12.3.0")
print("Initializing mod loader")
loader.initialize()

apk = loader.get_apk()

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
is_file_str = "true" if is_file else "false"

script_content = script_content.replace(
    "{{IS_FILE}}",
    is_file_str,
)

print("Loading presents from" + presents_str)

script = NewFridaScript(
    name="Mailbox Hack",
    content=script_content,
    architectures="all",
    description="Disable signature verification + capture presents responses",
)

mod = NewMod(
    name="Mailbox Hack",
    authors=["fieryhenry", "jamesiotio", "NekoB0x"],
    description="A mod that disables signature verification and replaces mailbox server responses with custom ones.",
)

mod.add_script(script)

apk.set_app_name("Battle Cats Mailbox Hack")
apk.set_package_name(
    "jp.co.ponos.battlecatsen.mailboxhack"
)  # may not work if you set decode_resources to False when extracting the APK

print("Applying mods to game...")

loader.apply(mod)
loader.initialize_adb()
loader.install_adb(run_game=True)
print(apk.final_apk_path)
