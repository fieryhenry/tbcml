# see https://github.com/fieryhenry/mailboxhack for more information on what this script does
import sys
from tbcml import Mod, FridaScript, Path, ModLoader, is_lief_installed

if not is_lief_installed():
    print(
        "Please install the scripting dependencies to use this. (pip install -r requirements_scripting.txt) when in tbcml folder"
    )
    exit(1)

loader = ModLoader("en", "13.2.0")  # change to whatever you want
print("Initializing mod loader")
loader.initialize()

# if you are having issues with apktool do this instead:
# loader.initialize(decode_resources=False)

# and if that still doesn't work do this instead:
# loader.initialize(decode_resources=False, use_apktool=False)

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

print("Loading presents from " + presents_str)

script = FridaScript(
    name="Mailbox Hack",
    content=script_content,
    architectures="all",
    description="Disable signature verification + capture presents responses",
)

mod = Mod(
    name="Mailbox Hack",
    authors=["fieryhenry", "jamesiotio", "NekoB0x"],
    short_description="A mod that disables signature verification and replaces mailbox server responses with custom ones.",
)

mod.add_script(script)

# the below lines may not work if you set decode_resources to False when
# initializing the loader

apk.set_app_name("Battle Cats Mail Box Hack")
apk.set_package_name("jp.co.ponos.battlecatsen.mailboxhack")

print("Applying mods to game...")

loader.apply(mod)

print(apk.final_pkg_path)

# uncomment the lines below to install the apk and run the game if you have a
# device connected with adb

# loader.initialize_adb()
# loader.install_adb(run_game=True)
