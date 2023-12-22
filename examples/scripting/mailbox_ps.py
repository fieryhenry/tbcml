# see https://github.com/fieryhenry/TBCMailServer

from tbcml.core import (
    CountryCode,
    GameVersion,
    Apk,
    Mod,
    LibPatch,
    StringReplacePatch,
    FridaScript,
)

cc = CountryCode.EN  # change cc to be what you want
gv = GameVersion.from_string_latest(
    "12.3.0", cc
)  # change gv to be what you want (later versions may not work with the current version of tbcml)
apk = Apk(gv, cc, allowed_script_mods=True)
print("Downloading APK...")
apk.download()
print("Extracting APK...")
apk.extract()
mod = Mod(
    name="Private Server Setup",
    author="fieryhenry",
    description="A mod that disables signature verification and replaces the nyanko-items url with a custom one",
    mod_id=Mod.create_mod_id(),
    mod_version="1.0.0",
    encrypt=False,
)

script_64 = """
let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhmS2_m" // 64 bit

// Botan::PK_Verifier::verify_message(...)
Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
    onLeave: function (retval) {
        retval.replace(0x1)
    }
})
"""

script_32 = """
let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhjS2_j" // 32 bit

// Botan::PK_Verifier::verify_message(...)
Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
    onLeave: function (retval) {
        retval.replace(0x1)
    }
})
"""

script_name = "force-verify-nyanko-signature"

id = FridaScript.create_id()
x86_script = FridaScript("x86", cc, gv, script_32, script_name, id, mod)
x86_64_script = FridaScript("x86_64", cc, gv, script_64, script_name, id, mod)
arm_32_script = FridaScript("armeabi-v7a", cc, gv, script_32, script_name, id, mod)
arm_64_script = FridaScript("arm64-v8a", cc, gv, script_64, script_name, id, mod)
mod.scripts.add_script(x86_script)
mod.scripts.add_script(x86_64_script)
mod.scripts.add_script(arm_32_script)
mod.scripts.add_script(arm_64_script)

string_patch = StringReplacePatch(
    "https://nyanko-items.ponosgames.com",
    "https://bc.serveo.net/items/",  # replace bc with whatever sub-domain you are using
    "_",
)
patch_name = "replace-nyanko-items-url"
id = LibPatch.create_id()
libpatch_x86 = LibPatch(
    patch_name,
    "x86",
    cc,
    gv,
    [string_patch],
    id,
)
libpatch_x86_64 = LibPatch(
    patch_name,
    "x86_64",
    cc,
    gv,
    [string_patch],
    id,
)
libpatch_arm_32 = LibPatch(
    patch_name,
    "armeabi-v7a",
    cc,
    gv,
    [string_patch],
    id,
)
libpatch_arm_64 = LibPatch(
    patch_name,
    "arm64-v8a",
    cc,
    gv,
    [string_patch],
    id,
)

mod.patches.add_patch(libpatch_x86)
mod.patches.add_patch(libpatch_x86_64)
mod.patches.add_patch(libpatch_arm_32)
mod.patches.add_patch(libpatch_arm_64)

apk.set_app_name("12.3.0")
apk.set_package_name("jp.co.ponos.battlecatste")

apk.load_mods([mod])

print(apk.final_apk_path)
