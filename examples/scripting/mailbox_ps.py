# see https://github.com/fieryhenry/TBCMailServer

from tbcml import (
    Mod,
    LibPatch,
    StringReplacePatch,
    FridaScript,
    ModLoader,
)

loader = ModLoader("en", "12.3.0")
loader.initialize()

mod = Mod(
    name="Private Server Setup",
    authors="fieryhenry",
    description="A mod that disables signature verification and replaces the nyanko-items url with a custom one",
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

script_32 = FridaScript(
    name="Force Verify Nyanko Signature",
    content=script_32,
    architectures="32",
    description="Overwrites a botan cryptography function to always return 1",
)
script_64 = FridaScript(
    name="Force Verify Nyanko Signature",
    content=script_64,
    architectures="64",
    description="Overwrites a botan cryptography function to always return 1",
)

mod.add_script(script_32)
mod.add_script(script_64)

string_patch = StringReplacePatch(
    "https://nyanko-items.ponosgames.com",
    "https://bc.serveo.net/items/",  # replace bc with whatever sub-domain you are using
    "_",
)

patch = LibPatch(
    name="Replace Nyanko Items URL",
    architectures="all",
    patches=string_patch,
)
mod.patches.add_patch(patch)

apk = loader.get_apk()

apk.set_app_name("12.3.0")
apk.set_package_name("jp.co.ponos.battlecatste")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)

print(apk.final_apk_path)
