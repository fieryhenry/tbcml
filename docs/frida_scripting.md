# Frida Scripting

## WARNING

You should only use frida scripts if you trust the source of the script. The scripts have full access to the app and can do anything they want.

## Introduction

Frida is a toolkit that allows you to inject JavaScript into native apps. This allows you to hook functions and modify the behaviour of the app. This is useful to do more advanced things that are not possible with just editing the game files.

If you want to inject java code into the game, you can use the [smali scripting](smali_scripting.md) feature.

I plan to add support for [cydia substrate](http://www.cydiasubstrate.com/) in the future so that you can write hooks in c++ and more closely integrate with the game. (This is how those 0 recharge time apks work)

## Setup

You will need to have downloaded the frida-gadget binaries for each architecture you want to target. You can find them [here](https://github.com/frida/frida/releases).

You then need to extract the binaries and place them in the `LibGadgets` folder in the tbcml folder in appdata or documents directory. The folder structure should look like this:

```bash
tbcml
├── LibGadgets
│   ├── x86
│   │   └── libfrida-gadget.so
│   ├── x86_64
│   │   └── libfrida-gadget.so
│   ├── arm64-v8a
│   │   └── libfrida-gadget.so
│   └── armeabi-v7a
│       └── libfrida-gadget.so
├── ...
```

## Usage

You need to create a script file that will be injected into the app. This script file will be written in JavaScript. You can find the documentation for the Frida API [here](https://frida.re/docs/javascript-api/).

The tool provides you with some helper functions that you can access:

```javascript
function logError(message) {}
function logWarning(message) {}
function logInfo(message) {}
function logVerbose(message) {}
function logDebug(message) {}
function log(message, level = "info" /* "error" | "warning" | "info" | "verbose" | "debug" */) {}

function getBaseAddress() {}
function readStdString(address) {}
function writeStdString(address, content) {}

function getJavaClass(className) {}
```

The code for the above functions can be found [here](https://github.com/fieryhenry/tbcml/blob/master/src/tbcml/core/mods/frida_script.py)

You can read the logs with `adb logcat -s tbcml`.

Note that if you do not use the `getBaseAddress()` function, then all addresses are offset by 0x1000 (4096) due to the libgadget injection into the libnative-lib.so library.

12.2.0en x86 example that leaks any obfuscated strings the game uses such as decryption keys or secret keys:

```javascript
let address = getBaseAddress().add(0x7fb370)

Interceptor.attach(address, { // uint * ObfuscatedString::get(uint *param_1,byte **param_2)
    onLeave: function (retval) {
        log("ObfuscatedString::get: " + readStdString(retval))
    }
});
```

Note that the above code only works for x86 running version 12.2.0en of the game. You will need to find the correct address for your version of the game and architecture by using a disassembler such as [Ghidra](https://ghidra-sre.org/) or [IDA](https://www.hex-rays.com/products/ida/).

If you are running game version 8.4 and older then you do not need to find specific addresses because some debugging symbols are included in the libnative-lib.so library. Game versions 6.10 and older are written in java and so you can do stuff with classes, methods and fields directly.

8.4.0en example that sets catfood to 45000 when the game saves the save file:

```javascript
let asave_sym = "_ZN13MyApplication5asaveERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE" // MyApplication::asave(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>> const&)
let asave_address = Module.findExportByName("libnative-lib.so", asave_sym)
Interceptor.attach(asave_address, {
    onEnter: function (args) {
        let gatya_set_sym = "_ZN15GatyaItemHelper3setEii" // GatyaItemHelper::set(int, int)
        let gatya_set_address = Module.findExportByName("libnative-lib.so", gatya_set_sym)
        let gatya_set_func = new NativeFunction(gatya_set_address, 'int', ["int", 'int'])
        gatya_set_func(22, 45000) // 22 is the id for catfood
    }
});
```

6.10.0en example that does the same thing:

```javascript
var MyApplication_init = getJavaClass("jp.co.ponos.battlecats.em");

MyApplication_init["save"].implementation = function () {
    let GatyaHelper = getJavaClass("jp.co.ponos.battlecats.bv");
    GatyaHelper.a(22, 45000); // GatyaHelper.set(int, int) 22 is the id for catfood
    this["save"]();
};
```

To add the script to your mod you can do the following:

```python
script_js = Path("{script_path}")
script = FridaScript("{architecture}", cc, gv, script_js.read().to_str(), "{script_name}", mod)
mod.scripts.add_script(script)
```
