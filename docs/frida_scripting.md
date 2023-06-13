# Frida Scripting

## WARNING

You should only use frida scripts if you trust the source of the script. The scripts have full access to the app and can do anything they want.

## Introduction

Frida is a toolkit that allows you to inject JavaScript or your own library into native apps. This allows you to hook functions and modify the behaviour of the app. This is useful to do more advanced things that are not possible with just editing the game files.

If you want to inject into java code, you can use the [smali scripting](smali_scripting.md) feature.

## Setup

You will need to have downloaded the frida-gadget binaries for each architecture you want to target. You can find them [here](https://github.com/frida/frida/releases).

You then need to extract the binaries and place them in the `LibGadgets` folder in the tbcml folder in appdata or home directory. The folder structure should look like this:

```bash
tbcml
├── LibGadgets
│   ├── x86
│   │   └── libgadget.so
│   ├── x86_64
│   │   └── libgadget.so
│   ├── arm64-v8a
│   │   └── libgadget.so
│   └── armeabi-v7a
│       └── libgadget.so
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
```

The code for the above functions can be found [here](https://github.com/fieryhenry/tbcml/blob/master/src/tbcml/core/mods/frida_script.py)

You can read the logs with `adb logcat -s tbcml`.

Note that if you do not use the `getBaseAddress()` function, then all addresses are offset by 0x1000 (4096) due to the libgadget injection into the libnative-lib.so library.

Here is an example script that leaks any obfuscated strings the game uses such as decryption keys or secret keys:

```javascript
let address = getBaseAddress().add(0x7fb370)

Interceptor.attach(address, { // uint * ObfuscatedString::get(uint *param_1,byte **param_2)
    onEnter: function (args) {
    },
    onLeave: function (retval) {
        log("ObfuscatedString::get: " + readStdString(retval))
    }
});
```

Note that the above code only works for x86 running version 12.2.0en of the game. You will need to find the correct address for your version of the game and architecture by using a disassembler such as [Ghidra](https://ghidra-sre.org/) or [IDA](https://www.hex-rays.com/products/ida/).

If you are running game version 8.4 and older then you do not need to find specific addresses because some debugging symbols are included in the libnative-lib.so library. Game versions 6.10 and older are written in java and are not currently supported with Frida and the tool, however you can still inject smali code into the app. See the [smali scripting](smali_scripting.md) page for more information.

To add the script to your mod you can do the following:

```python
script_js = Path("{script_path}")
script = FridaScript("{architecture}", cc, gv, script_js.read().to_str(), "{script_name}", mod)
mod.scripts.add_script(script)
```
