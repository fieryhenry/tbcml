# Frida Scripting

## Introduction

Frida is a toolkit that allows you to inject JavaScript or your own library into native apps. This allows you to hook functions and modify the behaviour of the app. This is useful to do more advanced things that are not possible with just editing the game files.

## Installation

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
function logError(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.e("tbcml", message);
        console.error(message);
    });
}
function logWarning(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.w("tbcml", message);
        console.warn(message);
    });
}
function logInfo(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.i("tbcml", message);
        console.info(message);
    });
}
function logVerbose(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.v("tbcml", message);
        console.log(message);
    });
}
function logDebug(message) {
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.d("tbcml", message);
        console.log(message);
    });
}
function log(message, level = "info") {
    switch (level) {
        case "error":
            logError(message);
            break;
        case "warning":
            logWarning(message);
            break;
        case "info":
            logInfo(message);
            break;
        case "verbose":
            logVerbose(message);
            break;
        case "debug":
            logDebug(message);
            break;
        default:
            logInfo(message);
            break;
    }
}

function getBaseAddress() {
    return Module.findBaseAddress("libnative-lib.so").add(4096); // offset due to libgadget being added
}

function readStdString(address) {
  const isTiny = (address.readU8() & 1) === 0;
  if (isTiny) {
    return address.add(1).readUtf8String();
  }

  return address.add(2 * Process.pointerSize).readPointer().readUtf8String();
}

function writeStdString(address, content) {
    const isTiny = (address.readU8() & 1) === 0;
    if (isTiny)
        address.add(1).writeUtf8String(content);
    else
        address.add(2 * Process.pointerSize).readPointer().writeUtf8String(content);
}
```

You can read the logs with `adb logcat -s tbcml`.

Here is an example script that leaks any obfuscated strings the game uses such as decryption keys or secret keys used for signing requests:

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

Note that the above code only works for x86 running version 12.2.0en of the game. You will need to find the correct address for your version of the game.

To add the script to your mod you can do the following:

```python
script_js = Path("script.js")
script = FridaScript("x86", cc, gv, script_js.read().to_str(), "obfuscated_int", mod)
mod.scripts.add_script(script)
```

Note that you should only use scripts that you trust. The scripts have full access to the app and can do anything they want.
