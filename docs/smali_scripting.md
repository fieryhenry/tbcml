# Smali Scripting

## WARNING

You should only use smali scripts if you trust the source of the script. The scripts have full access to the app and can do anything they want.

## Introduction

Smali scripting allows you to inject smali code into the `onCreate()` method of the main activity. This allows you to write your own code that will be executed when the app starts up. This is useful to do more advanced things that are not possible with just editing the game files. On game versions 6.10.0 and older you can do lots more because the code is written in java. On newer versions, the code is written in c++ so you can't do as much. At the moment you can only inject into the `onCreate()` method of the main activity. In the future, I may add support for injecting into other methods and classes.

To inject into native code or to use another method to modify java code, you can use the [frida scripting](frida_scripting.md) feature.

## Setup

There is no setup required for smali scripting.

## Usage

You need to create a script file that will be injected into the app at the beginning of the `onCreate()` function. This script file will be written in smali. You can find the documentation for the smali language [here](https://source.android.com/docs/core/runtime/dalvik-bytecode).

The format of your script file should be:

```smali
.class public Lcom/tbcml/{class_name};
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static {method_signature}
    .locals 0

    {method_body}

    return-void
.end method
```

To add the script to your mod you can do the following:

```python
smali_path = Path("{path_to_smali_file}")
smali = Smali(
    smali_path.read().to_str(), "{class_name}", "{method_signature}"
)
mod.smali.add(smali)
```

Example code can be found [here](https://github.com/fieryhenry/tbcml/blob/master/src/tbcml/files/assets/DataLoad.smali)

The code is taken from one of those 9999999 catfood APKs that load a zip file into the game's /data/data/jp.co.ponos.battlecats/ directory on first start up. This is useful for loading custom assets into the game that aren't in the apk. To use it, you need to create a `data.zip` file in the assets folder of the apk.

Example structure:

```bash
data.zip
├── shared_prefs
│   └── save.xml (file that those 9999999 catfood APKs use to load save data, it's not actually used by the game anymore but the game is backwards compatible with it.)
├── files
│   └── 09b1058188348630d98a08e0f731f6bd.dat (gatya data)
```
