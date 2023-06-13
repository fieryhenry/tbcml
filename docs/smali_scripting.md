# Smali Scripting

## Introduction

Smali scripting allows you to inject smali code into the game. This allows you to hook functions and modify the behaviour of the app. This is useful to do more advanced things that are not possible with just editing the game files. However, this only really works on game versions 6.10 and older because the code is no longer written in java.

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

.method public static {method_name}{method_signature}
    .locals 0

    {method_body}

    return-void
.end method
```

To add the script to your mod you can do the following:

```python
smali_path = Path("DataLoad.smali")
smali = Smali(
    smali_path.read().to_str(), "DataLoad", "Start(Landroid/content/Context;)V"
)
mod.smali.add(smali)
```

The smali code for the above DataLoad.smali file can be found [here](https://github.com/fieryhenry/tbcml/blob/master/src/tbcml/files/assets/DataLoad.smali)

The code is taken from one of those 9999999 catfood APKs that load a zip file into the game's /data/data/jp.co.ponos.battlecats/ directory on first start up. This is useful for loading custom assets into the game that aren't in the apk. To use it, you need to create a `data.zip` file in the assets folder of the apk.

Example structure:

```bash
shared_prefs
├── save.xml (save file)
files
├── 09b1058188348630d98a08e0f731f6bd.dat (gatya data)

```
