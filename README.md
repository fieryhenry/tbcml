# Battle Cats Mod Manager

## Introduction

The battle cats mod manager is a tool for easily loading and managing mods into The Battle Cats.

Join the [discord server](https://discord.gg/DvmMgvn5ZB) if you want to suggest new features, report bugs or get help on how to use the modding tool (please read the below tutorials first before asking for help).

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M53M4MN)

## Thanks to:

- EasyMoneko for the original keys for decrypting/encrypting: https://www.reddit.com/r/battlecats/comments/41e4l1/is_there_anyone_able_to_access_bc_files_your_help/

- Battle Cats Ultimate for what some of the numbers mean in various csvs. https://github.com/battlecatsultimate

- This resource for unit csvs: https://pastebin.com/JrCTPnUV

- Vixie on discord for enemy csvs

- My Gamatoto for enemy icons: https://mygamatoto.com

## Getting Started

#### Prerequisites

To get started loading mods into the game you will also need the following software:

##### Download

- [Python](https://www.python.org/downloads/)

- [Java JDK](https://www.oracle.com/uk/java/technologies/javase/jdk11-archive-downloads.html)

- [Apktool](https://ibotpeaches.github.io/Apktool/install/)

##### Installation

To install the tool, run the following command:

```batch
python3 -m pip install -U bcgm_mod_manager
```

If you are using windows you will most likely need to use `py` instead of `python3`.

##### Run

To start the tool, run the following command:

```batch
python3 -m bcgm_mod_manager
```

If you are using windows you will most likely need to use `py` instead of `python3`.

## Mods and Mod Packs

### Mods

Mods are in the format of a `.bcmod` file and can be shared and imported with the `Load mods from .bcmod files` option.

You can find examples of mods [here](https://github.com/fieryhenry/bcgm_mod_manager/tree/master/example_mods)

All mods are automatically enabled when they are loaded, but can be disabled with the option to `Mod Management -> Disable mods`. These won't be loaded into the game apk.

You can view your mods with the `Display mods` option.

##### Create a Mod

To create a mod you will need some game files. To get them you can use the `Data Decryption -> Decrypt all game files` option. To decrypt server files you will need to use the option to `Download -> Download server pack files` beforehand.

Then you will need to modify those files, to do this you can use the features in `Edit Game Files`

Once you have your modded files, use the option in the tool to `Mod Management -> Create mod from game files`. Then input the required information and select your custom files. Alternatively, if you already have a mod, you can add files to it (it will overwrite duplicate files) with the `Mod Management -> Add game files to mod` option.

##### Load Mods Into the Game

To load your mods into the game, first select what mods you want by enabling / disabling certain mods by using the options in the tool.

Then select the option to `Load enabled mods into apk`, and say whether or not you are using the jp version of the game.

You will need to wait a while for it to download the apk, extract files, encrypt mods, patch the lib file, and sign the apk.

Once finished you can say `y` to open the containing folder. It will be called `modded.apk`.

You can then install the apk like normal.

The opening text will have information about what mods are currently loaded

---

### Mod Packs

Mod Packs are in the form of a `.bcmodpack` file and are collections of mods.

They can be imported with the `Mod Packs -> Load mod packs from .bcmodpack files` option.

They act as regular mods that can be enabled, disabled, upacked, etc.

##### Create a Mod Pack

To create a mod pack, first enable the mods you want and disable the mods you don't want in the mod pack with the `Mod Management -> Enable mods` and `Mod Management -> Disable mods` options.

Then select the option to `Mod Packs -> Create mod pack of enabled mods`. Enter all of the required information.

The mod pack will be in the mods folder.

---

### Import Data from Battle Cats Ultimate

If you have modded bcu files that you want to put into the actual game, then use the `Edit Game Files -> Import bcu data` feature.

At the moment only custom cats will be imported with the feature, but this can be expanded overtime.

To get the files from bcu you will need to export the pack if you haven't already (may require a password). Then locate the bcu install folder and then the workspace folder.

WARNING: Some animations may cause the game to crash when entering a stage, getting knockbacked, etc. I have no idea why this happens and hopefully it can be fixed.

---

### Enemies as Cats

To use an enemy as a cat you will need to use the feature in `Edit Game Files -> Add enemies as cats`. Enter the enemy ids that you want from [here](https://battle-cats.fandom.com/wiki/Enemy_Release_Order). And the cat ids to replace from [here](https://battle-cats.fandom.com/wiki/Cat_Release_Order). The recharge time is set to 0 (not actually 0 in game), the cost is half the money drop and some abilities cannot be used by cats (e.g burrow, barrier / shield) and so aren't imported. The icons in the upgrade menu are low quality because that's the quality of the images that My Gamatoto uses. The icons in battle are auto-generated and so may look strange / offset.

### Todo

- [ ] Ability to import bcu data for stages and enemies + fix crashing with some cats

- [ ] Ability to add new cats / enemies into the game

- [ ] Mod browser

- [ ] Optimization

- [ ] Mobile app / gui
