# Help

## Download

#### Prerequisites

You will need to first download:

- [Python](https://www.python.org/downloads/) for running and installing the editor
- [Java JDK](https://www.oracle.com/uk/java/technologies/javase/jdk11-archive-downloads.html) for Apktool and signing the apk
- [Apktool](https://ibotpeaches.github.io/Apktool/install/) for extracting and packing the apk

If you are not using windows you will need to use `python3` instead of `py` in the following commands

#### Installation

Run this command to install the editor:

```batch
py -m pip install -U bcgm_mod_manager
```

If you get `No module named pip` then run this command:

```batch
py -m ensurepip --upgrade
```

#### Run

To start the tool run the following command:

```batch
py -m bcgm_mod_manager
```

## How to create custom game files

To create a mod you will need some game files. If you are wanting to edit any sprite / animation data you will need to first use the option to `Download -> Download server pack files`. If not, then just run the `Data Decryption -> Decrypt all game files` option. It will need to download the apk file, which could take a while.

After you have your game files, there are a few options on how you want to modify them. Here are the options:

#### Manual Modification

If you want to manually edit unit stats, enemy stats or stage data, then use the corresponding features in `Edit Game Files`. It will ask you if you want a fresh download of game files. You can say `n` as we have already done that step.

Then you can edit the stats that you want. Once finished, the tool will display where the modified files are, and you can move on to the next step.

#### Import enemies as cats

If you want to have an enemy as a cat unit, you will need to run the `Download -> Download server pack files` option and then the `Data Decryption -> Decrypt all game files` option to get the animation data.

Then you can run the `Edit Game Files -> Add enemies as cats` feature. sIt will ask you if you want a fresh download of game files. You can say `n` as we have already done that step.

Then you can enter the enemy ids that you wish to select from here: [Enemy Release Order](https://battle-cats.fandom.com/wiki/Enemy_Release_Order). Then you can enter the cat ids that you wish to replace, you can find cat ids here: [Cat Release Order](https://battle-cats.fandom.com/wiki/Cat_Release_Order).

The recharge time for the units is set to 0 (Game's hard min is 2 seconds), and the unit cost is set to half of its money drop. If an enemy has a targeted effect e.g weaken, knockback, slow, etc, the cat will target every trait. Some abilities that enemies have cannot be transferred onto a cat (e.g burrow, aku barrier, starred alien shield), and so will not have them. Only the first form is set, the other forms will be the normal cat forms (Might change that in the future).

The battle unit icons are automatically generated and so may look strange and positioned weirdly in the image. The upgrade unit icons are low quality because that's the quality the battle cats db, BCU, and My Gamatoto use.

It might take a while depending on how many enemies you selected.

Once finished, the tool will display where the modified files are, and you can move on to the next step.

#### Import from Battle Cats Ultimate data

If you have a BCU pack that you want as an actual mod, then you will first need to export the pack into the game files (In the future I might add the ability to select bcuzips).

First you will need to run the `Download -> Download server pack files` option and then the `Data Decryption -> Decrypt all game files` option to get the animation data.

Use the `Edit Game Files -> Import bcu data` feature and select the folder of the exported pack (Usually in the workspace folder in the BCU install folder).

At the moment, only unit data will be imported.

The upgrade unit icons are low quality because that's the quality BCU uses.

WARNING: Some animations may cause the game to crash when entering a 
stage, getting knockbacked, etc. I have no idea why this happens because it doesn't happen every time.

Once finished, the tool will display where the modified files are, and you can move on to the next step.

### How to create a mod

Once you have your game files you can use the `Mod Management -> Create mod from game files` to create a new mod. Then input the required information and select your custom files (The tool displayed where they are located when you created them). Alternatively, if you already have a mod, you can add files to it (it 
will overwrite duplicate files) with the `Mod Management -> Add game files to mod` option.

### Load mods into game

To load your mods into the game, first select what mods you want by 
enabling / disabling certain mods by using the options in the tool.

Then select the option to `Load enabled mods into apk`, and say whether or not you are using the jp version of the game.

You will need to wait a while for it to download the apk, extract files, encrypt mods, patch the lib file, and sign the apk.

Once finished you can say `y` to open the containing folder. It will be called `modded.apk`.

Then you will need re-install the game with your new mod. To do this, first start a data transfer and record your codes. Then uninstall the game. Then install the game again with your custom apk. Then wait for the files to download, then resume the data transfer with your codes.

The opening text (The one with the `Skip` button) will have information about what mods are currently loaded
