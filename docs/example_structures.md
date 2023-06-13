# Example Structures

## Mod Structure

```bash
├── apk_files
│   └── assets
│       └── bg.png
├── audio
│   └── 000.ogg
├── game_files
│   └── t_unit.csv
├── mod_edits
│   ├── cats
│   │   └── 0
│   │       └── forms
│   │           └── 0.json
│   │               └── upgrade_icon
│   │                   └── __image__.png
│   ├── enemies
│   │   └── 0.json
├── scripts
│   ├── scripts.json
│   ├── x86
│   │   └── 0 recharge time.json
│   ├── armeabi-v7a
│   │   └── 0 recharge time.json
├── smali
│   └── DataLoad.smali
├── mod.json
└── icon.png
```

## scripts.json Structure

```json
{
    "arcs": {
        "x86": [
            "0 recharge time.json"
        ],
        "armeabi-v7a": [
            "0 recharge time.json"
        ]
    }
}
```

## mod.json Structure

```json
{
    "name": "Mod Name",
    "author": "Mod Author",
    "description": "Mod Description",
    "long_description": "Mod Long Description",
    "mod_id": "rFBworJzHcwrgIqk",
    "mod_version": "1.0.0",
    "contributors": [
        "Contributor 1",
        "Contributor 2"
    ],
    "dependencies": [
        {
            "mod_id": "RyxAazQgntLCcrOr",
            "mod_version": "1.0.0"
        },
        {
            "mod_id": "oZFvzpFoYCsKakKF",
            "mod_version": "1.5.0"
        }
    ],
}
```
