# Mod Edits Structure

image structure

```json
{
    "__image__": "base64 encoded image                                                   ---string",
}
```

rect structure

```json
{
    "x": "x coordinate of the top left corner of the rect                                ---integer",
    "y": "y coordinate of the top left corner of the rect                                ---integer",
    "width": "width of the rect                                                          ---integer",
    "height": "height of the rect                                                        ---integer",
    "name": "optional name of the rect                                                   ---string",
}
```

texture structure

```json
{
    "image": "sprite sheet of the texture                                                ---image structure",
    "rects": [
        "1 cut of the texture                                                            ---rect structure",
    ],
    "metadata": {
        "head_name": "header name of the file e.g imgcut                                 ---string",
        "version_code": "version code of the file e.g 1                                  ---integer",
        "img_name": "name of the image e.g 000_f.png                                     ---string",
    },
    "imgcut_name": "name of the imgcut e.g 000_f.imgcut                                  ---string",
}
```

```json
{
    "item_shop" : {
        "items": {
            "id": {
                "gatya_item_id": "id for item                                            ---integer",
                "count": "amount to buy                                                  ---integer",
                "price": "catfood cost of purchase                                       ---integer",
                "draw_item_value": "wether to display the current item amount            ---boolean",
                "category_name": "name of shop category on the top left of the screen    ---localizable string",
                "rect_id": "imgcut id of image                                           ---integer",
            }
        },
        "tex": "imgcut of all the items in the shop                                      ---texture structure",
    },
    "cats": {
        "id": {
            "forms": {
                "id": {
                    "name": "name of the cat                                             ---string",
                    "description": [
                        "line 1 of description                                           ---string",
                        "line 2 of description                                           ---string",
                        "line 3 of description                                           ---string",
                    ],
                    "stats": {
                        "raw_stats": {
                            "id": "stat value                                            ---integer",
                        }
                    }
                }
            }
        }
    }
}
```
