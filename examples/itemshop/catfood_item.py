import tbcml


class CustomLocalizable(tbcml.Localizable):
    def __init__(self):
        super().__init__()
        self.set_string("catfood", "Cat Food")


class CatFoodItem(tbcml.ShopItem):
    def __init__(self):
        super().__init__(
            count=500,
            cost=1,
            gatya_item_id=22,
            draw_item_value=True,
            category_name="catfood",
            imgcut_rect_id=0,  # use same image as speed up
        )


class CustomShop(tbcml.ItemShop):
    def __init__(self):
        super().__init__(
            total_items=4
        )  # change total number of shop items, leave as None to not remove any items

        self.set_item(CatFoodItem(), 2)  # set 3rd item to catfood


mod = tbcml.Mod()

mod.add_modification(CustomShop())
mod.add_modification(CustomLocalizable())
