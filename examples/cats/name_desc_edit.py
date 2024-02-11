import tbcml


class NewForm(tbcml.CatForm):
    def __init__(self):
        super().__init__(form_type=tbcml.CatFormType.FIRST)

        self.name = "cool name"
        self.description = ["cat that does stuff...", "example cat for tbcml"]


class NewCat(tbcml.Cat):
    def __init__(self):
        super().__init__(cat_id=0)

        self.set_form(NewForm())


mod = tbcml.Mod()
mod.add_modification(NewCat())
