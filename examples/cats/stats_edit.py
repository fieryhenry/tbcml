import tbcml


class NewForm(tbcml.CatForm):
    def __init__(self):
        super().__init__(form_type=tbcml.CatFormType.FIRST)

        stats = self.get_stats()
        stats.hp = 5000
        stats.cost = 0
        stats.attack_1_damage = 8000
        stats.speed = 100
        stats.attack_interval = 0
        stats.area_attack = True


class NewCat(tbcml.Cat):
    def __init__(self):
        super().__init__(cat_id=0)

        self.set_form(NewForm())


mod = tbcml.Mod()
mod.add_modification(NewCat())
