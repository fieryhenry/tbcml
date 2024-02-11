import tbcml


class CustomCat(tbcml.Cat):
    def __init__(self, bcuzip: tbcml.BCUZip):
        super().__init__(cat_id=0)

        self.import_from_bcu(bcuzip, bcu_id=0)  # id 0 = first bcu cat, 1 = 2nd, etc..


zip_data = tbcml.Path("examples/bcu/99ogmqbr.pack.bcuzip").read()
zip = tbcml.BCUZip(zip_data)

mod = tbcml.Mod()
mod.add_modification(CustomCat(zip))
