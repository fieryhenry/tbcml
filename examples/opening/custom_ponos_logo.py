import tbcml


path = tbcml.Path(__file__).parent().add("new_ponos_logo.png")

logo_screen = tbcml.LogoScreen()
logo_screen.import_img(path)

mod = tbcml.Mod()
mod.add_modification(logo_screen)
