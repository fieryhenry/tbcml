from tbcml.anim import model, anim

try:
    from tbcml.anim import viewer
except (NameError, ImportError):
    __all__ = ["model", "anim"]
else:
    __all__ = ["model", "anim", "viewer"]
