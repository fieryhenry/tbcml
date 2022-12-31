from typing import Any, Callable, Literal, Optional, Union
import typing
from bcml.cli import color
from bcml.core import io
import tkinter as tk
from tkinter import filedialog

class Item:
    def __init__(self, name: Any, value: Optional[Any] = None, color: Optional[str] = None, func: Optional[Callable[..., Any]] = None, args: list[Any] = [], kwargs: dict[str, Any] = {}):
        self.name = name
        self.value = value
        self.color = color
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    @staticmethod
    def name_list_to_item_list(items: list[Any]) -> list["Item"]:
        return [Item(item) for item in items]
    
    @staticmethod
    def name_value_list_to_item_list(items: list[tuple[Any, Any]]) -> list["Item"]:
        return [Item(name, value) for name, value in items]
    
    def __str__(self) -> str:
        if self.value is None:
            return str(self.name)
        return f"{self.name} ({self.value})"
    
    def __repr__(self) -> str:
        return f"Item({self.name}, {self.value})"
    
    def to_display(self, index: int):
        if self.color is None:
            return f"<blue>{index + 1}.</> {self}"
        return f"<blue>{index + 1}.</> <{self.color}>{self}</>"
    
    def run(self) -> Any:
        if self.func is None:
            return
        return self.func(*self.args, **self.kwargs)

class ListSelector:
    def __init__(self, items: list["Item"], display: str = "") -> None:
        self.items = items
        self.display = display
    
    def get_index(self) -> Optional[int]:
        if not self.items:
            return None
        if len(self.items) == 1:
            color.ColoredText().display(f"<green>{self.items[0]}</>")
            return 0
        color.ColoredText().display(self.display)
        for index, item in enumerate(self.items):
            color.ColoredText().display(item.to_display(index))
        while True:
            try:
                selection = int(color.ColoredInput().get("Selection:"))
                if selection < 1 or selection > len(self.items):
                    raise ValueError
                color.ColoredText().display(f"<green>{self.items[selection - 1]}</>")
                return selection - 1
            except ValueError:
                color.ColoredText().display("<red>Invalid selection!</>")
    
    def get(self) -> Optional[Item]:
        index = self.get_index()
        if index is None:
            return None
        return self.items[index]
    
    def run(self) -> Any:
        index = self.get_index()
        if index is None:
            return
        return self.items[index].run()
    
    def get_multi_indexes(self) -> Optional[list[int]]:
        if not self.items:
            return []
        if len(self.items) == 1:
            color.ColoredText().display(f"<green>{self.items[0]}</>")
            return [0]
        color.ColoredText().display(self.display)
        for index, item in enumerate(self.items):
            color.ColoredText().display(item.to_display(index))
        while True:
            try:
                selections = color.ColoredInput().get("Selections (separate with spaces):").split()
                indexes = [int(selection) - 1 for selection in selections]
                if any(index < 0 or index >= len(self.items) for index in indexes):
                    raise ValueError
                color.ColoredText().display(f"<green>{', '.join(str(self.items[index]) for index in indexes)}</>")
                return indexes
            except ValueError:
                color.ColoredText().display("<red>Invalid selection!</>")
    
    def get_multi(self) -> Optional[list[Item]]:
        indexes = self.get_multi_indexes()
        if indexes is None:
            return None
        return [self.items[index] for index in indexes]
    
    def run_multi(self) -> list[Any]:
        indexes = self.get_multi_indexes()
        if indexes is None:
            return []
        return [self.items[index].run() for index in indexes]
    
    

class FileSelector:
    def __init__(self, title: str, filetypes: list[tuple[str, str]]):
        self.title = title
        self.filetypes = filetypes
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.wm_attributes("-topmost", 1) # type: ignore
    
    @typing.overload
    def get(self, multi: Literal[False]) -> Optional["io.path.Path"]:
        ...
    
    @typing.overload
    def get(self, multi: Literal[True]) -> Optional[list["io.path.Path"]]:
        ...
    
    @typing.overload
    def get(self) -> Optional["io.path.Path"]:
        ...

    def get(self, multi: bool = False) -> Union[Optional["io.path.Path"], Optional[list["io.path.Path"]]]:
        if multi:
            paths = filedialog.askopenfilenames(title=self.title, filetypes=self.filetypes)
            if not paths:
                return None
            return [io.path.Path(path) for path in paths]
        path = filedialog.askopenfilename(title=self.title, filetypes=self.filetypes)
        if not path:
            return None
        return io.path.Path(path)
    

class FolderSelector:
    def __init__(self, title: str, default: Optional["io.path.Path"] = None):
        self.title = title
        self.default = default
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.wm_attributes("-topmost", 1) # type: ignore
    
    def get(self) -> "io.path.Path":
        path = filedialog.askdirectory(title=self.title, initialdir=self.default.path if self.default else None)
        return io.path.Path(path)

