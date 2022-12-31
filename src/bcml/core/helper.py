from typing import Any


class ListManager:
    def __init__(self, lst: list[Any]):
        self.lst = lst
    
    def chunks(self, n: int) -> list[list[Any]]:
        return [self.lst[i:i + n] for i in range(0, len(self.lst), n)]

    def remove_comments(self) -> list[Any]:
        new_lst: list[Any] = []
        for item in self.lst:
            new_lst.append(item.split(b"//")[0])
        return new_lst
    
    @staticmethod
    def remove_empty(lst: list[Any]) -> list[Any]:
        new_lst: list[Any] = []
        for item in lst:
            if isinstance(item, list):
                ls = ListManager.remove_empty(item) # type: ignore
                if ls:
                    new_lst.append(ls)
            elif item:
                new_lst.append(item)
        return new_lst
    