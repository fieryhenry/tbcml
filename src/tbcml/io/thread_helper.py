from __future__ import annotations

import threading
from typing import Any, Callable, Generator, TypeVar

T = TypeVar("T")


class Thread:
    def __init__(self, func: Callable[..., Any], args: tuple[Any, ...]):
        self.func = func
        self.args = args

    def run(self):
        self.retval = self.func(*self.args)

    def get_return(self):
        return self.retval

    def set_thread_obj(self, obj: threading.Thread):
        self.thread = obj

    def get_thread(self) -> threading.Thread:
        return self.thread


def chunks(lst: list[T], n: int) -> Generator[list[T], None, None]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def run_chunk(funcs: list[Thread]):
    """Run a list of functions with a list of arguments"""
    for func in funcs:
        func.run()


def run_thread(thread: Thread):
    thread.run()


def create_threads(
    funcs: list[Callable[..., Any]], args: list[tuple[Any, ...]]
) -> list[Thread]:
    threads: list[Thread] = []
    for func, arg in zip(funcs, args):
        thread = Thread(func, arg)
        threads.append(thread)
    return threads


def run_in_thread(
    func: Callable[..., Any], args: tuple[Any, ...] | None = None
) -> Thread:
    if args is None:
        args = ()
    thread_obj = Thread(func, args)
    thread = threading.Thread(target=run_thread, args=(thread_obj,))
    thread.start()
    thread_obj.set_thread_obj(thread)
    return thread_obj


def run_in_threads(
    funcs: list[Callable[..., T]], args: list[tuple[Any, ...]], max_threads: int = 8
) -> list[T]:
    if len(funcs) != len(args):
        raise ValueError("Total functions and total args must be equal!")
    chunk_size = len(funcs) // max_threads
    func_chunks = chunks(funcs, chunk_size)
    arg_chunks = chunks(args, chunk_size)
    threads: list[threading.Thread] = []
    threads_ls_ls: list[Thread] = []
    for arg_chunk, fun_chunk in zip(arg_chunks, func_chunks):
        threads_ls = create_threads(fun_chunk, arg_chunk)
        thread = threading.Thread(target=run_chunk, args=(threads_ls,))
        thread.start()
        threads.append(thread)
        threads_ls_ls.extend(threads_ls)

    for thread in threads:
        thread.join()

    retvals: list[T] = []
    for thread_obj in threads_ls_ls:
        retvals.append(thread_obj.get_return())

    return retvals
