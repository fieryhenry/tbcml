from __future__ import annotations

import subprocess
import threading
import tbcml


class CommandResult:
    def __init__(self, result: str, exit_code: int):
        self.result = result
        self.exit_code = exit_code

    def __str__(self) -> str:
        return self.result

    def __repr__(self) -> str:
        return f"Result({self.result!r}, {self.exit_code!r})"

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def __bool__(self) -> bool:
        return self.success


class Command:
    def __init__(
        self,
        command: list[str],
        cwd: tbcml.Path | None = None,
        shell: bool = False,
    ):
        self.command = command
        self.process = None
        self.thread = None
        if isinstance(cwd, tbcml.Path):
            self.cwd = cwd.to_str()
        else:
            self.cwd = cwd

        self.shell = shell

    def run(self, inputData: str = "\n", display: bool = False) -> CommandResult:
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            shell=self.shell,
            universal_newlines=True,
            cwd=self.cwd,
        )
        output, _ = self.process.communicate(inputData)
        if display:
            print(output)
        return_code = self.process.wait()
        return CommandResult(output, return_code)

    def run_in_thread(self, inputData: str = "\n") -> None:
        self.thread = threading.Thread(target=self.run, args=(inputData,))
        self.thread.start()
