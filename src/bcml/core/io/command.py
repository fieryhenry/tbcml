import subprocess

class Result:
    def __init__(self, result: str, exit_code: int):
        self.result = result
        self.exit_code = exit_code
    
    def __str__(self) -> str:
        return self.result
    
    def __repr__(self) -> str:
        return f"Result({self.result!r}, {self.exit_code!r})"

class Command:
    def __init__(self, command: str, display_output: bool = True):
        self.command = command
        self.display_output = display_output
    
    def run(self, inputData: str = "\n") -> Result:
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            shell=True,
            universal_newlines=True,
        )
        if self.display_output and self.process.stdout:
            for line in self.process.stdout:
                print(line, end="")
        output = self.process.communicate(inputData)[0]
        exit_code = self.process.wait()
        return Result(output, exit_code)
