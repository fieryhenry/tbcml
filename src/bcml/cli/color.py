import enum
import colored  # type: ignore

class ColorHex(enum.Enum):
    GREEN = "#008000"
    RED = "#FF0000"
    DARK_YELLOW = "#D7C32A"
    BLACK = "#000000"
    WHITE = "#FFFFFF"
    CYAN = "#00FFFF"
    DARK_GREY = "#A9A9A9"
    BLUE = "#0000FF"
    YELLOW = "#FFFF00"
    MAGENTA = "#FF00FF"
    DARK_BLUE = "#00008B"
    DARK_CYAN = "#008B8B"
    DARK_MAGENTA = "#8B008B"
    DARK_RED = "#8B0000"
    DARK_GREEN = "#006400"
    LIGHT_GREY = "#D3D3D3"

class ColoredText:


    def __init__(self, end: str = "\n") -> None:
        self.end = end

    def display(self, string: str) -> None:
        text_data = self.parse(string)
        for i, (text, color) in enumerate(text_data):
            if i == len(text_data) - 1:
                text += self.end
            if color == "":
                print(text, end="")
            else:
                print(colored.stylize(text, colored.fg("#" + color)), end="")  # type: ignore

    def parse(self, txt: str) -> list[tuple[str, str]]:
        # example: "This is a <red>red</red> text"
        # example: "This is a <red>red</red> text with <green>green</green> text"
        # example: "This is a <#FF0000>red</#FF0000> text with <#00FF00>green</#00FF00> text"

        # output is in the form of: [("This is a ", ""), ("red", "#FF0000"), (" text with ", ""), ("green", "#00FF00"), (" text", "")]
        # allow escaping of < and > with \, so that \\<red\\> is not parsed as a color tag

        output: list[tuple[str, str]] = []
        text = txt + "</>"
        current_text = ""
        char_index = 0
        in_tag = False
        in_hex_code = False
        current_hex_color = ""
        in_enum_name = False
        current_enum_string = ""
        while char_index < len(text):
            char = text[char_index]
            if char == "\\":
                if char_index + 1 < len(text):
                    char_index += 1
                    char = text[char_index]
                    current_text += char
                    char_index += 1
                continue

            if char == "<":
                if current_enum_string:
                    for item in list(ColorHex):
                        name = item.name
                        if name.lower() == current_enum_string.lower():
                            current_hex_color = str(item.value).strip("#")
                            break
                output.append((current_text, current_hex_color))
                current_text = ""
                current_hex_color = ""
                current_enum_string = ""
                in_tag = True
            if char == ">":
                in_hex_code = False
                in_tag = False
                in_enum_name = False
                char_index += 1
                continue
            if not in_tag:
                current_text += char
            if in_hex_code:
                current_hex_color += char
            if char == "#" and in_tag:
                in_hex_code = True
            if in_enum_name:
                current_enum_string += char
            if in_tag and not in_hex_code:
                in_enum_name = True
            char_index += 1
        return output


class ColoredInput(ColoredText):
    def __init__(self, end: str = "") -> None:
        super().__init__(end)

    def get(self, display_string: str) -> str:
        self.display(display_string)
        return input()

    def get_int(
        self,
        display_string: str,
        error_message: str = "<red>Please enter a valid number</>",
    ) -> int:
        while True:
            try:
                return int(self.get(display_string))
            except ValueError:
                self.display(error_message)
    
    def get_bool(
        self,
        display_string: str,
        true_string: str = "y",
        false_string: str = "n",
    ):
        while True:
            result = self.get(display_string).lower()
            if result == true_string:
                return True
            if result == false_string:
                return False
