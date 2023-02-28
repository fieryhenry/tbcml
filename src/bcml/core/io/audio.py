from bcml.core import io
import ffmpeg


class AudioFile:
    def __init__(self, path: io.path.Path):
        self.path = path
        self._audio = ffmpeg.input(str(path))

    def get_bc_file_name(self):
        file_name = self.path.basename()
        if not file_name.startswith("snd"):
            file_name = f"snd{file_name}"
        return file_name

    def save(self, path: io.path.Path):
        self._audio.output(str(path)).run()

    def caf_to_little_endian(self):
        if self.path.get_extension() == "caf":
            self._audio = self._audio.filter("endian", "little")
        return self

    def set_file_name(self, file_name: str):
        self.path = self.path.parent().add(file_name)
        return self

    def reverse(self):
        self._audio = self._audio.filter("areverse")
        return self

    def convert_to_ogg(self):
        temp_path = self.path.parent().add("temp.ogg")
        self.save(temp_path)
        self.path = temp_path
        self._audio = ffmpeg.input(str(self.path))
        temp_path.remove()
        return self
