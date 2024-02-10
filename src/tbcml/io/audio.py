try:
    import ffmpeg  # type: ignore
except ImportError:
    ffmpeg = None

from marshmallow_dataclass import dataclass
import tbcml


@dataclass
class AudioFile:
    id: int
    is_bgm: bool
    data: "tbcml.Data"

    def get_sound_format(self):
        return AudioFile.get_sound_format_s(self.is_bgm)

    @staticmethod
    def get_sound_format_s(is_bgm: bool):
        if is_bgm:
            return "ogg"
        return "caf"

    @staticmethod
    def get_is_bgm(sound_format: str):
        if sound_format == "ogg":
            return True
        return False

    def caf_to_little_endian(self) -> "AudioFile":
        """Converts a CAF audio file to little endian. Stuff like audacity saves CAF files as big endian and the game doesn't support that.

        Returns:
            AudioFile: The audio file.
        """
        extension = self.get_sound_format()
        if extension != "caf":
            return self
        if ffmpeg is None:
            print("ffmpeg not installed, skipping conversion")
            return self
        with tbcml.TempFile(extension=extension) as input_temp:
            input_temp.write(self.data)

            stream = ffmpeg.input(input_temp.path)  # type: ignore
            with tbcml.TempFile(extension=extension) as output_temp:
                stream = ffmpeg.output(  # type: ignore
                    stream, output_temp.path, acodec="pcm_s16le", loglevel="quiet"  # type: ignore
                )
                ffmpeg.run(stream)  # type: ignore

                self.data = output_temp.read()

        return self

    def get_apk_file_name(self) -> str:
        id_str = str(self.id).zfill(3)
        ext = self.get_sound_format()
        return f"snd{id_str}.{ext}"
