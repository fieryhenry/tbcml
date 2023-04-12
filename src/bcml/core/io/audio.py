from bcml.core import io
import ffmpeg


class AudioFile:
    def __init__(self, data: "io.data.Data", file_name: str):
        self.data = data
        self.file_name = file_name

    @staticmethod
    def from_zip(zip_file: "io.zip.Zip", file_name: str):
        path = io.path.Path("audio").add(file_name)
        data = zip_file.get_file(path)
        if data is None:
            raise ValueError(f"File {path} not found in zip file")
        return AudioFile(data, file_name)

    def to_zip(self, zip_file: "io.zip.Zip"):
        path = io.path.Path("audio").add(self.file_name)
        zip_file.add_file(path, self.data)

    def get_id(self) -> int:
        name = self.file_name.split(".")[0]
        id = name.replace("snd", "")
        return int(id)

    def get_apk_name(self) -> str:
        if not self.file_name.startswith("snd"):
            return f"snd{self.file_name}"
        return self.file_name

    @staticmethod
    def from_file(path: "io.path.Path"):
        data = path.read()
        file_name = path.basename()
        return AudioFile(data, file_name)

    def __str__(self):
        return self.file_name

    def __repr__(self):
        return self.file_name

    def to_little_endian(self):
        extension = self.file_name.split(".")[-1]
        if extension != "caf":
            return self
        with io.temp_file.TempFile(extension=extension) as input_temp:
            input_temp.write(self.data)

            stream = ffmpeg.input(input_temp.path)
            with io.temp_file.TempFile(extension=extension) as output_temp:
                stream = ffmpeg.output(  # type: ignore
                    stream, output_temp.path, acodec="pcm_s16le", loglevel="quiet"
                )
                ffmpeg.run(stream)  # type: ignore

                self.data = output_temp.read()

        return self


class Audio:
    def __init__(self, audio_files: dict[str, AudioFile]):
        self.audio_files = audio_files

    @staticmethod
    def create_empty():
        return Audio({})

    def add_to_zip(self, zip_file: "io.zip.Zip"):
        json_data = {
            "audio_files": [
                audio_file.file_name for audio_file in self.audio_files.values()
            ]
        }
        data = io.json_file.JsonFile.from_object(json_data)
        zip_file.add_file(io.path.Path("audio.json"), data.to_data())

        for audio_file in self.audio_files.values():
            audio_file.to_zip(zip_file)

    @staticmethod
    def from_zip(zip_file: "io.zip.Zip"):
        data = zip_file.get_file(io.path.Path("audio.json"))
        if data is None:
            return Audio.create_empty()
        json_data = io.json_file.JsonFile.from_data(data).get_json()
        audio_files = {
            file_name: AudioFile.from_zip(zip_file, file_name)
            for file_name in json_data["audio_files"]
        }
        return Audio(audio_files)

    def import_audio(self, other: "Audio"):
        self.audio_files.update(other.audio_files)

    def sort_by_id(self):
        audio_files = sorted(self.audio_files.values(), key=lambda x: x.get_id())
        self.audio_files = {
            audio_file.file_name: audio_file for audio_file in audio_files
        }

    def get(self, file_name: str) -> AudioFile:
        return self.audio_files[file_name]
