from typing import Optional

import ffmpeg  # type: ignore

from tbcml import core


class AudioFile:
    """Represents an audio file."""

    def __init__(self, data: "core.Data", file_name: str):
        """Initializes an AudioFile.

        Args:
            data (core.Data): The data of the audio file.
            file_name (str): The name of the audio file.
        """
        self.data = data
        self.file_name = file_name

    @staticmethod
    def from_zip(zip_file: "core.Zip", file_name: str) -> "AudioFile":
        """Creates an AudioFile from a mod zip file.

        Args:
            zip_file (core.Zip): Mod zip file to read from.
            file_name (str): Name of the audio file.

        Raises:
            ValueError: If the file is not found in the zip file.

        Returns:
            AudioFile: The audio file.
        """
        path = core.Path("audio").add(file_name)
        data = zip_file.get_file(path)
        if data is None:
            raise ValueError(f"File {path} not found in zip file")
        return AudioFile(data, file_name)

    def to_zip(self, zip_file: "core.Zip"):
        """Adds the audio file to a mod zip file.

        Args:
            zip_file (core.Zip): Mod zip file to add to.
        """
        path = core.Path("audio").add(self.file_name)
        zip_file.add_file(path, self.data)

    def get_id(self) -> int:
        """Gets the ID of the audio file.

        Returns:
            int: The ID of the audio file.
        """
        name = self.file_name.split(".")[0]
        id = name.replace("snd", "")
        return int(id)

    def get_apk_name(self) -> str:
        """Gets the name of the audio file in the APK.

        Returns:
            str: The name of the audio file in the APK.
        """
        if not self.file_name.startswith("snd"):
            return f"snd{self.file_name}"
        return self.file_name

    @staticmethod
    def from_file(path: "core.Path") -> "AudioFile":
        """Creates an AudioFile from a file.

        Args:
            path (core.Path): Path to the audio file.

        Returns:
            AudioFile: The audio file.
        """
        data = path.read()
        file_name = path.basename()
        return AudioFile(data, file_name)

    def __str__(self) -> str:
        """Gets the name of the audio file.

        Returns:
            str: The name of the audio file.
        """
        return self.file_name

    def __repr__(self) -> str:
        """Gets the name of the audio file.

        Returns:
            str: The name of the audio file.
        """
        return self.file_name

    def caf_to_little_endian(self) -> "AudioFile":
        """Converts a CAF audio file to little endian. Stuff like audacity saves CAF files as big endian and the game doesn't support that.

        Returns:
            AudioFile: The audio file.
        """
        extension = self.get_extension()
        if extension != "caf":
            return self
        with core.TempFile(extension=extension) as input_temp:
            input_temp.write(self.data)

            stream = ffmpeg.input(input_temp.path)  # type: ignore
            with core.TempFile(extension=extension) as output_temp:
                stream = ffmpeg.output(  # type: ignore
                    stream, output_temp.path, acodec="pcm_s16le", loglevel="quiet"  # type: ignore
                )
                ffmpeg.run(stream)  # type: ignore

                self.data = output_temp.read()

        return self

    def get_extension(self) -> str:
        """Gets the extension of the audio file.

        Returns:
            str: The extension of the audio file.
        """
        return self.file_name.split(".")[-1]

    def play(self):
        """Plays the audio file by writing it to a temporary file and opening it."""

        with core.TempFile(extension=self.get_extension()) as temp_file:
            temp_file.write(self.data)
            temp_file.open_file()


class Audio:
    """Represents a collection of audio files."""

    def __init__(self, audio_files: dict[str, AudioFile]):
        """Initializes an Audio object.

        Args:
            audio_files (dict[str, AudioFile]): The audio files. The key is the name of the audio file.
        """
        self.audio_files = audio_files

    @staticmethod
    def create_empty() -> "Audio":
        """Creates an empty Audio object.

        Returns:
            Audio: The empty Audio object.
        """
        return Audio({})

    def add_to_zip(self, zip_file: "core.Zip"):
        """Adds the audio files to a mod zip file.

        Args:
            zip_file (core.Zip): Mod zip file to add to.
        """
        for audio_file in self.audio_files.values():
            audio_file.to_zip(zip_file)

    @staticmethod
    def from_zip(zip_file: "core.Zip") -> "Audio":
        """Creates an Audio object from a mod zip file.

        Args:
            zip_file (core.Zip): Mod zip file to read from.

        Returns:
            Audio: The audio object.
        """
        audio_files = {}
        for file in zip_file.get_paths():
            if file.path.startswith("audio/"):
                audio_file = AudioFile.from_zip(zip_file, file.basename())
                audio_files[audio_file.file_name] = audio_file
        return Audio(audio_files)

    def import_audio(self, other: "Audio"):
        """Imports audio files from another Audio object.

        Args:
            other (Audio): The other Audio object.
        """
        self.audio_files.update(other.audio_files)

    def sort_by_id(self):
        """Sorts the audio files by their ID."""
        audio_files = sorted(self.audio_files.values(), key=lambda x: x.get_id())
        self.audio_files = {
            audio_file.file_name: audio_file for audio_file in audio_files
        }

    def get(self, file_name: str) -> Optional[AudioFile]:
        """Gets an audio file.

        Args:
            file_name (str): Name of the audio file.

        Returns:
            AudioFile: The audio file.
        """
        return self.audio_files.get(file_name)
