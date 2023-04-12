import enum
import hashlib
import hmac
import random
from typing import Optional
from Cryptodome.Cipher import AES
from bcml.core import country_code, io, game_data


class HashAlgorithm(enum.Enum):
    """An enum representing a hash algorithm."""

    MD5 = enum.auto()
    SHA1 = enum.auto()
    SHA256 = enum.auto()


class Hash:
    """A class to hash data."""

    def __init__(self, algorithm: HashAlgorithm):
        """Initializes a new instance of the Hash class.

        Args:
            algorithm (HashAlgorithm): The hash algorithm to use.
        """
        self.algorithm = algorithm

    def get_hash(
        self,
        data: "io.data.Data",
        length: Optional[int] = None,
    ) -> "io.data.Data":
        """Gets the hash of the given data.

        Args:
            data (io.data.Data): The data to hash.
            length (Optional[int], optional): The length of the hash. Defaults to None.

        Raises:
            ValueError: Invalid hash algorithm.

        Returns:
            io.data.Data: The hash of the data.
        """
        if self.algorithm == HashAlgorithm.MD5:
            hash = hashlib.md5()
        elif self.algorithm == HashAlgorithm.SHA1:
            hash = hashlib.sha1()
        elif self.algorithm == HashAlgorithm.SHA256:
            hash = hashlib.sha256()
        else:
            raise ValueError("Invalid hash algorithm")
        hash.update(data.get_bytes())
        if length is None:
            return io.data.Data(hash.digest())
        return io.data.Data(hash.digest()[:length])


class AesCipher:
    """A class to represent an AES cipher."""

    def __init__(
        self,
        key: bytes,
        iv: Optional[bytes] = None,
        mode: Optional[int] = None,
        enable: bool = True,
    ):
        """Initializes a new instance of the AesCipher class.

        Args:
            key (bytes): Key to use.
            iv (Optional[bytes], optional): Initialization vector to use. Defaults to None.
            mode (Optional[int], optional): Mode to use. Defaults to None.
            enable (bool, optional): Whether to enable encryption. Defaults to True. ImageDataLocal is a pack that is not encrypted.
        """
        self.key = key
        self.iv = iv
        if mode is None:
            if iv is None:
                mode = AES.MODE_ECB
            else:
                mode = AES.MODE_CBC
        self.mode = mode
        self.enable = enable

    def get_cipher(self):
        """Gets the cipher.

        Returns:
            AES: The cipher.
        """
        if self.iv is None:
            return AES.new(self.key, self.mode)  # type: ignore
        else:
            return AES.new(self.key, self.mode, self.iv)  # type: ignore

    def encrypt(self, data: "io.data.Data") -> "io.data.Data":
        """Encrypts the given data.

        Args:
            data (io.data.Data): The data to encrypt.

        Returns:
            io.data.Data: The encrypted data.
        """
        if not self.enable:
            return data
        cipher = self.get_cipher()
        return io.data.Data(cipher.encrypt(data.get_bytes()))

    def decrypt(self, data: "io.data.Data") -> "io.data.Data":
        """Decrypts the given data.

        Args:
            data (io.data.Data): The data to decrypt.

        Returns:
            io.data.Data: The decrypted data.
        """
        if not self.enable:
            return data
        cipher = self.get_cipher()
        return io.data.Data(cipher.decrypt(data.get_bytes()))

    @staticmethod
    def get_cipher_from_pack(
        cc: country_code.CountryCode, pack_name: str
    ) -> "AesCipher":
        """Gets the cipher from the pack.

        Args:
            cc (country_code.CountryCode): The country code.
            pack_name (str): The pack name.

        Raises:
            Exception: Unknown country code.

        Returns:
            AesCipher: The cipher.
        """
        aes_mode = AES.MODE_CBC
        if cc == country_code.CountryCode.JP:
            key = "d754868de89d717fa9e7b06da45ae9e3"
            iv = "40b2131a9f388ad4e5002a98118f6128"
        elif cc == country_code.CountryCode.EN:
            key = "0ad39e4aeaf55aa717feb1825edef521"
            iv = "d1d7e708091941d90cdf8aa5f30bb0c2"
        elif cc == country_code.CountryCode.KR:
            key = "bea585eb993216ef4dcb88b625c3df98"
            iv = "9b13c2121d39f1353a125fed98696649"
        elif cc == country_code.CountryCode.TW:
            key = "313d9858a7fb939def1d7d859629087d"
            iv = "0e3743eb53bf5944d1ae7e10c2e54bdf"
        else:
            raise Exception("Unknown country code")
        enable = not game_data.pack.PackFile.is_image_data_local_pack(pack_name)
        if game_data.pack.PackFile.is_server_pack(pack_name):
            aes_mode = AES.MODE_ECB
            key = (
                Hash(HashAlgorithm.MD5).get_hash(io.data.Data("battlecats"), 8).to_hex()
            )
            return AesCipher(key.encode("utf-8"), None, aes_mode, enable)
        else:
            return AesCipher(bytes.fromhex(key), bytes.fromhex(iv), aes_mode, enable)


class Hmac:
    """A class to do HMAC stuff."""

    def __init__(self, key: "io.data.Data", algorithm: HashAlgorithm):
        """Initializes a new instance of the Hmac class.

        Args:
            key (io.data.Data): Key to use.
            algorithm (HashAlgorithm): Algorithm to use.
        """
        self.key = key
        self.algorithm = algorithm

    def get_hmac(self, data: "io.data.Data") -> "io.data.Data":
        """Gets the HMAC of the given data.

        Args:
            data (io.data.Data): The data to get the HMAC of.

        Raises:
            ValueError: Invalid hash algorithm.

        Returns:
            io.data.Data: The HMAC.
        """
        if self.algorithm == HashAlgorithm.MD5:
            hash = hashlib.md5
        elif self.algorithm == HashAlgorithm.SHA1:
            hash = hashlib.sha1
        elif self.algorithm == HashAlgorithm.SHA256:
            hash = hashlib.sha256
        else:
            raise ValueError("Invalid hash algorithm")
        return io.data.Data(
            hmac.new(self.key.to_bytes(), data.get_bytes(), hash).digest()
        )


class Random:
    """A class to get random data"""

    @staticmethod
    def get_bytes(length: int) -> bytes:
        """Gets random bytes.

        Args:
            length (int): The length of the bytes.

        Returns:
            bytes: The random bytes.
        """
        return bytes(random.getrandbits(8) for _ in range(length))

    @staticmethod
    def get_alpha_string(length: int) -> str:
        """Gets a random string of the given length.

        Args:
            length (int): The length of the string.

        Returns:
            str: The random string.
        """
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join(random.choice(characters) for _ in range(length))
