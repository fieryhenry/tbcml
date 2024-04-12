"""Module for handling game server stuff"""

from __future__ import annotations

import base64
import datetime
import json
import time
from typing import Any

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import tbcml


class GameVersionSearchError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class ServerFileHandler:
    """Class for handling downloading game files from the game server"""

    def __init__(self, apk: tbcml.Pkg, lang: tbcml.Language | None):
        """Initializes the ServerFileHandler class

        Args:
            apk (tbcml.Apk): The APK object to use, used for country code and game version list
        """
        self.apk = apk
        self.lang = lang
        self.tsv_paths = self.apk.get_download_tsvs(lang=lang)
        if lang is not None:
            self.tsv_paths_all = self.apk.get_all_download_tsvs()
        self.game_versions = self.find_game_versions()
        self.tsvs: dict[int, tbcml.CSV] = {}
        self.file_map = self.create_file_map()

    def parse_tsv(self, index: int) -> tbcml.CSV:
        """Parses a TSV file from the APK

        Args:
            index (int): The index of the TSV file to parse

        Raises:
            ValueError: If the index is invalid

        Returns:
            tbcml.CSV: The parsed TSV file
        """
        if index >= len(self.tsv_paths) or index < 0:
            raise ValueError("Invalid TSV index")
        if index in self.tsvs:
            return self.tsvs[index]
        tsv_path = self.tsv_paths[index]
        tsv = tbcml.CSV(tsv_path.read(), delimeter="\t")
        self.tsvs[index] = tsv
        return tsv

    def create_file_map(self) -> dict[str, int]:
        """Creates a file map for the server files

        Returns:
            dict[str, int]: The file map. Key is the file name, value is the index of the tsv file that contains the file
        """
        tsvs = self.parse_tsvs()
        file_map: dict[str, int] = {}
        for i in range(len(tsvs)):
            tsv = tsvs[i]
            for row in tsv:
                name = row[0].strip()
                if not self.is_valid_name(name):
                    continue
                file_map[name] = i
        return file_map

    def parse_tsvs(self) -> dict[int, tbcml.CSV]:
        """Parses all TSV files from the APK

        Returns:
            dict[int, tbcml.CSV]: The parsed TSV files
        """
        for i in range(len(self.tsv_paths)):
            self.parse_tsv(i)
        return self.tsvs

    def get_game_version(self, index: int) -> int:
        """Gets the game version from the libnative.so file

        Args:
            index (int): The index of the game version to get, aligns with the TSV file

        Raises:
            ValueError: If the index is invalid

        Returns:
            int: The game version
        """
        if index >= len(self.game_versions) or index < 0:
            raise ValueError("Invalid index")
        return self.game_versions[index]

    def get_url(self, index: int) -> str:
        """Gets the download URL for a game version, code taken from the game but some stuff that is seamingly unused has been removed

        Args:
            index (int): The index of the game version to get

        Returns:
            str: The download URL
        """
        game_version = self.get_game_version(index)
        project_name = f"battlecats{self.apk.country_code.get_patching_code()}"
        str_code = ""
        if game_version < 1000000:
            str_code = project_name + "_" + str(game_version) + "_" + str(index)
        else:
            str_code = "%s_%06d_%02d_%02d" % (
                project_name,
                game_version // 100,
                index,
                game_version % 100,
            )

        if self.lang is not None:
            str_code += f"_{self.lang.value}"

        url = f"https://nyanko-assets.ponosgames.com/iphone/{project_name}/download/{str_code}.zip"
        return url

    def download(
        self,
        index: int,
        display: bool = False,
    ) -> tbcml.Zip:
        """Downloads game files from the server for a given game version

        Args:
            index (int): The index of the game version to download

        Raises:
            ValueError: If the zip data is invalid

        Returns:
            tbcml.Zip: The downloaded game files
        """
        url = self.get_url(index)
        cloudfront = CloudFront()
        signed_cookie = cloudfront.generate_signed_cookie(
            "https://nyanko-assets.ponosgames.com/*"
        )
        headers = {
            "accept-encoding": "gzip",
            "connection": "keep-alive",
            "cookie": signed_cookie,
            "range": "bytes=0-",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; Pixel 2 Build/PQ3A.190801.002)",
        }
        req = tbcml.RequestHandler(url, headers=headers)
        if display:
            stream: requests.Response = req.get_stream()
            total = int(stream.headers.get("content-length", 0))
            downloaded = 0
            content_ls: list[bytes] = []
            for chunk in stream.iter_content(chunk_size=1024):
                if chunk:
                    content_ls.append(chunk)
                    downloaded += len(chunk)
                    bytes_readable = tbcml.RequestHandler.sizeof_fmt(downloaded)
                    total_readable = tbcml.RequestHandler.sizeof_fmt(total)

                    print(
                        f"Downloaded {bytes_readable}/{total_readable} bytes",
                        end="      \r",
                    )
            print()
            print()
            content = b"".join(content_ls)
        else:
            stream = req.get()
            content = stream.content
        zipf = tbcml.Zip(tbcml.Data(content))
        return zipf

    @staticmethod
    def is_valid_name(name: str) -> bool:
        """Checks if a given name is valid

        Args:
            name (str): The name to check

        Returns:
            bool: Whether the name is valid
        """
        if not name or ord(name[0]) == 65279 or name.isdigit():
            return False
        return True

    @staticmethod
    def get_server_metadata_path() -> tbcml.Path:
        return tbcml.Path.get_documents_folder().add("server_latest.json")

    @staticmethod
    def get_server_metadata() -> dict[str, Any]:
        path = ServerFileHandler.get_server_metadata_path()
        if not path.exists():
            path.write(tbcml.Data("{}"))
        data = path.read()
        return tbcml.JsonFile(data).get_json()

    def get_latest_local_server_versions(self) -> list[int] | None:
        v: list[int] | dict[str, list[int]] | None = self.get_server_metadata().get(
            self.apk.country_code.get_code()
        )
        if v is None:
            return None
        lang_str = self.get_lang_str()
        if lang_str is not None:
            if not isinstance(v, dict):
                return None
            return v.get(lang_str)
        if not isinstance(v, list):
            return None
        return v

    def get_lang_str(self) -> str | None:
        if self.apk.country_code == tbcml.CountryCode.EN:
            lang = "en" if self.lang is None else self.lang.value
            return lang
        return None

    def set_latest_local_server_versions(self, versions: list[int]):
        dt = self.get_server_metadata()
        lang_str = self.get_lang_str()
        val = dt.get(self.apk.country_code.get_code())
        if lang_str is not None:
            if val is None or isinstance(val, int):
                val = {}
            val[lang_str] = versions
        else:
            val = versions
        dt[self.apk.country_code.get_code()] = val
        self.set_server_metadata(dt)

    def add_latest_local_server_version(self, version: int):
        versions = self.get_latest_local_server_versions()
        if versions is None:
            versions = []
        if version in versions:
            return
        versions.append(version)
        self.set_latest_local_server_versions(versions)

    def reset_latest_local_server_version(self):
        self.set_latest_local_server_versions([])

    @staticmethod
    def set_server_metadata(data: dict[str, Any]):
        path = ServerFileHandler.get_server_metadata_path()
        tbcml.JsonFile.from_object(data).to_data().to_file(path)

    def needs_extracting(
        self,
        index: int,
        force: bool = False,
    ) -> bool:
        """Extracts game files to the server files path for a given game version

        Args:
            index (int): The index of the game version to extract
            force (bool, optional): Whether to force download even if the files already exist. Defaults to False.

        Returns:
            bool: Whether the files were extracted
        """
        tsv = self.parse_tsv(index)
        if not force:
            found = True
            hashes_equal = True
            for row in tsv:
                name = row[0].strip()
                if not self.is_valid_name(name):
                    continue
                if name not in self.file_map:
                    found = False
                    break
                if self.file_map[name] != index:
                    continue
                path = self.apk.get_server_path().add(name)
                if not path.exists():
                    found = False
                    break
                md5_hash = row[2].strip()
                file_hash = (
                    tbcml.Hash(tbcml.HashAlgorithm.MD5).get_hash(path.read()).to_hex()
                )
                if md5_hash != file_hash:
                    hashes_equal = False
                    break

            if found and hashes_equal:
                return False

        return True

    def extract_all(
        self,
        force: bool = False,
        display: bool = False,
    ) -> tbcml.Result:
        """Extracts all game versions

        Args:
            force (bool, optional): Whether to force extraction even if the files already exist. Defaults to False.
            display (bool, optional): Whether to display text with the current download progress. Defualts to False.
        """
        versions = self.get_latest_local_server_versions()
        if versions is None:
            versions = []
        to_extract: list[int] = []
        for i in range(len(self.tsv_paths)):
            if not force and i in versions:
                continue
            if self.needs_extracting(i, force):
                to_extract.append(i)
            else:
                self.add_latest_local_server_version(i)

        for i, index in enumerate(to_extract):
            if display:
                print(
                    f"Downloading server zip file {i+1}/{len(to_extract)} (id {index})"
                )
            self.extract(index, display)
            self.add_latest_local_server_version(index)

        return tbcml.Result(True)

    def extract(self, index: int, display: bool = False):
        zipf = self.download(index, display)
        path = self.apk.get_server_path()
        zipf.extract(path)

    def find_game_versions(self) -> list[int]:
        """Finds all game versions in the libnative.so file

        Raises:
            ValueError: If the libnative.so file could not be found
            ValueError: If the architecture could not be found
            ValueError: If the country code is not supported
            ValueError: If no game versions were found

        Returns:
            list[int]: A list of game versions
        """
        arcs = self.apk.get_architectures()
        lib = None
        arc = None
        for ac in arcs:
            lb = self.apk.get_native_lib_path(ac)
            if lb is not None and lb.exists():
                lib = lb
                arc = ac
                break
        if lib is None:
            raise GameVersionSearchError(
                "Could not find libnative.so. Maybe your game version is too to be supported atm"
            )
        if arc is None:
            raise GameVersionSearchError(
                "Could not find architecture. Maybe your game version is too to be supported atm"
            )
        lib_file = tbcml.Lib(arc, lib)
        if self.apk.country_code == tbcml.CountryCode.JP:
            list_to_search = [5, 5, 5, 7000000]
        elif self.apk.country_code == tbcml.CountryCode.EN:
            list_to_search = [3, 2, 2, 6100000]
        elif self.apk.country_code == tbcml.CountryCode.KR:
            list_to_search = [3, 2, 1, 6100000]
        elif self.apk.country_code == tbcml.CountryCode.TW:
            list_to_search = [2, 3, 1, 6100000]
        else:
            raise GameVersionSearchError(
                "Country code not supported. Maybe your game version is too to be supported atm"
            )
        start_index = lib_file.search(
            tbcml.Data.from_int_list(list_to_search, "little")
        )
        if start_index == -1:
            raise GameVersionSearchError(
                "Could not find game versions. Maybe your game version is too to be supported atm"
            )
        end_index1 = lib_file.search(
            tbcml.Data.from_int(0xFFFFFFFF, "little"), start=start_index
        )
        end_index2 = lib_file.search(
            tbcml.Data.from_int_list([0, 0, 0, 0], "little"), start=start_index
        )
        end_index = min(end_index1, end_index2)
        length = (end_index - start_index) // 4
        data = lib_file.read_int_list(start_index, length)

        if (
            self.apk.country_code != tbcml.CountryCode.EN
            or self.lang is None
            or len(data) <= len(self.tsv_paths)
        ):
            return data[: len(self.tsv_paths)]

        index = self.lang.get_index() + 1
        count = 0
        for i, tsvs in enumerate(self.tsv_paths_all):
            if i == index:
                break
            count += len(tsvs)
        return data[count : count + len(self.tsv_paths)]


class CloudFront:
    """A class for interacting with the game's CloudFront aws server for downloading game files"""

    def __init__(self):
        """Initializes the CloudFront class"""
        self.cf_key_pair_id = "APKAJO6MLYTURWB2NOWQ"
        self.cf_private_key = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCORX64nic2atwz
1VsqbI/jqHwrdrSktgjoBrFWqgziJXrVvHVZ+shhUfRxa4BKvdRigbZuNjrmFfUE
Scxdfj72QAe0SRxgMhaloPikbSUlvrfOacFOiQD7dMtwv8DAAjvshKU/qmzdkp1j
DC3QcIX5gsuNqUuM6SxPBZviuvxD/IsbLlxxUCh30hZNUb/3aTf00SzI1/rAL2jB
faQfR6FY2qt0yICoXaVwCu6GObJDPdMjX8ssCmTxRb81aAnfUy6A9x/ywutYjjaY
W2RA9hzWCxk6nONpuRQsZkEbNULoKzgyfxMc/xNfFYH+0T2ui59zsRVTNsCHYVEb
iz9an3HXAgMBAAECggEAGMPgGyLskHxpeFxbUjczlN1vP+GZ8FH/muQPWpafR35e
s3Xqt47/8nDhrByaaGhC4CLULrsh5YtM60ItYNjo/NSIgsl3NweBCbPLlFOrc7aP
KE8gZxtSIHNkNmwqkUHSTImKelqgOLGc0/D6yJ3NtHEgHbiqfgzYuaiwSfdikjLR
T5sRs7T5k0Gy67FSOOa43s4WHj77ywdcvYbzBdSM/uu8R2Syng4RijKCvKLIEIE0
3lPDI9/KNG8ofSyaqjLa09xfooQ7S8La21El3iu/icOowR0WM+hXLcEilCkuMFY1
IrheIsx2Pyb6N3qwE/jRMIqQwH5uzM8OThmU+17tgQKBgQDCwrR33GXg5SNvSg4N
iBsuV1p2sXeuJxZrSCyNUVaT7lg01dUnk9MbAflqNsD43mHdXWYLd8FqKZ4Fc3K/
t3sdYJPeOmMIKmBexhOnohoAwg4FZhuUvzhx6DPuBG2gSCzzGNjU9SXCr9TQlwkc
XTRIEjBe5JuFFhHGe+xMVEu+rQKBgQC7AasNilpc7lhXuNi/fXdJwqX+s3Jiolys
8BQJ83i1Xy7pzfa2usOjYLFcebcXv9lTfrDUW4ju1ip8zVVWkdF9xE9uRFDbSBJo
MvQNa9bGgFlLu/V5XsbCFbFrYqI94OHIT4/2dHJsyeJpoXpoFHZ2aGt/98fFEGqU
YbAdR/HXEwKBgQCPMEUshm6knPKjZKfWTQXm2TRaZXmfIX+7GlIfB/kGQ8q39aqE
MYuYpKfx7hWMIzuCW6OltMMPwU87pLhtuYEbhSDR1s1ueHFn3Gsg6O4DNqjGUV7f
yoK+REDBsqHCoK3jgJYSY7YCX/Gv9gstvlyszCqh6aNpgmNJMVz2dVdG9QKBgQCK
G2FITrUNjLiRkGICiZZfUvFkeQIw9deboHIsJzMuP21WHlXl/WgecHqL4Rfm4jiO
ATJ2omMuf9xA7yPnGymryB8hQDK2vzNY4Mh8YPftATzxQY64Y9ZF3993fxBywnH8
jUW0rasTzMT5XdgYpYQXTmaVy1gtoUIU81AtT8S7IQKBgQC2F7xdWSv7Pw+MimN2
Tx8VMiCUkL+5uNJwvWw2rrEHvt2jphD016pgdutlgI28qoXwcleLxAz1Ey1njCTO
19bsOA9bhuwbIrIb93nGHyRrQe1L7PdBjwlIqEj8R08Z/oGQsXhqzgF9KfO2V46i
oPSxLzYw2sBjmwVooXMVr6GxEw==
-----END PRIVATE KEY-----"""

    def make_policy(self, url: str) -> str:
        """Makes a policy for the given url

        Args:
            url (str): URL to make policy for

        Returns:
            str: Policy
        """
        policy = {
            "Statement": [
                {
                    "Resource": url,
                    "Condition": {
                        "DateLessThan": {
                            "AWS:EpochTime": int(time.time()) + 60 * 60,
                        },
                        "DateGreaterThan": {
                            "AWS:EpochTime": int(time.time()) - 60 * 60,
                        },
                    },
                }
            ]
        }
        return json.dumps(policy).replace(" ", "")

    def make_signature(self, message: str) -> bytes:
        """Makes a signature for the given message

        Args:
            message (str): Message to make signature for

        Returns:
            bytes: Signature
        """
        private_key = serialization.load_pem_private_key(
            self.cf_private_key.encode(), password=None, backend=default_backend()
        )
        return private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA1())  # type: ignore

    @staticmethod
    def aws_base64_encode(data: bytes) -> bytes:
        """Encodes data in base64

        Args:
            data (bytes): Data to encode

        Returns:
            bytes: Encoded data
        """
        return base64.b64encode(data)

    @staticmethod
    def aws_base64_decode(data: bytes) -> bytes:
        """Decodes data from base64

        Args:
            data (bytes): Data to decode

        Returns:
            bytes: Decoded data
        """
        return base64.b64decode(data)

    def generate_signature(self, policy: str) -> str:
        """Generates a signature for the given policy

        Args:
            policy (str): Policy to generate signature for

        Returns:
            str: Signature
        """
        signature = self.make_signature(policy)
        return self.aws_base64_encode(signature).decode()

    def generate_signed_cookie(self, url: str) -> str:
        """Generates a signed cookie for the given url

        Args:
            url (str): URL to generate signed cookie for

        Returns:
            str: Signed cookie
        """
        policy = self.make_policy(url)
        signature = self.generate_signature(policy)
        return f"CloudFront-Key-Pair-Id={self.cf_key_pair_id}; CloudFront-Policy={self.aws_base64_encode(policy.encode()).decode()}; CloudFront-Signature={signature}"


class EventData:
    """Class for downloading event data from the game server
    Lots of this code is taken from the PackPack discord bot: https://github.com/battlecatsultimate/PackPack
    """

    def __init__(
        self,
        file_name: str,
        cc: tbcml.CountryCode,
        gv: tbcml.GameVersion,
        use_old: bool = False,
    ):
        """Initializes the class

        Args:
            file_name (str): File to download
        """
        self.use_old = use_old
        self.aws_access_key_id = "AKIAJCUP3WWCHRJDTPPQ"
        self.aws_secret_access_key = "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"
        self.region = "ap-northeast-1"
        self.service = "s3"
        self.request = "aws4_request"
        self.algorithm = "AWS4-HMAC-SHA256"
        self.domain = "nyanko-events-prd.s3.ap-northeast-1.amazonaws.com"
        self.cc = cc
        self.gv = gv

        if not self.use_old:
            self.domain = "nyanko-events.ponosgames.com"

        self.url = f"https://{self.domain}/battlecats{self.cc.get_patching_code()}_production/{file_name}"

    def get_auth_header(self) -> str:
        """Gets the authorization header

        Returns:
            str: Authorization header
        """
        output = self.algorithm + " "
        output += f"Credential={self.aws_access_key_id}/{self.get_date()}/{self.region}/{self.service}/{self.request}, "
        output += "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        signature = self.get_signing_key(self.get_amz_date())
        output += f"Signature={signature.to_hex()}"

        return output

    def get_date(self) -> str:
        """Gets the date

        Returns:
            str: Date in YYYYMMDD format
        """
        return datetime.datetime.now(datetime.UTC).strftime("%Y%m%d")

    def get_amz_date(self) -> str:
        """Gets the amz date

        Returns:
            str: Date in YYYYMMDDTHHMMSSZ format
        """
        return datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")

    def get_signing_key(self, amz: str) -> tbcml.Data:
        """Gets the signing key for the given amz date

        Args:
            amz (str): Amz date

        Returns:
            tbcml.Data: Signing key
        """
        k = tbcml.Data("AWS4" + self.aws_secret_access_key)
        k_date = self.hmacsha256(k, self.get_date())
        date_region_key = self.hmacsha256(k_date, self.region)
        date_region_service_key = self.hmacsha256(date_region_key, self.service)
        signing_key = self.hmacsha256(date_region_service_key, self.request)

        string_to_sign = self.get_string_to_sign(amz)

        final = self.hmacsha256(signing_key, string_to_sign)
        return final

    def hmacsha256(self, key: tbcml.Data, message: str) -> tbcml.Data:
        """Gets the hmacsha256 of the given key and message

        Args:
            key (tbcml.Data): Key
            message (str): Message

        Returns:
            tbcml.Data: Hmacsha256 of the given key and message
        """
        return tbcml.Hmac(key, tbcml.HashAlgorithm.SHA256).get_hmac(tbcml.Data(message))

    def get_string_to_sign(self, amz: str) -> str:
        """Gets the string to sign for the given amz date

        Args:
            amz (str): Amz date

        Returns:
            str: String to sign
        """
        output = self.algorithm + "\n"
        output += amz + "\n"
        output += (
            self.get_date()
            + "/"
            + self.region
            + "/"
            + self.service
            + "/"
            + self.request
            + "\n"
        )
        request = self.get_canonical_request(amz)
        output += (
            tbcml.Hash(tbcml.HashAlgorithm.SHA256)
            .get_hash(tbcml.Data(request))
            .to_hex()
        )
        return output

    def get_canonical_request(self, amz: str) -> str:
        """Gets the canonical request for the given amz date

        Args:
            amz (str): Amz date

        Returns:
            str: Canonical request
        """
        output = "GET\n"
        output += self.get_canonical_uri() + "\n" + "\n"
        output += "host:" + self.domain + "\n"
        output += "x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
        output += "x-amz-date:" + amz + "\n"
        output += "\n"
        output += "host;x-amz-content-sha256;x-amz-date\n"
        output += "UNSIGNED-PAYLOAD"
        return output

    def get_canonical_uri(self) -> str:
        """Gets the canonical uri for the current url

        Returns:
            str: Canonical uri, e.g. /battlecatsen_production/...
        """
        return self.url.split(self.domain)[1]

    def get_inquiry_code(self) -> str:
        url = "https://nyanko-backups.ponosgames.com/?action=createAccount&referenceId="
        return tbcml.request.RequestHandler(url).get().json()["accountId"]

    def generate_signature(self, iq: str, data: str) -> str:
        """Generates a signature from the inquiry code and data.

        Returns:
            str: The signature.
        """
        random_data = tbcml.Random.get_hex_string(64)
        key = iq + random_data
        hmac = tbcml.Hmac(tbcml.Data(key), tbcml.HashAlgorithm.SHA256)
        signature = hmac.get_hmac(tbcml.Data(data))

        return random_data + signature.to_hex()

    def get_headers(self, iq: str, data: str) -> dict[str, str]:
        return {
            "accept-enconding": "gzip",
            "connection": "keep-alive",
            "content-type": "application/json",
            "nyanko-signature": self.generate_signature(iq, data),
            "nyanko-timestamp": str(int(time.time())),
            "nyanko-signature-version": "1",
            "nyanko-signature-algorithm": "HMACSHA256",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G955F Build/N2G48B)",
        }

    def get_password(self, inquiry_code: str) -> str:
        url = "https://nyanko-auth.ponosgames.com/v1/users"
        data = {
            "accountCode": inquiry_code,
            "accountCreatedAt": str(int(time.time())),
            "nonce": tbcml.Random.get_hex_string(32),
        }
        data = tbcml.JsonFile.from_object(data).to_data_request()
        headers = self.get_headers(inquiry_code, data.to_str())
        response = tbcml.RequestHandler(url, headers=headers, data=data).post()
        json_data: dict[str, Any] = response.json()
        payload = json_data.get("payload", {})
        password = payload.get("password", "")
        return password

    def get_client_info(self) -> dict[str, Any]:
        country_code = self.cc
        data = {
            "clientInfo": {
                "client": {
                    "countryCode": country_code.get_request_code(),
                    "version": self.gv.game_version,
                },
                "device": {
                    "model": "SM-G955F",
                },
                "os": {
                    "type": "android",
                    "version": "9",
                },
            },
            "nonce": tbcml.Random.get_hex_string(32),
        }
        return data

    def get_token(self) -> str:
        inquiry_code = self.get_inquiry_code()
        password = self.get_password(inquiry_code)
        url = "https://nyanko-auth.ponosgames.com/v1/tokens"
        data = self.get_client_info()
        data["password"] = password
        data["accountCode"] = inquiry_code
        data = tbcml.JsonFile.from_object(data).to_data_request()
        headers = self.get_headers(inquiry_code, data.to_str())
        response = tbcml.RequestHandler(url, headers=headers, data=data).post()
        json_data: dict[str, Any] = response.json()
        payload = json_data.get("payload", {})
        token = payload.get("token", "")
        return token

    def make_request(self) -> "requests.Response":
        """Makes the request to download the event data

        Returns:
            request.requests.Response: Response
        """
        url = self.url
        headers = {
            "accept-encoding": "gzip",
            "connection": "keep-alive",
            "host": self.domain,
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; Pixel 2 Build/PQ3A.190801.002)",
        }
        if self.use_old:
            headers["authorization"] = self.get_auth_header()
            headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
            headers["x-amz-date"] = self.get_amz_date()
        else:
            url += "?jwt=" + self.get_token()

        return tbcml.RequestHandler(url, headers=headers).get()
