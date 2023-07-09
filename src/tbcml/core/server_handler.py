"""Module for handling game server stuff"""
import base64
import datetime
import json
import time
from typing import Any

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from tbcml import core


class ServerFileHandler:
    """Class for handling downloading game files from the game server"""

    def __init__(self, apk: "core.Apk"):
        """Initializes the ServerFileHandler class

        Args:
            apk (core.Apk): The APK object to use, used for country code and game version list
        """
        self.apk = apk
        self.tsv_paths = self.apk.get_download_tsvs()
        self.game_versions = self.find_game_versions()

    def parse_tsv(self, index: int) -> "core.CSV":
        """Parses a TSV file from the APK

        Args:
            index (int): The index of the TSV file to parse

        Raises:
            ValueError: If the index is invalid

        Returns:
            core.CSV: The parsed TSV file
        """
        if index >= len(self.tsv_paths) or index < 0:
            raise ValueError("Invalid TSV index")
        tsv_path = self.tsv_paths[index]
        tsv = core.CSV(tsv_path.read(), delimeter="\t")
        return tsv

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

        url = f"https://nyanko-assets.ponosgames.com/iphone/{project_name}/download/{str_code}.zip"
        return url

    def download(
        self,
        index: int,
    ) -> "core.Zip":
        """Downloads game files from the server for a given game version

        Args:
            index (int): The index of the game version to download

        Raises:
            ValueError: If the zip data is invalid

        Returns:
            core.Zip: The downloaded game files
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
        req = core.RequestHandler(url, headers=headers)
        resp = req.get()
        data = resp.content
        try:
            zipf = core.Zip(core.Data(data))
        except Exception as exc:
            raise ValueError("Invalid zip data") from exc
        return zipf

    def extract(
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
            hashes_equal = False
            for row in tsv:
                name = row[0].strip()
                if not name or ord(name[0]) == 65279 or name.isdigit():
                    continue
                path = core.Apk.get_server_path(self.apk.country_code).add(name)
                if not path.exists():
                    found = False
                    break
                md5_hash = row[2].strip()
                file_hash = (
                    core.Hash(core.HashAlgorithm.MD5).get_hash(path.read()).to_hex()
                )
                if md5_hash == file_hash:
                    hashes_equal = True
                    break

            if found and hashes_equal:
                return False
        zipf = self.download(index)
        path = core.Apk.get_server_path(self.apk.country_code)
        zipf.extract(path)
        return True

    def extract_all(
        self,
        force: bool = False,
    ):
        """Extracts all game versions

        Args:
            force (bool, optional): Whether to force extraction even if the files already exist. Defaults to False.
        """
        for i in range(len(self.tsv_paths)):
            self.extract(i, force)

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
            lb = self.apk.get_libnative_path(ac)
            if lb.exists():
                lib = lb
                arc = ac
                break
        if lib is None:
            raise ValueError("Could not find libnative.so")
        if arc is None:
            raise ValueError("Could not find architecture")
        lib_file = core.Lib(arc, lib)
        if self.apk.country_code == core.CountryCode.JP:
            list_to_search = [5, 5, 5, 7000000]
        elif self.apk.country_code == core.CountryCode.EN:
            list_to_search = [3, 2, 2, 6100000]
        elif self.apk.country_code == core.CountryCode.KR:
            list_to_search = [3, 2, 1, 6100000]
        elif self.apk.country_code == core.CountryCode.TW:
            list_to_search = [2, 3, 1, 6100000]
        else:
            raise ValueError("Unknown country code")
        start_index = lib_file.search(core.Data.from_int_list(list_to_search, "little"))
        if start_index == -1:
            raise ValueError("Could not find game version")
        length = len(self.tsv_paths)
        data = lib_file.read_int_list(start_index, length)
        return data


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
        cc: "core.CountryCode",
        gv: "core.GameVersion",
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
        return datetime.datetime.utcnow().strftime("%Y%m%d")

    def get_amz_date(self) -> str:
        """Gets the amz date

        Returns:
            str: Date in YYYYMMDDTHHMMSSZ format
        """
        return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    def get_signing_key(self, amz: str) -> "core.Data":
        """Gets the signing key for the given amz date

        Args:
            amz (str): Amz date

        Returns:
            core.Data: Signing key
        """
        k = core.Data("AWS4" + self.aws_secret_access_key)
        k_date = self.hmacsha256(k, self.get_date())
        date_region_key = self.hmacsha256(k_date, self.region)
        date_region_service_key = self.hmacsha256(date_region_key, self.service)
        signing_key = self.hmacsha256(date_region_service_key, self.request)

        string_to_sign = self.get_string_to_sign(amz)

        final = self.hmacsha256(signing_key, string_to_sign)
        return final

    def hmacsha256(self, key: "core.Data", message: str) -> "core.Data":
        """Gets the hmacsha256 of the given key and message

        Args:
            key (core.Data): Key
            message (str): Message

        Returns:
            core.Data: Hmacsha256 of the given key and message
        """
        return core.Hmac(key, core.HashAlgorithm.SHA256).get_hmac(core.Data(message))

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
            core.Hash(core.HashAlgorithm.SHA256).get_hash(core.Data(request)).to_hex()
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
        return core.request.RequestHandler(url).get().json()["accountId"]

    def generate_signature(self, iq: str, data: str) -> str:
        """Generates a signature from the inquiry code and data.

        Returns:
            str: The signature.
        """
        random_data = core.Random.get_hex_string(64)
        key = iq + random_data
        hmac = core.Hmac(core.Data(key), core.HashAlgorithm.SHA256)
        signature = hmac.get_hmac(core.Data(data))

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
            "nonce": core.Random.get_hex_string(32),
        }
        data = core.JsonFile.from_object(data).to_data_request()
        headers = self.get_headers(inquiry_code, data.to_str())
        response = core.RequestHandler(url, headers=headers, data=data).post()
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
            "nonce": core.Random.get_hex_string(32),
        }
        return data

    def get_token(self) -> str:
        inquiry_code = self.get_inquiry_code()
        password = self.get_password(inquiry_code)
        url = "https://nyanko-auth.ponosgames.com/v1/tokens"
        data = self.get_client_info()
        data["password"] = password
        data["accountCode"] = inquiry_code
        data = core.JsonFile.from_object(data).to_data_request()
        headers = self.get_headers(inquiry_code, data.to_str())
        response = core.RequestHandler(url, headers=headers, data=data).post()
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

        return core.RequestHandler(url, headers=headers).get()
