import base64
import json
import time
from typing import Optional, Callable
from bcml.core import io, request, country_code

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class ServerFileHandler:
    def __init__(self, apk: "io.apk.Apk"):
        self.apk = apk
        self.tsv_paths = self.apk.get_download_tsvs()
        self.game_versions = self.find_game_versions()

    def parse_tsv(self, index: int) -> "io.bc_csv.CSV":
        if index >= len(self.tsv_paths) or index < 0:
            raise ValueError("Invalid TSV index")
        tsv_path = self.tsv_paths[index]
        tsv = io.bc_csv.CSV(tsv_path.read(), delimeter="\t")
        return tsv

    def get_game_version(self, index: int) -> int:
        if index >= len(self.game_versions) or index < 0:
            raise ValueError("Invalid TSV index")
        return self.game_versions[index]

    def get_url(self, index: int):
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
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> "io.zip.Zip":
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
        req = request.RequestHandler(url, headers=headers)
        if progress_callback is None:
            resp = req.get()
        else:
            resp = req.get_stream_no_file_size(progress_callback)
        data = resp.content
        try:
            zipf = io.zip.Zip(io.data.Data(data))
        except Exception:
            raise ValueError("Invalid zip data")
        return zipf

    def extract(
        self,
        index: int,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
        force: bool = False,
    ) -> bool:
        tsv = self.parse_tsv(index)
        if not force:
            found = True
            for row in tsv:
                name = row[0].to_str().strip()
                if not name or ord(name[0]) == 65279 or name.isdigit():
                    continue
                path = io.apk.Apk.get_server_path(self.apk.country_code).add(name)
                if not path.exists():
                    found = False

            if found:
                return False
        zipf = self.download(index, progress_callback)
        path = io.apk.Apk.get_server_path(self.apk.country_code)
        zipf.extract(path)
        return True

    def extract_all(
        self,
        progress_callback_individual: Optional[
            Callable[[float, int, int], None]
        ] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        force: bool = False,
    ):
        if progress_callback:
            progress_callback(0, len(self.tsv_paths))
        for i in range(len(self.tsv_paths)):
            if progress_callback_individual:
                progress_callback_individual(0, 0, 0)
            self.extract(i, progress_callback_individual, force)
            if progress_callback is not None:
                progress_callback(i + 1, len(self.tsv_paths))

    def find_game_versions(self):
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
        lib_file = io.lib.Lib(arc, lib)
        if self.apk.country_code == country_code.CountryCode.JP:
            list_to_search = [5, 5, 5, 7000000]
        elif self.apk.country_code == country_code.CountryCode.EN:
            list_to_search = [3, 2, 2, 6100000]
        elif self.apk.country_code == country_code.CountryCode.KR:
            list_to_search = [3, 2, 1, 6100000]
        elif self.apk.country_code == country_code.CountryCode.TW:
            list_to_search = [2, 3, 1, 6100000]
        else:
            raise ValueError("Unknown country code")
        start_index = lib_file.search(
            io.data.Data.from_int_list(list_to_search, "little")
        )
        if start_index == -1:
            raise ValueError("Could not find game version")
        length = len(self.tsv_paths)
        data = lib_file.read_int_list(start_index, length)
        return data


class CloudFront:
    def __init__(self):
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

    def make_policy(self, url: str):
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

    def make_signature(self, message: str):
        private_key = serialization.load_pem_private_key(
            self.cf_private_key.encode(), password=None, backend=default_backend()
        )
        return private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA1())

    @staticmethod
    def aws_base64_encode(data: bytes):
        return base64.b64encode(data)

    @staticmethod
    def aws_base64_decode(data: bytes):
        return base64.b64decode(data)

    def generate_signature(self, policy: str):
        signature = self.make_signature(policy)
        return self.aws_base64_encode(signature).decode()

    def generate_signed_cookie(self, url: str):
        policy = self.make_policy(url)
        signature = self.generate_signature(policy)
        return f"CloudFront-Key-Pair-Id={self.cf_key_pair_id}; CloudFront-Policy={self.aws_base64_encode(policy.encode()).decode()}; CloudFront-Signature={signature}"
