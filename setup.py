import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("src/tbcml/files/version.txt", "r", encoding="utf-8") as fh:
    version = fh.read()

setuptools.setup(
    name="tbcml",
    version=version,
    author="fieryhenry",
    description="A mod loader for The Battle Cats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fieryhenry/TBCModLoader",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "beautifulsoup4",
        "cloudscraper",
        "cryptography",
        "ffmpeg-python",
        "lief",
        "Pillow",
        "pycryptodomex",
        "PyYAML",
        "requests",
        "PyQt5",
        "androguard",
        "qtawesome",
    ],
    include_package_data=True,
    extras_require={
        "testing": [
            "pytest",
            "pytest-cov",
        ],
    },
    package_data={"tbcml": ["py.typed"]},
)
