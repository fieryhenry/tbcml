import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("src/bcml/files/version.txt", "r", encoding="utf-8") as fh:
    version = fh.read()

setuptools.setup(
    name="bcml",
    version=version,
    author="fieryhenry",
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fieryhenry/bcml",
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
        "numpy",
        "opencv-python-headless",
        "Pillow",
        "pycryptodomex",
        "PyYAML",
        "requests",
        "PyQt5",
    ],
    include_package_data=True,
    extras_require={
        "testing": [
            "pytest",
            "pytest-cov",
        ],
    },
    package_data={"bcml": ["py.typed"]},
    flake8={"max-line-length": 160},
)
