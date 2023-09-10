from typing import Any, Optional

from PIL import Image, ImageDraw
from PyQt5.QtGui import QImage, QIcon, QPixmap

from tbcml import core


class BCImage:
    def __init__(self, dt: Optional["core.Data"] = None):
        if not dt:
            self.data = core.Data()
        else:
            self.data = dt
        self.__image: Optional[Image.Image] = None
        self._qimg: Optional[QImage] = None
        self.__original_data = self.data.copy()
        self.__original_img: Optional[Image.Image] = None

    @property
    def image(self) -> Image.Image:
        if not self.__image:
            if self.data.is_empty():
                self.__image = Image.new("RGBA", (1, 1))
            else:
                self.__image = Image.open(self.data.to_bytes_io())
            self.__original_img = self.__image.copy()
            self.__original_data = self.data.copy()
        if self.__original_img is None:
            self.__original_img = self.__image.copy()
        return self.__image

    def copy(self):
        data = self.to_data()
        return BCImage(data)

    @staticmethod
    def create_empty():
        return BCImage(core.Data())

    def is_empty(self):
        return self.data.is_empty()

    @property
    def width(self):
        return self.image.width

    @property
    def height(self):
        return self.image.height

    @staticmethod
    def from_size(width: int, height: int):
        image = Image.new("RGBA", (width, height))
        image_data = core.Data()
        bytes_io = image_data.to_bytes_io()
        image.save(bytes_io, format="PNG")
        return BCImage(core.Data(bytes_io.getvalue()))

    def crop_rect(self, x1: int, y1: int, x2: int, y2: int) -> "BCImage":
        dt = self.image.crop((x1, y1, x2, y2))
        image_data = core.Data()
        bytes_io = image_data.to_bytes_io()
        dt.save(bytes_io, format="PNG")
        return BCImage(core.Data(bytes_io.getvalue()))

    def get_subimage(self, rect: "core.Rect") -> "BCImage":
        return self.crop_rect(rect.x, rect.y, rect.x + rect.width, rect.y + rect.height)

    def __len__(self):
        return len(self.data)

    def scale_x(self, scale: float):
        if scale < 0:
            self.flip_x()
            scale *= -1
        self.__image = self.image.resize(
            (int(self.width * scale), self.height), resample=Image.BICUBIC
        )

    def scale_y(self, scale: float):
        if scale < 0:
            self.flip_y()
            scale *= -1
        self.__image = self.image.resize(
            (self.width, int(self.height * scale)), resample=Image.BICUBIC
        )

    def scale(self, scale_x: float, scale_y: float):
        self.scale_x(scale_x)
        self.scale_y(scale_y)

    def flip_x(self):
        self.__image = self.image.transpose(Image.FLIP_LEFT_RIGHT)

    def flip_y(self):
        self.__image = self.image.transpose(Image.FLIP_TOP_BOTTOM)

    def add_image(self, image: "BCImage", x: int, y: int):
        self.image.paste(image.image, (x, y), image.image)

    def save(self, path: "core.Path"):
        self.image.save(path.to_str(), format="PNG")

    def to_data(self):
        if self.image.tobytes() == self.__original_img.tobytes() and len(self.data) > 0:  # type: ignore
            return self.__original_data
        bytes_io = core.Data().to_bytes_io()
        self.image.save(bytes_io, format="PNG")
        return core.Data(bytes_io.getvalue())

    @staticmethod
    def from_base_64(base_64: str) -> "BCImage":
        return BCImage(core.Data.from_base_64(base_64))

    def to_base_64(self) -> str:
        return self.to_data().to_base_64()

    def apply_dict(self, dt: dict[str, Any]):
        self.data = core.Data.from_base_64(dt["__image__"])
        self.__image = None

    def to_dict(self) -> dict[str, Any]:
        return {"__image__": self.to_base_64()}

    def paste(self, image: "BCImage", x: int, y: int):
        self.image.paste(image.image, (x, y), image.image)

    def paste_rect(self, image: "BCImage", rect: "core.Rect"):
        self.image.paste(
            image.image,
            (rect.x, rect.y, rect.x + rect.width, rect.y + rect.height),
            image.image,
        )

    def putpixel(self, x: int, y: int, color: tuple[int, int, int, int]):
        self.image.putpixel((x, y), color)

    def fix_libpng_warning(self):
        """Fixes the libpng warning: iCCP: known incorrect sRGB profile"""

        if "icc_profile" in self.image.info:
            del self.image.info["icc_profile"]

        return self

    def to_qimage(self) -> QImage:
        if self._qimg:
            return self._qimg
        self._qimg = QImage.fromData(self.to_data().to_bytes())
        return self._qimg

    def to_qicon(self) -> QIcon:
        return QIcon(QPixmap.fromImage(self.to_qimage()))

    def force_q_refresh(self):
        self._qimg = None

    def force_refresh(self):
        self.__image = None
        self.force_q_refresh()

    def crop_circle(self):
        if self.width != self.height:
            raise ValueError("Image must be square")
        mask = Image.new("L", self.image.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, self.width, self.height), fill=255)
        self.image.putalpha(mask)
