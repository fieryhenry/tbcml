from typing import Any, Optional
from bcml.core.io import data, path
from PIL import Image, ImageDraw

import cv2
import numpy as np


class BCImage:
    def __init__(self, dt: Optional["data.Data"] = None):
        if not dt:
            self.data = data.Data()
        else:
            self.data = dt
        self.__image: Optional[Image.Image] = None

    @property
    def image(self) -> Image.Image:
        if not self.__image:
            if self.data.is_empty():
                self.__image = Image.new("RGBA", (1, 1))
            else:
                self.__image = Image.open(self.data.to_bytes_io())
        return self.__image

    def copy(self):
        return BCImage(self.data.copy())

    @staticmethod
    def create_empty():
        return BCImage(data.Data())

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
        image = BCImage(data.Data())
        image.__image = Image.new("RGBA", (width, height))
        return image

    def crop(self, x1: int, y1: int, x2: int, y2: int):
        dt = self.image.crop((x1, y1, x2, y2))
        image_data = data.Data()
        bytes_io = image_data.to_bytes_io()
        dt.save(bytes_io, format="PNG")
        return BCImage(data.Data(bytes_io.getvalue()))

    def __len__(self):
        return len(self.data)

    def scale_x(self, scale: float):
        if scale < 0:
            self.flip_x()
            scale *= -1
        self.__image = self.image.resize((int(self.width * scale), self.height))

    def scale_y(self, scale: float):
        if scale < 0:
            self.flip_y()
            scale *= -1
        self.__image = self.image.resize((self.width, int(self.height * scale)))

    def scale(self, scale: float):
        self.__image = self.image.resize(
            (int(self.width * scale), int(self.height * scale)), resample=Image.BICUBIC
        )

    def flip_x(self):
        self.__image = self.image.transpose(Image.FLIP_LEFT_RIGHT)

    def flip_y(self):
        self.__image = self.image.transpose(Image.FLIP_TOP_BOTTOM)

    def rotate(self, angle: float, center: tuple[int, int]):
        # self.extend_image_transparent(self.width * 2, self.height * 2)
        self.draw_circle(center[0], center[1], 10, (255, 0, 0, 255))
        print(angle)
        self.save(path.Path(f"test{angle}.png"))
        # self.image = self.image.rotate(angle, expand=False, center=center, resample=Image.BICUBIC)
        # self.update()
        # self.save(path.Path(f"test_after{angle}.png"))

    def draw_circle(
        self, x: int, y: int, radius: int, color: tuple[int, int, int, int]
    ):
        self.__image = self.image.convert("RGBA")
        draw = ImageDraw.Draw(self.image)
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)

    def extend_image_transparent(self, width: int, height: int):
        new_image = Image.new("RGBA", (width, height))
        center = (self.width // 2, self.height // 2)
        new_image.paste(self.image, center)
        self.__image = new_image

    def move(self, x: int, y: int):
        self.__image = self.image.crop((x, y, x + self.width, y + self.height))

    def set_opacity(self, opacity: float):
        # set opacity without making the background black
        im2 = self.image.copy()
        im2.putalpha(int(255 * opacity))
        self.image.paste(im2, self.image)  # type: ignore

    def add_image(self, image: "BCImage", x: int, y: int):
        self.image.paste(image.image, (x, y), image.image)

    def save(self, path: "path.Path"):
        self.image.save(path.to_str(), format="PNG")

    def to_data(self):
        bytes_io = data.Data().to_bytes_io()
        self.image.save(bytes_io, format="PNG", compress_level=0)
        return data.Data(bytes_io.getvalue())

    def serialize(self) -> dict[str, Any]:
        return {"data": self.to_data().to_base_64()}

    @staticmethod
    def deserialize(dt: dict[str, Any]) -> "BCImage":
        return BCImage(data.Data.from_base_64(dt["data"]))

    def paste(self, image: "BCImage", x: int, y: int):
        self.image.paste(image.image, (x, y), image.image)

    def putpixel(self, x: int, y: int, color: tuple[int, int, int, int]):
        self.image.putpixel((x, y), color)

    @image.setter
    def image(self, image: Image.Image):
        self.__image = image

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BCImage):
            return False

        # use cv2 and numpy to compare images

        img1 = cv2.cvtColor(np.array(self.image), cv2.COLOR_RGBA2BGRA)
        img2 = cv2.cvtColor(np.array(other.image), cv2.COLOR_RGBA2BGRA)

        return np.array_equal(img1, img2)  # type: ignore

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)
