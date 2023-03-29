import math
import typing
from PyQt5 import QtGui


class AnimTransformer:
    def __init__(self):
        self.matrix: list[float] = [0.1, 0.0, 0.0, 0.0, 0.1, 0.0]

    def translate(self, x: float, y: float):
        self.matrix[2] += (self.matrix[0] * x) + (self.matrix[1] * y)
        self.matrix[5] += (self.matrix[3] * x) + (self.matrix[4] * y)

    def rotate(
        self,
        *,
        randians: typing.Optional[float] = None,
        degrees: typing.Optional[float] = None,
        fraction: typing.Optional[float] = None,
    ):
        if fraction is not None:
            degrees = fraction * 360
        if degrees is not None:
            randians = math.radians(degrees)
        if randians is None:
            raise ValueError("No angle provided")
        sin = math.sin(randians)
        cos = math.cos(randians)
        f = (self.matrix[0] * cos) + (self.matrix[1] * sin)
        f2 = (self.matrix[0] * -sin) + (self.matrix[1] * cos)
        f3 = (self.matrix[3] * cos) + (self.matrix[4] * sin)
        f4 = (self.matrix[3] * -sin) + (self.matrix[4] * cos)
        self.matrix[0] = f
        self.matrix[1] = f2
        self.matrix[3] = f3
        self.matrix[4] = f4

    def scale(self, x: float, y: float):
        self.matrix[0] *= x
        self.matrix[3] *= x
        self.matrix[1] *= y
        self.matrix[4] *= y

    def to_q_transform(self):
        return QtGui.QTransform(
            self.matrix[0],
            self.matrix[3],
            self.matrix[1],
            self.matrix[4],
            self.matrix[2],
            self.matrix[5],
        )

    def __str__(self):
        return f"AnimTransformer({self.matrix})"

    def __repr__(self):
        return f"AnimTransformer({self.matrix})"

    def copy(self):
        new_tranformer = AnimTransformer()
        new_tranformer.matrix = self.matrix.copy()
        return new_tranformer

    def get_translation(self):
        return self.matrix[2], self.matrix[5]
