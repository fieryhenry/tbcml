import math
import typing
from PyQt5 import QtGui


class AnimTransformer:
    """A class for transforming animation matrices"""

    def __init__(self):
        """Initializes the transformer with a default matrix"""
        self.matrix: list[float] = [0.1, 0.0, 0.0, 0.0, 0.1, 0.0]

    def translate(self, x: float, y: float):
        """Translates the matrix by the given x and y values

        Args:
            x (float): X value
            y (float): Y value
        """
        self.matrix[2] += (self.matrix[0] * x) + (self.matrix[1] * y)
        self.matrix[5] += (self.matrix[3] * x) + (self.matrix[4] * y)

    def rotate(
        self,
        *,
        randians: typing.Optional[float] = None,
        degrees: typing.Optional[float] = None,
        fraction: typing.Optional[float] = None,
    ):
        """Rotates the matrix by the given angle

        Args:
            randians (typing.Optional[float], optional): Angle in randians. Defaults to None.
            degrees (typing.Optional[float], optional): Angle in degrees. Defaults to None.
            fraction (typing.Optional[float], optional): Angle as a fraction of a 360 degree circle. Defaults to None.

        Raises:
            ValueError: No angle provided
        """
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
        """Scales the matrix by the given x and y values

        Args:
            x (float): X value
            y (float): Y value
        """
        self.matrix[0] *= x
        self.matrix[3] *= x
        self.matrix[1] *= y
        self.matrix[4] *= y

    def to_q_transform(self) -> QtGui.QTransform:
        """Converts the matrix to a QTransform

        Returns:
            QtGui.QTransform: QTransform
        """
        return QtGui.QTransform(
            self.matrix[0],
            self.matrix[3],
            self.matrix[1],
            self.matrix[4],
            self.matrix[2],
            self.matrix[5],
        )

    def __str__(self) -> str:
        """Returns a string representation of the matrix

        Returns:
            str: String representation
        """
        return f"AnimTransformer({self.matrix})"

    def __repr__(self) -> str:
        """Returns a string representation of the matrix

        Returns:
            str: String representation
        """
        return f"AnimTransformer({self.matrix})"

    def copy(self) -> "AnimTransformer":
        """Returns a copy of the transformer

        Returns:
            AnimTransformer: Copy of the transformer
        """
        new_tranformer = AnimTransformer()
        new_tranformer.matrix = self.matrix.copy()
        return new_tranformer

    def get_translation(self) -> tuple[float, float]:
        """Returns the translation of the matrix

        Returns:
            tuple[float, float]: Translation
        """
        return self.matrix[2], self.matrix[5]
