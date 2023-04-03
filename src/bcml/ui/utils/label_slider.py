# code from https://gist.github.com/wiccy46/b7d8a1d57626a4ea40b19c5dbc5029ff
from typing import Callable, Optional, Union
from PyQt5.QtGui import QPainter, QPaintEvent
from PyQt5.QtWidgets import (
    QSlider,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QStyleOptionSlider,
    QStyle,
)
from PyQt5.QtCore import Qt, QRect, QPoint


class LabeledSlider(QWidget):
    def __init__(
        self,
        minimum: int,
        maximum: int,
        interval: int = 1,
        orientation: Qt.Orientation = Qt.Orientation.Horizontal,
        labels: Optional[Union[list[str], tuple[str]]] = None,
        p0: int = 0,
        parent: Optional[QWidget] = None,
        value_changed_callback: Optional[Callable[[int], None]] = None,
    ):
        super(LabeledSlider, self).__init__(parent=parent)
        self.value_changed_callback = value_changed_callback

        levels = range(minimum, maximum + interval, interval)

        if labels is not None:
            if len(labels) != len(levels):
                raise Exception("Size of <labels> doesn't match levels.")
            self.levels = list(zip(levels, labels))
        else:
            self.levels = list(zip(levels, map(str, levels)))

        if orientation == Qt.Orientation.Horizontal:
            self._layout = QVBoxLayout(self)
        elif orientation == Qt.Orientation.Vertical:
            self._layout = QHBoxLayout(self)
        else:
            raise Exception("<orientation> wrong.")

        # gives some space to print labels
        self.left_margin = 10
        self.top_margin = 10
        self.right_margin = 10
        self.bottom_margin = 10

        self._layout.setContentsMargins(
            self.left_margin, self.top_margin, self.right_margin, self.bottom_margin
        )

        self.sl = QSlider(orientation, self)
        self.sl.setMinimum(minimum)
        self.sl.setMaximum(maximum)
        self.sl.setValue(minimum)
        self.sl.setSliderPosition(p0)
        if self.value_changed_callback is not None:
            self.sl.valueChanged.connect(self.value_changed_callback)
        if orientation == Qt.Orientation.Horizontal:
            self.sl.setTickPosition(QSlider.TickPosition.TicksBelow)
            self.sl.setMinimumWidth(300)  # just to make it easier to read
        else:
            self.sl.setTickPosition(QSlider.TickPosition.TicksLeft)
            self.sl.setMinimumHeight(300)  # just to make it easier to read
        self.sl.setTickInterval(interval)
        self.sl.setSingleStep(1)

        self._layout.addWidget(self.sl)

    def paintEvent(self, a0: QPaintEvent):

        super(LabeledSlider, self).paintEvent(a0)
        style = self.sl.style()
        painter = QPainter(self)
        st_slider = QStyleOptionSlider()
        st_slider.initFrom(self.sl)
        st_slider.orientation = self.sl.orientation()

        length = style.pixelMetric(
            QStyle.PixelMetric.PM_SliderLength, st_slider, self.sl
        )
        available = style.pixelMetric(
            QStyle.PixelMetric.PM_SliderSpaceAvailable, st_slider, self.sl
        )

        for v, v_str in self.levels:

            # get the size of the label
            rect = painter.drawText(QRect(), Qt.TextFlag.TextDontPrint, v_str)

            if self.sl.orientation() == Qt.Orientation.Horizontal:
                # I assume the offset is half the length of slider, therefore
                # + length//2
                x_loc = (
                    QStyle.sliderPositionFromValue(
                        self.sl.minimum(), self.sl.maximum(), v, available
                    )
                    + length // 2
                )

                # left bound of the text = center - half of text width + L_margin
                left = x_loc - rect.width() // 2 + self.left_margin
                bottom = self.rect().bottom()

                # enlarge margins if clipping
                if v == self.sl.minimum():
                    if left <= 0:
                        self.left_margin = rect.width() // 2 - x_loc
                    if self.bottom_margin <= rect.height():
                        self.bottom_margin = rect.height()

                    self._layout.setContentsMargins(
                        int(self.left_margin),
                        self.top_margin,
                        int(self.right_margin),
                        int(self.bottom_margin),
                    )

                if v == self.sl.maximum() and rect.width() // 2 >= self.right_margin:
                    self.right_margin = rect.width() // 2
                    self._layout.setContentsMargins(
                        int(self.left_margin),
                        self.top_margin,
                        int(self.right_margin),
                        int(self.bottom_margin),
                    )

            else:
                y_loc = QStyle.sliderPositionFromValue(
                    self.sl.minimum(), self.sl.maximum(), v, available, upsideDown=True
                )

                bottom = y_loc + length // 2 + rect.height() // 2 + self.top_margin - 3
                # there is a 3 px offset that I can't attribute to any metric

                left = self.left_margin - rect.width()
                if left <= 0:
                    self.left_margin = rect.width() + 2
                    self._layout.setContentsMargins(
                        int(self.left_margin),
                        self.top_margin,
                        int(self.right_margin),
                        int(self.bottom_margin),
                    )

            pos = QPoint(int(left), int(bottom))
            painter.drawText(pos, v_str)

        return

    def set_value(self, value: int):
        self.sl.setValue(value)
