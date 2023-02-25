import sys

from PyQt5 import QtWidgets

from bcml.ui import main

app = QtWidgets.QApplication(sys.argv)
window = main.MainWindow()
window.run()
