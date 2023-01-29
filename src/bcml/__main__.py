import sys
from bcml.ui import main
from PyQt5 import QtWidgets

app = QtWidgets.QApplication(sys.argv)
window = main.MainWindow()
window.run()
