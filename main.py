import sys
from sniffer import Ui_Dialog
from PyQt5.QtWidgets import QDialog, QApplication

if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow = QDialog()
    ui = Ui_Dialog()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
