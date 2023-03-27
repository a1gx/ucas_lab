import sys
from sniffer import Ui_Dialog
from PyQt5.QtWidgets import QDialog, QApplication
import netifaces


class MyWindow(QDialog):
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        _ui = Ui_Dialog()
        _ui.setupUi(self)
        self.setWindowTitle("Sniffer by A1gxer")
        interfaces = netifaces.interfaces()
        for _ in interfaces:
            _ui.eth_comboBox.addItem(_)
        _ui.eth_comboBox.setCurrentIndex(-1)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    my = MyWindow()
    my.show()
    sys.exit(app.exec_())
