import sys
from sniffer import Ui_Dialog
from PyQt5.QtWidgets import QDialog, QApplication
import netifaces


class MyWindow(QDialog):
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setWindowTitle("Sniffer by A1gxer")
        interfaces = netifaces.interfaces()
        for _ in interfaces:
            self.ui.eth_comboBox.addItem(_)
        self.ui.eth_comboBox.setCurrentIndex(-1)
        self.ui.stop_btn.setEnabled(False)
        self.ui.begin_btn.setAutoDefault(False)

        # 链接信号与槽函数
        self.ui.begin_btn.clicked.connect(self.start)
        self.ui.stop_btn.clicked.connect(self.stop)

    # 实现基础抓包
    def start(self):
        print("开始执行抓包分析")
        self.ui.stop_btn.setEnabled(True)

    def stop(self):
        print("停止执行抓包")
        self.ui.stop_btn.setEnabled(False)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    my = MyWindow()
    my.show()
    sys.exit(app.exec_())
