import sys
import time

from PyQt5.QtGui import QColor

from sniffer import Ui_Dialog
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtCore import QThread, pyqtSignal
import netifaces
import pyshark


# 定义一个用于抓包的线程类
class Sniffer(QThread):
    # 定义一个用于设置流量包数据的信号
    _pac_sig = pyqtSignal(list)

    def __init__(self, nt_card):
        super(Sniffer, self).__init__()
        self.init_filter = 'http || tcp || udp || arp || icmp'  # 暂时只考虑这五种协议
        self.cap = pyshark.LiveCapture(interface=nt_card, display_filter=self.init_filter, use_json=True,
                                       include_raw=True)
        self._isStop = False  # 用于控制抓包的线程

    def __del__(self):
        self.wait()

    def processer(self, pac):
        pass

    def run(self) -> None:
        data = []
        index = 1
        start_time = time.time()
        for pac in self.cap.sniff_continuously():
            if not self._isStop:
                data.append(self.processer(pac))
                # 每秒发出一次信号来处理数据，然后清空数据
                if time.time() - start_time >= 1 or index % 20 == 0:
                    start_time = time.time()
                    self._pac_sig.emit(data)
                    data = []
                index += 1
            else:
                break


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
        # 设置各个协议对应的颜色
        self.pro_color = {'TCP': QColor(135, 206, 235, 50), 'UDP': QColor(0, 255, 0, 50),
                          'HTTP': QColor(255, 215, 0, 50), 'ICMP': QColor(255, 97, 0, 50),
                          'ARP': QColor(160, 32, 240, 50)}

        # 链接信号与槽函数
        self.ui.begin_btn.clicked.connect(self.start)
        self.ui.stop_btn.clicked.connect(self.stop)

    # 实现基础抓包
    def start(self):
        print("开始执行抓包分析")
        self.ui.stop_btn.setEnabled(True)
        self.ui.begin_btn.setEnabled(False)

    def stop(self):
        print("停止执行抓包")
        self.ui.stop_btn.setEnabled(False)
        self.ui.begin_btn.setEnabled(True)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    my = MyWindow()
    my.show()
    sys.exit(app.exec_())
