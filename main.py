import sys
import time

import hexdump
from PyQt5.QtGui import QColor

from sniffer import Ui_Dialog
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.QtCore import QThread, pyqtSignal
import netifaces
import pyshark
from collections import OrderedDict


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
        ether_protocol_type = {'0x0800': 'IP', '0x0806': 'ARP'}
        ip_protocol = {'1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP'}
        hex_rep = hexdump.hexdump(pac, result='return')  # 流量包的二进制表示
        Frames = OrderedDict()  # 这个用于显示流量包的详细信息
        attach_info = ''
        tmstmp = pac.sniff_time
        ether_dst_mac = pac.eth.dst
        ether_src_mac = pac.eth.src
        ether_type = pac.eth.type
        ether_protocol_frame = ''
        ether_data_len = '0'
        src_ip, dst_ip, protocol = ['', '', '']
        try:
            ether_data_len = pac.data.len
        except:
            pass
        if ether_type in ether_protocol_type:
            ether_protocol_frame = ether_protocol_type[ether_type]
        Frames['以太网II型帧'] = ['时间戳: ' + tmstmp, '目标Mac地址: ' + ether_dst_mac, ' 源Mac地址: ' + ether_src_mac,
                                  '数据字段长度: ' + ether_data_len, '帧内协议类型: ' + ether_protocol_frame]
        if ether_type == '0x0800':
            ip = pac.ip
            version = ip.version
            ihl = ip.hdr_len
            total_len = ip.len
            iden = ip.id
            rf = ip.flags_tree.rb
            df = ip.flags_tree.df
            mf = ip.flags_tree.mf
            offset = ip.frag_offset
            ttl = ip.ttl
            protocol = ''
            if ip.proto in ip_protocol:
                protocol = ip_protocol[ip.proto]
            src_ip = ip.src
            dst_ip = ip.dst
            Frames['IP帧'] = ['IP版本: ' + version, '报头长度: ' + ihl, '封包总长: ' + total_len, '识别码: ' + iden,
                              '保留分段: ' + rf, '不分段: ' + df, '更多数据段: ' + mf, '分割定位: ' + offset,
                              '延续时间: ' + ttl, 'IP封包协议: ' + protocol, '源IP: ' + src_ip, '目的IP: ' + dst_ip]
            try:
                tcp = pac.tcp
                src_port = tcp.srcport
                dst_port = tcp.dstport
                seq_num = tcp.seq
                ack_num = tcp.ack
                urg = tcp.flags_tree.urg
                ack = tcp.flags_tree.ack
                psh = tcp.flags_tree.push
                rst = tcp.flags_tree.reset
                syn = tcp.flags_tree.syn
                fin = tcp.flags_tree.fin
                win_size = tcp.window_size

                Frames['TCP帧'] = ['源端口: ' + src_port, '目的端口: ' + dst_port, '序列号: ' + seq_num,
                                   '确认号: ' + ack_num,
                                   'URG: ' + urg, 'ACK: ' + ack, 'PSH: ' + psh, 'RST: ' + rst, 'SYN: ' + syn,
                                   'FIN: ' + fin, '窗口大小: ' + win_size]
                attach_info = " ".join(Frames['TCP帧'])
            except:
                pass
            try:
                icmp = pac.icmp
                _type = icmp.type
                code = icmp.code
                checksum = icmp.checksum
                Frames['ICMP帧'] = ['类型: ' + _type, '代码: ' + code, '校验和: ' + checksum]
                attach_info = " ".join(Frames['ICMP帧'][0:3])
            except:
                pass
            try:
                udp = pac.udp
                src_port = udp.srcport
                dst_port = udp.dstport
                udp_len = udp.length
                Frames['UDP帧'] = ['源端口: ' + src_port, '目的端口: ' + dst_port, 'UDP长度: ' + udp_len]
                attach_info = " ".join(Frames['UDP帧'][0:3])
            except:
                pass
        elif ether_type == '0x0806':
            arp = pac.arp
            protocol = 'ARP'
            if arp.hw_type == '1':
                hard_type = '以太网地址'
            else:
                hard_type = arp.hw_type
            if arp.proto_type == '0x0800':
                pro_type = 'IP地址'
            else:
                pro_type = str(arp.proto_type)
            hard_len = arp.hw_size
            pro_len = arp.proto_size
            if arp.opcode == '1':
                op = '1 - ARP请求'
            else:
                op = '2 - ARP应答'
            send_mac = arp.src_hw_mac
            src_ip = arp.src_proto_ipv4
            dst_mac = arp.dst_hw_mac
            dst_ip = arp.dst_proto_ipv4
            Frames['ARP帧'] = ['硬件类型: ' + hard_type, '协议类型: ' + pro_type, '硬件地址长度: ' + hard_len,
                               '协议地址长度: ' + pro_len,
                               '操作类型: ' + op, '发送者硬件地址: ' + send_mac, '发送者IP地址: ' + src_ip,
                               '目标硬件地址: ' + dst_mac, '目标IP地址: ' + dst_ip]
            attach_info = " ".join(Frames['ARP帧'])
        return [tmstmp, src_ip, dst_ip, protocol, attach_info, hex_rep, Frames]

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
