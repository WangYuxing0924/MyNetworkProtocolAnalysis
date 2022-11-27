from PySide6.QtWidgets import QApplication, QMessageBox, QMdiSubWindow, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QObject, Signal

from threading import Thread
import sys
import time
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP,ICMP, TCP, UDP
from protocol import *


# 自定义信号源对象类型，一定要继承自QObject
from protocol.send_udp import Send_UDP


class MySignals(QObject):
    # 定义一种信号，两个参数 类型分别是：QTextEdit和字符串
    # 调用emit方法，发信号时，传入参数 必须是这里指定的参数类型
    textEdit_print = Signal(QTextEdit, str)


class Send_PDU(QObject):
    def __init__(self):
        QObject.__init__(self)
        # 从PySide6文件中加载UI定义[
        self.ui = QUiLoader().load('ui/sendPDUGUI.ui')
        self.ui.protocolEditorFrame.closeAllSubWindows()
        # 调用信号和槽的函数以及空间管理等函数
        self.signleAndSlot()
        # 实例化GUI界面输出信号对象
        self.global_ms = MySignals()
        self.global_ms.textEdit_print.connect(self.printToGui)

    # 定义信号和槽函数
    def signleAndSlot(self):
        self.ui.protocolsTree.itemClicked.connect(self.on_click_protocols_tree)

    def printToGui(self, fb, text):
        fb.append(text)
        fb.ensureCursorVisible()

    # 定义触发函数
    def on_click_protocols_tree(self, item, colum):
        choosedPDUType = item.text(0)
        # QMessageBox.informaation(UI,"友情提示",choosedPDUType)
        if choosedPDUType == '帧':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_macFrame = QUiLoader().load('ui/macFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_macFrame)
            self.subUI_macFrame.show()
            self.subUI_macFrame.sendPushButton.clicked.connect(self.sendEtherFrame)
            self.subUI_macFrame.sendContPushButton.clicked.connect(self.continueSendEtherFrame)
        if choosedPDUType == 'ARP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_arpFrame = QUiLoader().load('ui/arpFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_arpFrame)
            self.subUI_arpFrame.show()
            self.subUI_arpFrame.sendPushButton.clicked.connect(self.sendARPFrame)
            self.subUI_arpFrame.sendContPushButton.clicked.connect(self.continueSendARPFrame)
        if choosedPDUType == 'IP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_ipFrame = QUiLoader().load('ui/ipFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_ipFrame)
            self.subUI_ipFrame.show()
            self.subUI_ipFrame.sendPushButton.clicked.connect(self.sendIPFrame)
            self.subUI_ipFrame.sendContPushButton.clicked.connect(self.continueSendIPFrame)
        if choosedPDUType == 'ICMP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_icmpFrame = QUiLoader().load('ui/icmpFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_icmpFrame)
            self.subUI_icmpFrame.show()
            self.subUI_icmpFrame.sendPushButton.clicked.connect(self.sendICMPFrame)
            self.subUI_icmpFrame.sendContPushButton.clicked.connect(self.continueSendICMPFrame)
        if choosedPDUType == 'DNS':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_dnsFrame = QUiLoader().load('ui/dnsFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_dnsFrame)
            self.subUI_dnsFrame.show()
            self.subUI_dnsFrame.sendPushButton.clicked.connect(self.sendDNSFrame)
            self.subUI_dnsFrame.sendContPushButton.clicked.connect(self.continueSendDNSFrame)
        if choosedPDUType == 'UDP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_udpFrame = QUiLoader().load('ui/udpFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_udpFrame)
            self.subUI_udpFrame.show()
            send_udp = Send_UDP()
            self.subUI_udpFrame.sendPushButton.clicked.connect(self.sendUDPFrame)
            self.subUI_udpFrame.sendContPushButton.clicked.connect(self.continueSendUDPFrame)
        if choosedPDUType == 'HTTP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_httpFrame = QUiLoader().load('ui/httpFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_httpFrame)
            self.subUI_httpFrame.show()
            self.subUI_httpFrame.sendPushButton.clicked.connect(self.sendHTTPFrame)
            self.subUI_httpFrame.sendContPushButton.clicked.connect(self.continueSendHTTPFrame)
        if choosedPDUType == 'TCP':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_tcpFrame = QUiLoader().load('ui/tcpFrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_tcpFrame)
            self.subUI_tcpFrame.show()
            self.subUI_tcpFrame.sendPushButton.clicked.connect(self.sendTCPFrame)
            self.subUI_tcpFrame.sendContPushButton.clicked.connect(self.continueSendTCPFrame)
        if choosedPDUType == 'IPv6':
            self.ui.protocolEditorFrame.closeAllSubWindows()
            self.subUI_arpFrame = QUiLoader().load('ui/ipv6FrameEditWindow.ui')
            self.ui.protocolEditorFrame.addSubWindow(self.subUI_arpFrame)
            self.subUI_arpFrame.show()
            self.subUI_arpFrame.sendPushButton.clicked.connect(self.sendARPFrame)
            self.subUI_arpFrame.sendContPushButton.clicked.connect(self.continueSendEtherFrame)

    def sendEtherFrame(self):
        dstmac = self.subUI_macFrame.dstmacInput.text()
        print(dstmac)
        payLoad = self.subUI_macFrame.payloadInput.toPlainText()
        print(payLoad)
        count = self.subUI_macFrame.countInput.text()
        QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            etherFrame = Ether(dst=dstmac) / payLoad
            etherFramefoStr = '待发送信息\n' + \
                              'des:' + dstmac + '\n' + \
                              'src:' + etherFrame.src + '\n' + \
                              'payload:' + payLoad + '\n'
            print(etherFramefoStr)
            self.subUI_macFrame.resultText.append(etherFramefoStr)
            self.subUI_macFrame.resultText.append(str(etherFrame) + '\n')

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                for i in range(int(count)):
                    sendp(etherFrame)
                    self.subUI_macFrame.resultText.append('成功发送' + str(i+1) + '个以太帧。\n')

            t = Thread(target=run)
            t.start()
        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_macFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            QMessageBox.critical(self.subUI_macFrame, "错误", "发送数据失败\n")
        finally:
            pass
    def sendARPFrame(self):
        arptype = self.subUI_arpFrame.arptypeInput.text()
        print(arptype)
        srcmacinput = self.subUI_arpFrame.srcmacInput.text()
        print(srcmacinput)
        srcipInput = self.subUI_arpFrame.srcipInput.text()
        print(srcipInput)
        destmacInput = self.subUI_arpFrame.destmacInput.text()
        print(destmacInput)
        destipInput = self.subUI_arpFrame.destipInput.text()
        print(destipInput)
        arppayload = self.subUI_arpFrame.payload.toPlainText()
        print(arppayload)
        count = self.subUI_arpFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            arp = ARP()
            if arptype!='':
               arp.op = int(arptype)
            if srcmacinput!='':
                arp.hwsrc = srcmacinput
            if srcipInput!='':
                arp.psrc = srcipInput
            if destmacInput != '':
                arp.hwdst = destmacInput
            if destipInput!='':
                arp.pdst = destipInput

            # arp.op = 1
            #arp.psrc = "192.168.1.3"
            #arp.pdst = "192.168.1.1"
            #arpFrame = arp / arppayload
            arpFrame = arp / arppayload
            arpFramefoStr = '待发送信息\n' + \
                            'op:' + arptype + '\n' + \
                            'hwsrc:' + srcmacinput + '\n' + \
                            'psrc:' + srcipInput + '\n' + \
                            'hwdst:' + destmacInput + '\n' + \
                            'pdst:' + destipInput + '\n' + \
                            'payload:' + arppayload + '\n'
            print(arpFramefoStr)
            self.subUI_arpFrame.resultText.append(arpFramefoStr)
            self.subUI_arpFrame.resultText.append(str(arpFrame) + '\n')

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                e = Ether()
                for i in range(int(count)):
                    sendp(e/arpFrame)
                    #sr1(e/arpFrame)
                    self.subUI_arpFrame.resultText.append('成功发送' + str(i+1) + ' ARP帧。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_arpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            QMessageBox.critical(self.subUI_arpFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def sendIPFrame(self):
        src_mac = self.subUI_ipFrame.src_mac.text()
        print(src_mac)
        dst_mac = self.subUI_ipFrame.dst_mac.text()
        print(dst_mac)
        version = self.subUI_ipFrame.version.text()
        print(version)
        id = self.subUI_ipFrame.id.text()
        print(id)
        ihl = self.subUI_ipFrame.ihl.text()
        print(ihl)
        iplen = self.subUI_ipFrame.len.text()
        print(iplen)
        tos = self.subUI_ipFrame.tos.text()
        print(tos)
        frag = self.subUI_ipFrame.frag.text()
        print(frag)
        flags = self.subUI_ipFrame.flags.text()
        print(flags)
        proto = self.subUI_ipFrame.proto.text()
        print(proto)
        ttl = self.subUI_ipFrame.ttl.text()
        print(ttl)
        #chksum = self.subUI_ipFrame.chksum.text()
        #print(chksum)
        src = self.subUI_ipFrame.src.text()
        print(src)
        dst = self.subUI_ipFrame.dst.text()
        print(dst)
        payload = self.subUI_ipFrame.payload.text()
        print(payload)

        tt = len(payload)
        print("dddddd======="+str(tt))
        count = self.subUI_ipFrame.count.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            ippkg = IP()
            e = Ether()
            if src_mac!='':
                e.src = src_mac
            if dst_mac!='':
                e.dst_mac = dst_mac
            if version!='':
                ippkg.version = int(version)
            if id!='':
                ippkg.id = int(id)
            if ihl!='':
                ippkg.ihl = int(ihl)
            if iplen != '':
                ippkg.len = int(iplen)
            if tos!='':
                ippkg.tos = int(tos)
            if frag!='':
                ippkg.frag = int(frag)
            if flags != '':
                ippkg.flags = int(flags)
            if proto!='':
                ippkg.proto = int(proto)
            if ttl != '':
                ippkg.ttl = int(ttl)
            #if chksum!='':
            #    ippkg.chksum = int(chksum)
            if src != '':
                ippkg.src = src
            if dst != '':
                ippkg.dst = dst

            ippkg.len = ippkg.len + len(payload)
            ipFrame = ippkg / payload
            ipFramefoStr = '待发送信息\n' + \
                           'src_mac:' + src_mac + '\n' + \
                           'dst_mac:' + dst_mac + '\n' + \
                           'version:' + version + '\n' + \
                           'id:' + id + '\n' + \
                           'ihl:' + ihl + '\n' + \
                           'len:' + str(ippkg.len) + '\n' + \
                           'tos:' + tos + '\n' + \
                            'frag:' + frag + '\n' + \
                            'flags:' + flags + '\n' + \
                            'proto:' + proto + '\n' + \
                           'ttl:' + ttl + '\n' + \
                           'src:' + src + '\n' + \
                           'dst:' + dst + '\n' + \
                           'payload:' + payload + '\n'
            print(ipFramefoStr)
            #自动计算校验和
            #ipFrame.len = 20 + len(payload)

            y = raw(ipFrame)
            ipraw = IP(y)
            print("=========ipraw.show()====")
            ipraw.show()
            print("=========ipraw.show() end====")
            print("ip_packet_payload len:" + str(ipFrame.len))
            chsum_scapy = ipraw[IP].chksum
            self.subUI_ipFrame.resultText.append(ipFramefoStr)
            self.subUI_ipFrame.resultText.append(str(ipFrame) + '\n')
            self.subUI_ipFrame.resultText.append("添加数据后scapy自动计算的IP首部校验和是: %04x (%s)" %(chsum_scapy, str(chsum_scapy)))
            #自己计算IP校验和
            checksum_changed_self = self.calculateIPChksum(ipFrame, payload)
            self.subUI_ipFrame.resultText.append("改变数据长度后IP首部的校验和是 : %04x (%s)" % (checksum_changed_self, str(checksum_changed_self)))
            if chsum_scapy == checksum_changed_self:
                self.subUI_ipFrame.resultText.append("校验和正确")
            else:
                self.subUI_ipFrame.resultText.append("校验和不正确")
            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                e = Ether()
                for i in range(int(count)):
                    sendp(e/ipFrame)
                    #sr1(e/arpFrame)
                    self.subUI_ipFrame.resultText.append('成功发送' + str(i+1) + ' IP包。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_ipFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            print(e)
            QMessageBox.critical(self.subUI_ipFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def sendICMPFrame(self):
        id = self.subUI_icmpFrame.id.text()
        print(id)
        seq = self.subUI_icmpFrame.seq.text()
        print(seq)
        srcipInput = self.subUI_icmpFrame.srcipInput.text()
        print(srcipInput)
        destipInput = self.subUI_icmpFrame.destipInput.text()
        print(destipInput)
        payload = self.subUI_icmpFrame.payload.toPlainText()
        print(payload)
        count = self.subUI_icmpFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            ippkg = IP()
            icmp = ICMP()
            if id !='' :
                icmp.id = int(id)
            if seq !='':
                icmp.seq = int(seq)

            if srcipInput!='':
                ippkg.src = srcipInput
            if destipInput!='':
                ippkg.dst = destipInput

            # arp.op = 1
            #arp.psrc = "192.168.1.3"
            #arp.pdst = "192.168.1.1"
            #arpFrame = arp / arppayload
            #ippkg.len = 20 + len(payload)
            icmpFrame = ippkg/icmp/payload
            print("icmpFrame==="+str(icmpFrame))
           # print
            #icmpFrame.len = icmpFrame.len + len(payload)
            icmpFrame.show2()

            icmpFramefoStr = '待发送信息\n' + \
                            'id:' + id + '\n' + \
                            'seq:' + seq + '\n' + \
                            'src:' + srcipInput + '\n' + \
                            'dst:' + destipInput + '\n' + \
                            'payload:' + payload + '\n'
            print(icmpFramefoStr)
            self.subUI_icmpFrame.resultText.append(icmpFramefoStr)
            self.subUI_icmpFrame.resultText.append(str(icmpFrame) + '\n')
            # 计算校验和
            icmp_payload = icmp / payload
            icmp_payload.len = 8 + len(payload)
            y = raw(icmp_payload)
            icmpraw = ICMP(y)
            icmpraw.show()
            # print("icmp_packet_payload len:" + str(icmp.len))
            chsum_scapy = icmpraw[ICMP].chksum
            self.subUI_icmpFrame.resultText.append(
                "添加数据后scapy自动计算的ICMP首部校验和是: %04x (%s)" % (chsum_scapy, str(chsum_scapy)))
            # 自己计算IP校验和
            checksum_changed_self = self.calculateICMPChksum(icmp_payload, payload)
            self.subUI_icmpFrame.resultText.append(
                "改变数据长度后IP首部的校验和是 : %04x (%s)" % (checksum_changed_self, str(checksum_changed_self)))
            if chsum_scapy == checksum_changed_self:
                self.subUI_icmpFrame.resultText.append("校验和正确")
            else:
                self.subUI_icmpFrame.resultText.append("校验和不正确")

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息

                for i in range(int(count)):
                    icmpFrame = ippkg / icmp / payload
                    ping1 = sr1(icmpFrame, timeout=2, verbose=False)
                    icmp.id = icmp.id+1
                    icmp.seq = icmp.seq+1
                    #icmpFrame = ippkg / icmp / payload
                    #sr1(e/arpFrame)
                    if ping1:
                        self.subUI_icmpFrame.resultText.append('发送成功' + str(i+1) + ' ICMP包。对方主机可达\n')
                    else:
                        self.subUI_icmpFrame.resultText.append('发送失败' + str(i+1) + ' ICMP包。对方主机不可达\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_icmpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            print(e)
            QMessageBox.critical(self.subUI_icmpFrame, "错误", "发送数据失败\n")
        finally:
            pass
    def sendTCPFrame(self):
        seq = self.subUI_tcpFrame.seq.text()
        print(seq)
        flag = self.subUI_tcpFrame.flag.text()
        print(flag)
        flag1 = self.subUI_tcpFrame.flag1.text()
        print(flag1)
        srcipInput = self.subUI_tcpFrame.srcipInput.text()
        print(srcipInput)
        srcportInput = self.subUI_tcpFrame.srcportInput.text()
        print(srcportInput)
        destportInput = self.subUI_tcpFrame.destportInput.text()
        print(destportInput)
        destipInput = self.subUI_tcpFrame.destipInput.text()
        print(destipInput)
        payload = self.subUI_tcpFrame.payload.toPlainText()
        print(payload)
        count = self.subUI_tcpFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            ippkg = IP()
            tcppkg = TCP()
            tcppkg1 = TCP()
            if seq !='':
                tcppkg.seq = int(seq)
            if flag !='':
                tcppkg.flags = flag
            if flag1 !='':
                tcppkg1.flags = flag1
            if srcportInput!='':
                tcppkg.sport = int(srcportInput)
                tcppkg1.sport = int(srcportInput)
            if srcipInput!='':
                ippkg.src = srcipInput
            if destportInput != '':
                tcppkg.dport = int(destportInput)
                tcppkg1.dport = int(destportInput)
            if destipInput!='':
                ippkg.dst = destipInput
            tcpFrame = ippkg / tcppkg
            tcpFramefoStr = '待发送信息\n' + \
                            'seq:' + seq + '\n' + \
                            'flags:' + flag + '\n' + \
                            'second flags:' + flag1 + '\n' + \
                            'sport:' + srcportInput + '\n' + \
                            'src:' + ippkg.src + '\n' + \
                            'dport:' + destportInput + '\n' + \
                            'dst:' + ippkg.dst + '\n' + \
                            'payload:' + payload + '\n'
            print(tcpFramefoStr)
            self.subUI_tcpFrame.resultText.append(tcpFramefoStr)
            self.subUI_tcpFrame.resultText.append(str(tcpFrame) + '\n')


            # 计算第一包校验和
            tcp_payload = tcppkg
            checksum_changed_self = self.calculateTCPChksum(tcpFrame, tcp_payload)
            self.subUI_tcpFrame.resultText.append("自己计算的TCP第一次握手首部的校验和是" + str(checksum_changed_self))

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                #e = Ether()
                for i in range(int(count)):
                    SYNACK = sr1(tcpFrame)
                    tcppkg1.seq = SYNACK.ack
                    tcppkg1.ack = SYNACK.seq + 1
                    # 计算发送的第二包校验和
                    ip_tcp2= ippkg / tcppkg1
                    checksum_changed_self = self.calculateTCPChksum(ip_tcp2, tcppkg1)
                    self.subUI_tcpFrame.resultText.append("自己计算的TCP第三次握手首部的校验和是" + str(checksum_changed_self))
                    send(ip_tcp2)
                    self.subUI_tcpFrame.resultText.append('成功发送' + str(i+1) + ' TCP包。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_tcpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            print(e)
            QMessageBox.critical(self.subUI_tcpFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def sendUDPFrame(self):

        srcipInput = self.subUI_udpFrame.srcipInput.text()
        print(srcipInput)
        srcportInput = self.subUI_udpFrame.srcportInput.text()
        print(srcportInput)
        destportInput = self.subUI_udpFrame.destportInput.text()
        print(destportInput)
        destipInput = self.subUI_udpFrame.destipInput.text()
        print(destipInput)
        payload = self.subUI_udpFrame.payload.toPlainText()
        print(payload)
        count = self.subUI_udpFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            ippkg = IP()
            udppkg = UDP()
            if srcportInput!='':
                udppkg.sport = int(srcportInput)
            if srcipInput!='':
                ippkg.src = srcipInput
            if destportInput != '':
                udppkg.dport = int(destportInput)
            if destipInput!='':
                ippkg.dst = destipInput
            udpFrame = ippkg / udppkg / payload
            udpFramefoStr = '待发送信息\n' + \
                            'sport:' + srcportInput + '\n' + \
                            'src:' + ippkg.src + '\n' + \
                            'dport:' + destportInput + '\n' + \
                            'dst:' + ippkg.dst + '\n' + \
                            'payload:' + payload + '\n'
            print(udpFramefoStr)
            self.subUI_udpFrame.resultText.append(udpFramefoStr)
            self.subUI_udpFrame.resultText.append(str(udpFrame) + '\n')

            #UDP校验和
            udppkg1 = udppkg / payload
            checksum_changed_self = self.calculateUDPChksum(udpFrame, udppkg1)
            self.subUI_udpFrame.resultText.append("自己计算的UDP首部的校验和是" + str(checksum_changed_self))
            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                e = Ether()
                for i in range(int(count)):
                    send(ippkg / udppkg / payload)
                    #sr1(e/arpFrame)
                    self.subUI_udpFrame.resultText.append('成功发送' + str(i+1) + ' ARP帧。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_udpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            print(e)
            QMessageBox.critical(self.subUI_udpFrame, "错误", "发送数据失败\n")
        finally:
            pass


    def sendHTTPFrame(self):
        seq = self.subUI_httpFrame.seq.text()
        print(seq)
        flag = self.subUI_httpFrame.flag.text()
        print(flag)
        flag1 = self.subUI_httpFrame.flag1.text()
        print(flag1)
        srcipInput = self.subUI_httpFrame.srcipInput.text()
        print(srcipInput)
        srcportInput = self.subUI_httpFrame.srcportInput.text()
        print(srcportInput)
        destportInput = self.subUI_httpFrame.destportInput.text()
        print(destportInput)
        destipInput = self.subUI_httpFrame.destipInput.text()
        print(destipInput)
        payload = self.subUI_httpFrame.payload.text()
        print(payload)
        count = self.subUI_httpFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:

            ippkg = IP()
            tcppkg = TCP()
            tcppkg1 = TCP()
            if seq !='':
                tcppkg.seq = int(seq)
            if flag !='':
                tcppkg.flags = flag
            if flag1 !='':
                tcppkg1.flags = flag1
            if srcportInput!='':
                tcppkg.sport = int(srcportInput)
                tcppkg1.sport = int(srcportInput)
            if srcipInput!='':
                ippkg.src = srcipInput
            if destportInput != '':
                tcppkg.dport = int(destportInput)
                tcppkg1.dport = int(destportInput)
            if destipInput!='':
                ippkg.dst = destipInput
            httpFrame = ippkg/tcppkg
            httpFramefoStr = '待发送信息\n' + \
                            'seq:' + seq + '\n' + \
                            'flags:' + flag + '\n' + \
                            'second flags:' + flag1 + '\n' + \
                            'sport:' + srcportInput + '\n' + \
                            'src:' + ippkg.src + '\n' + \
                            'dport:' + destportInput + '\n' + \
                            'dst:' + ippkg.dst + '\n' + \
                            'http content:' + payload + '\n'
            print(httpFramefoStr)
            self.subUI_httpFrame.resultText.append(httpFramefoStr)
            self.subUI_httpFrame.resultText.append(str(httpFrame) + '\n')

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                #e = Ether()
                for i in range(int(count)):
                    #syn = IP(dst='192.168.1.1') / TCP(dport=80, flags='S')
                    syn_ack = sr1(httpFrame)
                    # dest = '192.168.1.1'
                    # syn = IP(dst=dest) / TCP(sport=38837, dport=80, flags='S')
                    # syn_ack = sr1(syn)
                    tcppkg1.seq = syn_ack.ack
                    tcppkg1.ack = syn_ack.seq + 1
                    getStr = 'GET / login.html / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
                    out_ack = send(ippkg / tcppkg1)
                    # out_ack = send(IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack,
                    #                        ack=syn_ack[TCP].seq + 1,
                    #                        flags='A'))
                    tcppkg1.flags = 'P''A'
                    # sr1(IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack,
                    #                        ack=syn_ack[TCP].seq + 1, flags='P''A') / getStr)
                    sr1(ippkg / tcppkg1 / getStr)

                    #reply = sr1(ippkg / tcppkg1 / getStr)
                    #reply.summary()
                    #request = IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport,
                    #                                      seq=syn_ack[TCP].ack +1, ack=syn_ack[TCP].seq + 1,
                    #                                      flags='A') / getStr
                    #reply = sr1(request)
                    self.subUI_httpFrame.resultText.append('成功发送' + str(i+1) + ' http包。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_httpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            QMessageBox.critical(self.subUI_httpFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def sendDNSFrame(self):

        qtype = self.subUI_dnsFrame.qtype.text()
        print(qtype)
        qname = self.subUI_dnsFrame.qname.text()
        print(qname)
        rd = self.subUI_dnsFrame.rd.text()
        print(rd)
        srcipInput = self.subUI_dnsFrame.srcipInput.text()
        print(srcipInput)
        srcportInput = self.subUI_dnsFrame.srcportInput.text()
        print(srcportInput)
        destportInput = self.subUI_dnsFrame.destportInput.text()
        print(destportInput)
        destipInput = self.subUI_dnsFrame.destipInput.text()
        print(destipInput)
        payload = self.subUI_dnsFrame.payload.toPlainText()
        print(payload)
        count = self.subUI_dnsFrame.countInput.text()
        #QMessageBox.information(self.subUI_macFrame, "目的mac地址", dstmac)
        try:
            ippkg = IP()
            udppkg = UDP()
            dnspkg = DNS()
            qd = DNSQR()
            dnspkg.qd = qd
            if qtype != '':
                qd.qtype = qtype
            if qname != '':
                qd.qname = qname
            if rd != '':
                dnspkg.rd = int(rd)
            if srcportInput!='':
                udppkg.sport = int(srcportInput)
            if srcipInput!='':
                ippkg.src = srcipInput
            if destportInput != '':
                udppkg.dport = int(destportInput)
            if destipInput!='':
                ippkg.dst = destipInput
            dnsFrame = ippkg / udppkg / dnspkg / payload

            dnsFramefoStr = '待发送信息\n' + \
                            'sport:' + srcportInput + '\n' + \
                            'src:' + ippkg.src + '\n' + \
                            'dport:' + destportInput + '\n' + \
                            'dst:' + ippkg.dst + '\n' + \
                            'qtype:' + qtype + '\n' + \
                            'qname:' + qname + '\n' + \
                            'rd:' + rd + '\n' + \
                            'payload:' + payload + '\n'
            print(dnsFramefoStr)
            print(dnsFrame)
            self.subUI_dnsFrame.resultText.append(dnsFramefoStr)
            self.subUI_dnsFrame.resultText.append(str(dnsFrame) + '\n')

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                e = Ether()
                for i in range(int(count)):
                    send(dnsFrame)
                    #sr1(e/arpFrame)
                    self.subUI_dnsFrame.resultText.append('成功发送' + str(i+1) + ' dns数据包。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(self.subUI_dnsFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            print(e)
            QMessageBox.critical(self.subUI_dnsFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def continueSendEtherFrame(self):
        buttonInfo = self.subUI_macFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            dstmac = self.subUI_macFrame.dstmacInput.text()
            payLoad = self.subUI_macFrame.payloadInput.toPlainText()
            QMessageBox.information(self.subUI_macFrame, "提示", f'即将开始向目的mac：{dstmac}地址连续发送数据帧！')
            try:
                etherFrame = Ether(dst=dstmac) / payLoad
                etherFrameInfoStr = '待发送信息\n' + \
                                    'des:' + dstmac + '\n' + \
                                    'src:' + etherFrame.src + '\n' + \
                                    'payload:' + payLoad + '\n'
                # self.subUI_macFrame.resultText.append(etherFrameInfoStr)
                # self.subUI_macFrame.resultText.append(str(etherFrame)+'\n')
                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_macFrame.resultText, etherFrameInfoStr)
                self.global_ms.textEdit_print.emit(self.subUI_macFrame.resultText, str(etherFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendEtherFrameThread, args=(etherFrame))
                t.setDaemon(True)
                t.start()
                self.subUI_macFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_macFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_macFrame.sendContPushButton.setText("连续发送")

    def continueSendARPFrame(self):
        buttonInfo = self.subUI_arpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            arptype = self.subUI_arpFrame.arptypeInput.text()
            print(arptype)
            srcmacinput = self.subUI_arpFrame.srcmacInput.text()
            print(srcmacinput)
            srcipInput = self.subUI_arpFrame.srcipInput.text()
            print(srcipInput)
            destmacInput = self.subUI_arpFrame.destmacInput.text()
            print(destmacInput)
            destipInput = self.subUI_arpFrame.destipInput.text()
            print(destipInput)
            arppayload = self.subUI_arpFrame.payload.toPlainText()
            print(arppayload)
            count = self.subUI_arpFrame.countInput.text()
            QMessageBox.information(self.subUI_arpFrame, "提示", f'即将开始向目的IP：{destipInput}地址连续发送数据包！')

            payload = self.subUI_arpFrame.payload.toPlainText()
            print(payload)
            #count = self.subUI_udpFrame.countInput.text()
            try:
                arp = ARP()
                if arptype == '':
                    arptype = 1
                arp.op = int(arptype)
                if srcmacinput != '':
                    arp.hwsrc = srcmacinput
                if srcipInput != '':
                    arp.psrc = srcipInput
                if destmacInput != '':
                    arp.hwdst = destmacInput
                if destipInput != '':
                    arp.pdst = destipInput

                # arp.op = 1
                # arp.psrc = "192.168.1.3"
                # arp.pdst = "192.168.1.1"
                # arpFrame = arp / arppayload
                arpFrame = arp / arppayload
                arpFramefoStr = '待发送信息\n' + \
                                'hwsrc:' + srcmacinput + '\n' + \
                                'psrc:' + srcipInput + '\n' + \
                                'hwdst:' + destmacInput + '\n' + \
                                'pdst:' + destipInput + '\n' + \
                                'payload:' + arppayload + '\n'
                print(arpFramefoStr)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_arpFrame.resultText, arpFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_arpFrame.resultText, str(arpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendARPFrameThread, args=(arpFrame))
                t.setDaemon(True)
                t.start()
                self.subUI_arpFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_arpFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_arpFrame.sendContPushButton.setText("连续发送")

    def continueSendIPFrame(self):
        buttonInfo = self.subUI_ipFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            version = self.subUI_ipFrame.version.text()
            print(version)
            id = self.subUI_ipFrame.id.text()
            print(id)
            ihl = self.subUI_ipFrame.ihl.text()
            print(ihl)
            len = self.subUI_ipFrame.len.text()
            print(len)
            tos = self.subUI_ipFrame.tos.text()
            print(tos)
            frag = self.subUI_ipFrame.frag.text()
            print(frag)
            flags = self.subUI_ipFrame.flags.text()
            print(flags)
            proto = self.subUI_ipFrame.proto.text()
            print(proto)
            ttl = self.subUI_ipFrame.ttl.text()
            print(ttl)
            #chksum = self.subUI_ipFrame.chksum.text()
            #print(chksum)
            src = self.subUI_ipFrame.src.text()
            print(src)
            dst = self.subUI_ipFrame.dst.text()
            print(dst)
            payload = self.subUI_ipFrame.payload.text()
            print(payload)
            QMessageBox.information(self.subUI_ipFrame, "提示", f'即将开始向目的IP：{dst}地址连续发送数据包！')


            #count = self.subUI_udpFrame.countInput.text()
            try:
                print("1111111")
                ippkg = IP()
                if version != '':
                    ippkg.version = int(version)
                if id != '':
                    ippkg.id = int(id)
                if ihl != '':
                    ippkg.ihl = int(ihl)
                if len != '':
                    ippkg.len = int(len)
                if tos != '':
                    ippkg.tos = int(tos)
                if frag != '':
                    ippkg.frag = int(frag)
                if flags != '':
                    ippkg.flags = int(flags)
                if proto != '':
                    ippkg.proto = int(proto)
                if ttl != '':
                    ippkg.ttl = int(ttl)
                #if chksum != '':
                #    ippkg.chksum = int(chksum)
                if src != '':
                    ippkg.src = src
                if dst != '':
                    ippkg.dst = dst
                print("33333")
                e=Ether()
                ipFrame = e / ippkg / payload
                ipFramefoStr = '待发送信息\n' + \
                               'version:' + version + '\n' + \
                               'id:' + id + '\n' + \
                               'ihl:' + ihl + '\n' + \
                               'len:' + len + '\n' + \
                               'tos:' + tos + '\n' + \
                               'frag:' + frag + '\n' + \
                               'flags:' + flags + '\n' + \
                               'proto:' + proto + '\n' + \
                               'ttl:' + ttl + '\n' + \
                               'src:' + src + '\n' + \
                               'dst:' + dst + '\n' + \
                               'payload:' + payload + '\n'
                print(ipFramefoStr)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_ipFrame.resultText, ipFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_ipFrame.resultText, str(ipFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendIPFrameThread, args=(ipFrame))
                t.setDaemon(True)
                t.start()
                self.subUI_ipFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                print(e)
                QMessageBox.critical(self.subUI_ipFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_ipFrame.sendContPushButton.setText("连续发送")

    def continueSendICMPFrame(self):
        buttonInfo = self.subUI_icmpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            id = self.subUI_icmpFrame.id.text()
            print(id)
            seq = self.subUI_icmpFrame.seq.text()
            print(seq)
            srcipInput = self.subUI_icmpFrame.srcipInput.text()
            print(srcipInput)
            destipInput = self.subUI_icmpFrame.destipInput.text()
            print(destipInput)
            payload = self.subUI_icmpFrame.payload.toPlainText()
            print(payload)
            count = self.subUI_icmpFrame.countInput.text()
            QMessageBox.information(self.subUI_icmpFrame, "提示", f'即将开始向目的IP：{destipInput}地址连续发送数据包！')
            try:
                ippkg = IP()
                icmp = ICMP()
                if id != '':
                    icmp.id = int(id)
                if seq != '':
                    icmp.seq = int(seq)

                if srcipInput != '':
                    ippkg.src = srcipInput
                if destipInput != '':
                    ippkg.dst = destipInput

                # arp.op = 1
                # arp.psrc = "192.168.1.3"
                # arp.pdst = "192.168.1.1"
                # arpFrame = arp / arppayload
                icmpFrame = ippkg / icmp / payload
                icmpFramefoStr = '待发送信息\n' + \
                                 'id:' + id + '\n' + \
                                 'seq:' + seq + '\n' + \
                                 'src:' + srcipInput + '\n' + \
                                 'dst:' + destipInput + '\n' + \
                                 'payload:' + payload + '\n'
                print(icmpFramefoStr)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_icmpFrame.resultText, icmpFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_icmpFrame.resultText, str(icmpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendICMPFrameThread, args=(icmpFrame))
                t.setDaemon(True)
                t.start()
                self.subUI_icmpFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_icmpFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_icmpFrame.sendContPushButton.setText("连续发送")

    def continueSendTCPFrame(self):
        buttonInfo = self.subUI_tcpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            seq = self.subUI_tcpFrame.seq.text()
            print(seq)
            flag = self.subUI_tcpFrame.flag.text()
            print(flag)
            flag1 = self.subUI_tcpFrame.flag1.text()
            print(flag1)
            srcipInput = self.subUI_tcpFrame.srcipInput.text()
            print(srcipInput)
            srcportInput = self.subUI_tcpFrame.srcportInput.text()
            print(srcportInput)
            destportInput = self.subUI_tcpFrame.destportInput.text()
            print(destportInput)
            destipInput = self.subUI_tcpFrame.destipInput.text()
            print(destipInput)
            QMessageBox.information(self.subUI_tcpFrame, "提示", f'即将开始向目的IP：{destipInput}地址连续发送数据帧！')

            payload = self.subUI_tcpFrame.payload.toPlainText()
            print(payload)
            #count = self.subUI_udpFrame.countInput.text()
            try:
                ippkg = IP()
                tcppkg = TCP()
                tcppkg1 = TCP()
                if seq != '':
                    tcppkg.seq = int(seq)
                if flag != '':
                    tcppkg.flags = flag
                if flag1 != '':
                    tcppkg1.flags = flag1
                if srcportInput != '':
                    tcppkg.sport = int(srcportInput)
                    tcppkg1.sport = int(srcportInput)
                if srcipInput != '':
                    ippkg.src = srcipInput
                if destportInput != '':
                    tcppkg.dport = int(destportInput)
                    tcppkg1.dport = int(destportInput)
                if destipInput != '':
                    ippkg.dst = destipInput
                tcpFrame = ippkg / tcppkg / payload
                tcpFrame1 = ippkg / tcppkg1 / payload
                tcpFramefoStr = '待发送信息\n' + \
                                'seq:' + seq + '\n' + \
                                'flags:' + flag + '\n' + \
                                'second flags:' + flag1 + '\n' + \
                                'sport:' + srcportInput + '\n' + \
                                'src:' + ippkg.src + '\n' + \
                                'dport:' + destportInput + '\n' + \
                                'dst:' + ippkg.dst + '\n' + \
                                'payload:' + payload + '\n'
                print(tcpFramefoStr)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_tcpFrame.resultText, tcpFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_tcpFrame.resultText, str(tcpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendTCPFrameThread, args=(tcppkg, ippkg, tcppkg1, payload))
                t.setDaemon(True)
                t.start()
                self.subUI_tcpFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_tcpFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_tcpFrame.sendContPushButton.setText("连续发送")

    def continueSendUDPFrame(self):
        buttonInfo = self.subUI_udpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            dstip = self.subUI_udpFrame.destipInput.text()
            QMessageBox.information(self.subUI_udpFrame, "提示", f'即将开始向目的IP：{dstip}地址连续发送数据帧！')
            srcipInput = self.subUI_udpFrame.srcipInput.text()
            print(srcipInput)
            srcportInput = self.subUI_udpFrame.srcportInput.text()
            print(srcportInput)
            destportInput = self.subUI_udpFrame.destportInput.text()
            print(destportInput)
            destipInput = self.subUI_udpFrame.destipInput.text()
            print(destipInput)
            payload = self.subUI_udpFrame.payload.toPlainText()
            print(payload)
            #count = self.subUI_udpFrame.countInput.text()
            try:
                ippkg = IP()
                udppkg = UDP()
                if srcportInput != '':
                    udppkg.sport = int(srcportInput)
                if srcipInput != '':
                    ippkg.src = srcipInput
                if destportInput != '':
                    udppkg.dport = int(destportInput)
                if destipInput != '':
                    ippkg.dst = destipInput
                udpFrame = ippkg / udppkg / payload
                udpFramefoStr = '待发送信息\n' + \
                                'sport:' + srcportInput + '\n' + \
                                'src:' + ippkg.src + '\n' + \
                                'dport:' + destportInput + '\n' + \
                                'dst:' + ippkg.dst + '\n' + \
                                'payload:' + payload + '\n'
                print(udpFramefoStr)
                # self.subUI_udpFrame.resultText.append(udpFramefoStr)
                # self.subUI_udpFrame.resultText.append(str(udpFramefoStr) + '\n')
                # self.subUI_macFrame.resultText.append(etherFrameInfoStr)
                # self.subUI_macFrame.resultText.append(str(etherFrame)+'\n')
                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_udpFrame.resultText, udpFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_udpFrame.resultText, str(udpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendUDPFrameThread, args=(udpFrame,))
                t.setDaemon(True)
                t.start()
                self.subUI_udpFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_udpFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_udpFrame.sendContPushButton.setText("连续发送")

    def continueSendHTTPFrame(self):
        buttonInfo = self.subUI_httpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            seq = self.subUI_httpFrame.seq.text()
            print(seq)
            flag = self.subUI_httpFrame.flag.text()
            print(flag)
            flag1 = self.subUI_httpFrame.flag1.text()
            print(flag1)
            srcipInput = self.subUI_httpFrame.srcipInput.text()
            print(srcipInput)
            srcportInput = self.subUI_httpFrame.srcportInput.text()
            print(srcportInput)
            destportInput = self.subUI_httpFrame.destportInput.text()
            print(destportInput)
            destipInput = self.subUI_httpFrame.destipInput.text()
            print(destipInput)
            payload = self.subUI_httpFrame.payload.text()
            print(payload)
            QMessageBox.information(self.subUI_httpFrame, "提示", f'即将开始向目的IP：{destipInput}地址连续发送数据帧！')

            payload = self.subUI_httpFrame.payload.text()
            print(payload)
            #count = self.subUI_udpFrame.countInput.text()
            try:
                ippkg = IP()
                tcppkg = TCP()
                tcppkg1 = TCP()
                if seq != '':
                    tcppkg.seq = int(seq)
                if flag != '':
                    tcppkg.flags = flag
                if flag1 != '':
                    tcppkg1.flags = flag1
                if srcportInput != '':
                    tcppkg.sport = int(srcportInput)
                    tcppkg1.sport = int(srcportInput)
                if srcipInput != '':
                    ippkg.src = srcipInput
                if destportInput != '':
                    tcppkg.dport = int(destportInput)
                    tcppkg1.dport = int(destportInput)
                if destipInput != '':
                    ippkg.dst = destipInput
                httpFrame = ippkg / tcppkg
                httpFramefoStr = '待发送信息\n' + \
                                 'seq:' + seq + '\n' + \
                                 'flags:' + flag + '\n' + \
                                 'second flags:' + flag1 + '\n' + \
                                 'sport:' + srcportInput + '\n' + \
                                 'src:' + ippkg.src + '\n' + \
                                 'dport:' + destportInput + '\n' + \
                                 'dst:' + ippkg.dst + '\n' + \
                                 'http content:' + payload + '\n'
                print(httpFramefoStr)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_httpFrame.resultText, httpFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_httpFrame.resultText, str(httpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendHTTPFrameThread, args=(tcppkg, ippkg, tcppkg1, payload))
                t.setDaemon(True)
                t.start()
                self.subUI_httpFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_httpFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_httpFrame.sendContPushButton.setText("连续发送")

    def continueSendDNSFrame(self):
        buttonInfo = self.subUI_dnsFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            destipInput = self.subUI_dnsFrame.destipInput.text()
            print(destipInput)
            QMessageBox.information(self.subUI_dnsFrame, "提示", f'即将开始向目的IP：{destipInput}地址连续发送数据帧！')
            qtype = self.subUI_dnsFrame.qtype.text()
            print(qtype)
            qname = self.subUI_dnsFrame.qname.text()
            print(qname)
            rd = self.subUI_dnsFrame.rd.text()
            print(rd)
            srcipInput = self.subUI_dnsFrame.srcipInput.text()
            print(srcipInput)
            srcportInput = self.subUI_dnsFrame.srcportInput.text()
            print(srcportInput)
            destportInput = self.subUI_dnsFrame.destportInput.text()
            print(destportInput)

            payload = self.subUI_dnsFrame.payload.toPlainText()
            print(payload)
            #count = self.subUI_udpFrame.countInput.text()
            try:
                ippkg = IP()
                udppkg = UDP()
                dnspkg = DNS()
                qd = DNSQR()
                dnspkg.qd = qd
                if qtype != '':
                    qd.qtype = qtype
                if qname != '':
                    qd.qname = qname
                if rd != '':
                    dnspkg.rd = int(rd)
                if srcportInput != '':
                    udppkg.sport = int(srcportInput)
                if srcipInput != '':
                    ippkg.src = srcipInput
                if destportInput != '':
                    udppkg.dport = int(destportInput)
                if destipInput != '':
                    ippkg.dst = destipInput
                dnsFrame = ippkg / udppkg / dnspkg / payload
                dnsFramefoStr = '待发送信息\n' + \
                                'sport:' + srcportInput + '\n' + \
                                'src:' + ippkg.src + '\n' + \
                                'dport:' + destportInput + '\n' + \
                                'dst:' + ippkg.dst + '\n' + \
                                'qtype:' + qtype + '\n' + \
                                'qname:' + qname + '\n' + \
                                'rd:' + rd + '\n' + \
                                'payload:' + payload + '\n'
                print(dnsFramefoStr)
                print(dnsFrame)

                # 将上面的输出语句修改为信号发送语句
                self.global_ms.textEdit_print.emit(self.subUI_dnsFrame.resultText, dnsFramefoStr)
                self.global_ms.textEdit_print.emit(self.subUI_dnsFrame.resultText, str(dnsFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                self.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=self.sendDNSFrameThread, args=(dnsFrame,))
                t.setDaemon(True)
                t.start()
                self.subUI_dnsFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(self.subUI_dnsFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            self.stopSending.set()
            self.subUI_dnsFrame.sendContPushButton.setText("连续发送")

    def sendEtherFrameThread(self, etherFrame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                sendp(etherFrame)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_macFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(1)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_macFrame, "错误", "发送数据失败\n")

    def sendARPFrameThread(self, arpFrame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                sendp(arpFrame)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_arpFrame.resultText, '发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(1)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_arpFrame, "错误", "发送数据失败\n")

    def sendIPFrameThread(self, ipFrame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                sendp(ipFrame)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_ipFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(1)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_ipFrame, "错误", "发送数据失败\n")

    def sendICMPFrameThread(self, frame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                ping1 = sr1(frame, timeout=2, verbose=False)
                count = count + 1
                if ping1:
                    self.global_ms.textEdit_print.emit(self.subUI_icmpFrame.resultText, f'发送成功{str(count)}包\n')
                    print("成功发送第" + str(count) + '帧\n')
                else:
                    self.global_ms.textEdit_print.emit(self.subUI_icmpFrame.resultText, f'发送失败{str(count)}包\n')
                    print("失败发送第" + str(count) + '包\n')
                time.sleep(2)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_icmpFrame, "错误", "发送数据失败\n")

    def sendTCPFrameThread(self, tcppkg, ippkg, tcppkg1, payload):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                tcpFrame = ippkg / tcppkg / payload
                SYNACK = sr1(tcpFrame)
                tcppkg1.seq = SYNACK.ack
                tcppkg1.ack = SYNACK.seq + 1
                send(ippkg / tcppkg1 / payload)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_tcpFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(2)
                tcppkg.seq = tcppkg.seq+1
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_tcpFrame, "错误", "发送数据失败\n")

    def sendUDPFrameThread(self, frame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                send(frame)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_udpFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(2)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_udpFrame, "错误", "发送数据失败\n")

    def sendHTTPFrameThread(self, tcppkg, ippkg, tcppkg1, payload):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                tcpFrame = ippkg / tcppkg / payload
                SYNACK = sr1(tcpFrame)
                tcppkg1.seq = SYNACK.ack + 1
                tcppkg1.ack = SYNACK.seq + 1
                send(ippkg / tcppkg1 / payload)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_httpFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(2)
                tcppkg.seq = tcppkg.seq+1
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_httpFrame, "错误", "发送数据失败\n")



    def sendDNSFrameThread(self, frame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        self.stopSending.clear()
        while not self.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                send(frame)
                count = count + 1
                self.global_ms.textEdit_print.emit(self.subUI_dnsFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(2)
            except Exception as e:
                print(e)
                QMessageBox.critical(self.subUI_dnsFrame, "错误", "发送数据失败\n")




    def calculateIPChksum(self, ip_packet_payload, payload):
        ip_packet_payload.chksum = 0
        ip_packet_payload[IP].show
        print("/n 报文长度是： %s" % str(ip_packet_payload.len))
        y = raw(ip_packet_payload)
        ipString = "".join("%02x" % orb(y) for y in y)
        print("ipString=======" + ipString)
        ipbytes = bytearray.fromhex(ipString)
        print("aaaaaaaa=======" + ipString)
        checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
        #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
        ip_packet_payload.chksum = checksum_changed_self
        return checksum_changed_self
        # print("改变数据长度后IP首部的校验和是 : %04x (%s)" % (checksum_changed_self, str(checksum_changed_self)))
        # if chsum_scapy == checksum_changed_self:
        #     print("校验和正确")
        # else:
        #     print("校验和不正确")
        # ip_packet_payload.chksum = checksum_changed_self





    def calculateICMPChksum(self, icmp_packet_payload, payload):
        icmp_packet_payload.chksum = 0
        icmp_packet_payload[ICMP].show
        print("/n 报文长度是： %s" % str(icmp_packet_payload.len))
        y = raw(icmp_packet_payload)
        icmpString = "".join("%02x" % orb(y) for y in y)
        #print("ipString=======" + ipString)
        ipbytes = bytearray.fromhex(icmpString)
        icmplen = len(icmp_packet_payload)
        checksum_changed_self = self.IP_headchecksum(ipbytes[0:icmplen])
        #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
        return checksum_changed_self


    def calculateTCPChksum(self, ip_packet, tcp_packet_payload):
        y = raw(ip_packet)
        ipString = "".join("%02x" % orb(y) for y in y)
        ipbytes = bytearray.fromhex(ipString)

        tcp_len = len(tcp_packet_payload)
        #计算UDP
        z = raw(tcp_packet_payload)
        tcpString = "".join("%02x" % orb(z) for z in z)
        # print("ipString=======" + ipString)
        tcpbytes = bytearray.fromhex(tcpString)
        # for i in udpbytes:
        #     print(str(i)+" ")
        print("========================================")
        tcp_content = []
        print(ipbytes[12])
        print(ipbytes[13])
        print(ipbytes[14])
        print(ipbytes[15])
        #IP源地址为IP报文的13、14、15、16字节
        tcp_content.append(ipbytes[12])
        tcp_content.append(ipbytes[13])
        tcp_content.append(ipbytes[14])
        tcp_content.append(ipbytes[15])
        #IP目的地址为IP报文的17、18、19、20字节
        tcp_content.append(ipbytes[16])
        tcp_content.append(ipbytes[17])
        tcp_content.append(ipbytes[18])
        tcp_content.append(ipbytes[19])
        tcp_content.append(0x00)
        # 协议类型
        tcp_content.append(0x06)
        #udp_content.append(0x00)
        #udp_content.append(0x0d)
        hight = tcp_len/256
        #TCP 长度
        tcp_content.append(int(tcp_len/256))
        tcp_content.append(tcp_len%256)
        #tcp_content.append(0x00)
        #tcp_content.append(0x14)
        for i in range(tcp_len):
            tcp_content.append(ipbytes[20 + i])

        tcp_content[28] = 0  # 把原来的校验和设置为0
        tcp_content[29] = 0
        if tcp_len % 2 == 1:  # 整个报文长度为奇数需要补充0
            tcp_content.append(0x00)

        print('需要计算的TCP校验和内容为：' + str(tcp_len))

        checksum_changed_self = self.calc_checksum(tcp_content)
        #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
        return checksum_changed_self


    def calculateUDPChksum(self, ip_packet,udp_packet_payload):
        #udp_packet_payload.chksum = 0
        #udp_packet_payload[UDP].show

        #print("/n 报文长度是： %s" % str(icmp_packet_payload.len))
        y = raw(ip_packet)
        ipString = "".join("%02x" % orb(y) for y in y)
        # print("ipString=======" + ipString)
        ipbytes = bytearray.fromhex(ipString)
        # for i in ipbytes:
        #     print(str(i)+" ")

        UDP_len = len(udp_packet_payload)
        #计算UDP
        z = raw(udp_packet_payload)
        udpString = "".join("%02x" % orb(z) for z in z)
        # print("ipString=======" + ipString)
        udpbytes = bytearray.fromhex(udpString)
        # for i in udpbytes:
        #     print(str(i)+" ")
        print("========================================")
        udp_content = []
        print(ipbytes[12])
        print(ipbytes[13])
        print(ipbytes[14])
        print(ipbytes[15])
        #IP源地址为IP报文的13、14、15、16字节
        udp_content.append(ipbytes[12])
        udp_content.append(ipbytes[13])
        udp_content.append(ipbytes[14])
        udp_content.append(ipbytes[15])
        #IP目的地址为IP报文的17、18、19、20字节
        udp_content.append(ipbytes[16])
        udp_content.append(ipbytes[17])
        udp_content.append(ipbytes[18])
        udp_content.append(ipbytes[19])
        udp_content.append(0x00)
        udp_content.append(0x11)
        #udp_content.append(0x00)
        #udp_content.append(0x0d)
        udp_content.append(ipbytes[20 + 4])
        udp_content.append(ipbytes[20 + 5])
        for i in range(UDP_len):
            udp_content.append(ipbytes[20 + i])



        # UDP数据长度是UDP报文中的第5、6字节
        # udp_content.append(ipbytes[20 + 4])
        # udp_content.append(ipbytes[20 + 5])
        # # 协议类型是IP报文的第10字节
        # udp_content.append(0x00)
        # udp_content.append(ipbytes[9])
        # UDP_Len = len(udpbytes)
        # for i in range(UDP_Len):
        #     udp_content.append(ipbytes[5 + i])
        udp_content[18] = 0  # 把原来的校验和设置为0
        udp_content[19] = 0
        if UDP_len % 2 == 1:  # 整个报文长度为奇数需要补充0
            udp_content.append(0x00)

        print('需要计算的UDP校验和内容为：' + str(udp_content))

        checksum_changed_self = self.calc_checksum(udp_content)
        #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
        return checksum_changed_self

    def calc_checksum(self, sum_data):
         join_sum_data = []
         for i in range(0, len(sum_data), 2):    #先需要将前后二个数合并成16位长度的16进制的数
             first_part = str(hex(sum_data[i]))[2:]    #10进制转换为16进制，长度为8位
             if len(first_part) < 2:    #如果转换为16进制后只有1位需要高位补0操作
                 first_part = '0' + first_part

             second_part = str(hex(sum_data[i + 1]))[2:]    #10进制转换为16进制，长度为8位
             if len(second_part) < 2:    #如果转换为16进制后只有1位需要高位补0操作
                 second_part = '0' + second_part

             total_part = first_part + second_part    #合并成16位长度

             join_sum_data.append(int(total_part, 16))    #重新把16进制转换为10进制
             #join_sum_data.append(total_part)

         #print(join_sum_data)

         sum_result = 0
         for single_value in join_sum_data:
             sum_result = sum_result + single_value    #计算所有数的和

         hex_sum_result = str(hex(sum_result))[2:]    #转变为4字节32位的十六进制格式

         len_hex_sum = len(hex_sum_result)    #取得字节数

         if len_hex_sum > 4:    #求和的结果大于2个字节16位的话，分割成二个2字节16位数
             first_part = int(hex_sum_result[:len_hex_sum - 4], 16)    #分割第一、二字节的十六进制数字，转换为10进制

             second_part = int(hex_sum_result[len_hex_sum - 4:], 16)    #分割第三、四字节的十六进制数字，转换为10进制

             last_check_sum = str(hex(0xffff - (first_part + second_part)))[2:]    #二个字节的十六进制数之和取反
             return last_check_sum
         else:
             last_check_sum = str(hex(65535 - sum_result))[2:]    #只有二个字节的十六进制数直接取反就好了
             return last_check_sum



    def IP_headchecksum(self, IP_head):
        checksum = 0
        print("gggggg===")
        headlen = len(IP_head)
        print("headlen===" + str(headlen))
        if headlen % 2 == 1:
            IP_head += b"\0"

        i = 0
        while i < headlen:
            temp = struct.unpack('!H', IP_head[i:i + 2])[0]
            checksum = checksum + temp
            i = i + 2
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = checksum + (checksum >> 16)
        return ~checksum & 0xffff




if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = Send_PDU()
    main.ui.show()
    sys.exit(app.exec_())
