from PySide6.QtWidgets import QApplication, QMessageBox, QMdiSubWindow, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QObject, Signal

from threading import Thread
import sys
import time
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP,ICMP, TCP, UDP

class Send_UDP(QObject):
    def __init__(self):
        QObject.__init__(self)

    def sendUDPFrame(self, parent):
        print("=============Enter sendUDPFrame")
        srcipInput = parent.subUI_udpFrame.srcipInput.text()
        print(srcipInput)
        srcportInput = parent.subUI_udpFrame.srcportInput.text()
        print(srcportInput)
        destportInput = parent.subUI_udpFrame.destportInput.text()
        print(destportInput)
        destipInput = parent.subUI_udpFrame.destipInput.text()
        print(destipInput)
        payload = parent.subUI_udpFrame.payload.toPlainText()
        print(payload)
        count = parent.subUI_udpFrame.countInput.text()
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
            parent.subUI_udpFrame.resultText.append(udpFramefoStr)
            parent.subUI_udpFrame.resultText.append(str(udpFrame) + '\n')

            # 提高并发但有风险的输出线程
            def run():
                # 在多行文本框text中显式发送帧的信息
                e = Ether()
                for i in range(int(count)):
                    send(ippkg / udppkg / payload)
                    #sr1(e/arpFrame)
                    parent.subUI_udpFrame.resultText.append('成功发送' + str(i+1) + ' ARP帧。\n')

            t = Thread(target=run)
            t.start()

        except ValueError as e:
            print(e)
            QMessageBox.critical(parent.subUI_udpFrame, "错误", "赋值异常，发送失败\n")
        except Exception as e:
            QMessageBox.critical(parent.subUI_udpFrame, "错误", "发送数据失败\n")
        finally:
            pass

    def continueSendFrame(self, parent):
        buttonInfo = parent.subUI_udpFrame.sendContPushButton.text()
        if buttonInfo == '连续发送':
            dstip = parent.subUI_udpFrame.dstipInput.text()
            payLoad = parent.subUI_udpFrame.payloadInput.toPlainText()
            QMessageBox.information(parent.subUI_udpFrame, "提示", f'即将开始向目的IP：{dstip}地址连续发送数据帧！')
            srcipInput = parent.subUI_udpFrame.srcipInput.text()
            print(srcipInput)
            srcportInput = parent.subUI_udpFrame.srcportInput.text()
            print(srcportInput)
            destportInput = parent.subUI_udpFrame.destportInput.text()
            print(destportInput)
            destipInput = parent.subUI_udpFrame.destipInput.text()
            print(destipInput)
            payload = parent.subUI_udpFrame.payload.toPlainText()
            print(payload)
            count = parent.subUI_udpFrame.countInput.text()
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
                #self.subUI_udpFrame.resultText.append(udpFramefoStr)
                #self.subUI_udpFrame.resultText.append(str(udpFramefoStr) + '\n')
                # self.subUI_macFrame.resultText.append(etherFrameInfoStr)
                # self.subUI_macFrame.resultText.append(str(etherFrame)+'\n')
                # 将上面的输出语句修改为信号发送语句
                parent.global_ms.textEdit_print.emit(parent.subUI_udpFrame.resultText, udpFramefoStr)
                parent.global_ms.textEdit_print.emit(parent.subUI_udpFrame.resultText, str(udpFrame) + '\n')
                # 在多行文本框text中显示发送帧的信息
                parent.stopSending = threading.Event()  # 用来终止数据包发送线程的线程事件
                t = threading.Thread(target=parent.sendFrameThread, args=(udpFrame,))
                t.setDaemon(True)
                t.start()
                parent.subUI_macFrame.sendContPushButton.setText("停止连续发送")
            except ValueError as e:
                QMessageBox.critical(parent.subUI_macFrame, "错误", "赋值异常，发送失败\n")
            finally:
                pass
        else:
            # 终止数据包发送线程
            parent.stopSending.set()
            parent.subUI_macFrame.sendContPushButton("连续发送")

    def sendFrameThread(parent, frame):
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        parent.stopSending.clear()
        while not parent.stopSending.is_set():  # 判断event的标志是否为true，即是否点击“停止”按键
            try:
                sendp(frame)
                count = count + 1
                parent.global_ms.textEdit_print.emit(parent.subUI_udpFrame.resultText, f'发送成功{str(count)}帧\n')
                print("成功发送第" + str(count) + '帧\n')
                time.sleep(1)
            except Exception as e:
                print(e)
                QMessageBox.critical(parent.subUI_udpFrame, "错误", "发送数据失败\n")