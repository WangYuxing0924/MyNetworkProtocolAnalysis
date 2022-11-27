from PySide6.QtWidgets import QApplication,QMessageBox,QMdiSubWindow,QListView,QTextEdit,QTreeWidget,QTreeWidgetItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QObject,QStringListModel

from threading import Thread

from scapy.all import *
from scapy.layers.l2 import Ether

class Sniff_PDU(QObject):

    def __init__(self):
        QObject.__init__(self)
        self.count=0
        self.sniffFlag=True #设置控制捕获线程运行的标志变量
        self.sniffDataList=[] #设置存放捕获PDU的变量
        self.sniffDataSumList=[] #设置存放捕获PDU摘要信息的变量
        #从pyside6文件加载UI定义
        self.ui=QUiLoader().load('ui/sniffPDUGUI.ui')
        self.slm=QStringListModel()
        self.ui.listView.setModel(self.slm)
        self.ui.listView.chilked.connect(self.choosedPDUAnalysis)

        self.ui.stsrtListButton.clicked.connet(self.start_sniff)
        self.ui.stopListButton.clicked.connet(self.stop_sniff)
        self.ui.clearButton.clicked.connect(self.clearData)

    #启动捕获线程
    def start_sniff(self):
        if self.sniffFlag is True:
            answer=QMessageBox.question(self.ui,"确认","是否开始报文捕获？")
            if answer == QMessageBox.No:
                print("停止报文捕获")
                return
            else:
                print("开始新的报文捕获！")
                self.ui.startListenButton.setEnabled(False)
                self.ui.stopListrnButton.setEnables(True)
                self.sniffFlag=False
                t=Thread(target=self.sniff_PDU,name='LoopThread')
                t.start()

    def sniff_PDU(self):
        sniffNum=int(self.ui.countInput.text())
        if sniffNum>0:
            sniff(prn=(lambda x:self.ether_monitor_callback(x) ),stop_filter=(lambda x:self.sniffFlag),count=sniffNum)
            self.stop_sniff()
        elif sniffNum==0:
            sniff(prn=(lambda x: sniff.ether_monitor_callback(x)),stop_filter=(lambda x: self.sniffFlag))
        else:
            QMessageBox.critical(self.ui,"警告",'捕获报文数必须大于等于0！(0:表示一直捕获)')
            self.stop_sniff()

    #捕获PDU的回调函数
    def ether_monitor_callback(self,pkt):
        self.count+=1
        pkt(SummaryInfo=str(self.count)+' '+pkt.summary())
        print(pktSummaryInfo)
        self.sniffDataList.append(pkt) #把sniff函数抓取到的数据报加入到捕获队列里面
        self.slm.setStringList(self.sniffDataSumList)
        time.sleep(1)

    #停止捕获线程
    def stop_sniff(self):
        self.ui.startListenButton.setEnabled(True)
        self.ui.stopListenButton.setEnabled(False)
        self.sniffFlag=True

    #清空捕获数据
    def clearData(self):
        if self.sniffFlag is True:
            self.sniffDataList=[]
            self.sniffDataSumList=[]
            self.slm.setStringList(self.sniffDataSumList)
            self.ui.PDUAnalysisTree.clear()
            self.ui.PUDCodeText.clear()
            self.count=0
        else:
            QMessageBox.information(self.ui,"友情提示","请先停止捕获！！")
    def choosedPDUAnalysis(self,qModelIndex):
        choosePDUNum=qModelIndex.row()
        #print("第"+str(choosePDUNum)+"个PDU需要详细解析")
        choosedPacket=self.sniffDataList[choosePDUNum]
        #print(choosedPacket.summary())
        self.ui.PDUAnalysisTree.clear()
        root=QTreeWidgetItem(self.ui.PDUAnalysisTree)
        root.setText(0,"数据链路层")

        child1=QTreeWidgetItem(root)
        child1.setText(0,'目的MAC: '+choosedPacket[Ether].dst+'\n')

        child2 = QTreeWidgetItem(root)
        child2.setText(0, '源MAC: ' + choosedPacket[Ether].src + '\n')

        child3 = QTreeWidgetItem(root)
        child3.setText(0, '上层协议类型: ' + str(choosedPacket[Ether].type) + '\n')

        child4 = QTreeWidgetItem(root)
        child4.setText(0, '数据: ' + str(choosedPacket[Ether].payload) + '\n')

        self.ui.PDUAnalysisTree.addTopLevelItem(root)
        self.ui.PDUCodeText.setText(hexdump(choosedPacket,dump=True))

app=QApplication([])
sniff_PDU=Sniff_PDU()
sniff_PDU.ui.show()
app.exec_()
