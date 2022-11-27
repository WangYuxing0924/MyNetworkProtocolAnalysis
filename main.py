# This is a sample Python script.
from PySide6.QtWidgets import QApplication, QMessageBox, QMdiSubWindow, QTextEdit, QTreeWidget, QTreeWidgetItem
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QObject, Signal

from threading import Thread
import sys
import time
from scapy.all import *
from scapy.layers.inet6 import IPv6, IP6Field, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP,ICMP, TCP, UDP
import random

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def http():
    # sport = random.randint(1024, 65535)
    # # SYN
    # ip = IP(dst='192.168.1.1')
    # SYN = TCP(sport=sport, dport=80, flags='S', seq=1000)
    # SYNACK = sr1(ip / SYN)
    #
    # # SYN-ACK
    # ACK = TCP(sport=sport, dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    # send(ip / ACK)
    # getStr = 'GET /login.html HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
    # sr1(IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport, seq=ACK[TCP].ack, ack=ACK[TCP].seq + 1,
    #                                 flags='P''A') / getStr)
    getStr = 'GET /login.html HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
    #getStr = 'GET /login.html HTTP/1.1\r\nHost: 104.193.88.123\r\n\r\n'

    dest = '192.168.1.1'
    sport = random.randint(1024, 65535)

    syn = IP(dst=dest) / TCP(sport=38888, dport=80, flags='S')
    # GET SYNACK
    syn_ack = sr1(syn)
    # Send ACK
    out_ack = send(
        IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1,
                           flags='A'))
    # Send the HTTP GET
    sr1(IP(dst=dest) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1,
                           flags='P''A') / getStr)



    #syn = IP(dst='192.168.1.1') / TCP(dport=80, flags='S')
    #syn_ack = sr1(syn)
    # Send ACK
    #out_ack = send(IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A'))
#    getStr = 'GET /login.html HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'

    # Send the HTTP GET
 #   sr1(IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='P''A') / getStr)
    #request = IP(dst='192.168.1.1') / TCP(dport=80, sport=syn_ack[TCP].dport,
    #seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / getStr
    #reply = sr1(request)
    #reply.summary()
    #reply.show()

def dns():
    print("Enter DNS")
    packet = IP(dst="192.168.1.1") / ICMP()
    print("Enter DNS 11111")
    res = sr1(packet)
    print("Enter DNS 2222"+str(res))
    if res:
        print("---------------------------------------")
        print("Host is Up, trying DNS Query")
        print("---------------------------------------")
        dnspkg = DNS()
        dnspkg.rd = 1
        #qd = DNSQR(qtype="A", qname="www.baidu.com")
        qd = DNSQR()
        qd.qtype = "A"
        qd.qname = "www.baidu.com"
        dnspkg.qd = qd
        packet = IP(dst="192.168.1.1") / UDP(sport=80, dport=53) / dnspkg
        sr1(packet)
    else:
        print("Destination Unreachable!")

def ping():
    ip1 = '9.197.243.1'
    package = IP(dst=ip1)
    sendp(package)

#    result, unanswer = sr(package, timeout=0.01, verbose=0)
#    for res, rcv in result:
#        scan_ip = rcv[IP].src
#        print
#        scan_ip + '--->' 'lived'

def ping_one():
    ip_id = random.randint(1, 65535)
    print("ip_id:"+str(ip_id))
    ip_id = 37905
    icmp_id = random.randint(1, 65535)
    icmp_seq = random.randint(1, 65535)
    icmp_seq=1
    payload = "aaaaaa"
    icmp = ICMP()
    icmp.id=1
    icmp.seq=1
    package = IP(dst='192.168.1.1')/ icmp /payload
    ping1 = sr1(package, timeout=2, verbose=False)
#    ping1 = sendp(package)
    if ping1:
        print("is online")
        return 0
    else:
        print("error")
        return -1


def ping_trail():
#    conf.L3socket
#    conf.L3socket = L3RawSocket
    package = IP(dst="192.168.1.1")/ICMP()
    reply = sr1(package)
    if not (reply is None):
        print(reply.dst, "is online")
    else:
        print("error")
    #print(reply.src)

def tcp(name):
    dst_ip = "192.168.1.1"
    #src_port = RandShort()
    src_port = 9999
    dst_port = 80

    ping_res = ping_one(dst_ip)
    if ping_res == -1:
        print('设备' + dst_ip + '不可达')
    else:
        print("设备"+dst_ip+"可达")
        syn = IP(dst=dst_ip) / TCP(dport=(int(80), int(80)), flags=2)
        print("aaaa")
        result_raw = sr(syn, timeout=10, verbose=False)
        print("bbbbb")
        # 取出收到结果的数据包，做成一个清单
        result_list = result_raw[0].res
        print("result_list===" + str(len(result_list)))
        for i in range(len(result_list)):
            # 判断清单的第i个回复的接受到的数据包，并判断是否有TCP字段
            if (result_list[i][1].haslayer(TCP)):
                # 得到TCP字段的头部信息
                TCP_Fields=result_list[i][1].getlayer(TCP).fields
                # 判断头部信息中的flags标志是否为18(syn+ack)
                print("TCP_Fields['flags']" + str(TCP_Fields['flags']))
                if TCP_Fields['flags'] == 18:
                    print('端口号: ' + str(TCP_Fields['sport']) + ' is Open!!!')

def tcp1():

    sport = random.randint(1024,65535)
    # SYN
    ip = IP(src='192.168.1.3', dst='192.168.1.1')
    tcp = TCP(sport=sport, dport=80, flags='S', seq=1000)
    ip_tcp= ip/tcp
    checksum_changed_self = calculateTCPChksum(ip_tcp, tcp)
    print("改变数据长度后TCP首部的校验和是" + str(checksum_changed_self))

    SYNACK = sr1(ip_tcp)
    payload = '1234'
    # SYN-ACK
    tcp2 = TCP(sport=sport, dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    ip_tcp2 = ip / tcp2 /payload

    send(ip_tcp2)
    checksum_changed_self = calculateTCPChksum(ip_tcp2, tcp2/payload)
    print("改变数据长度后TCP首部的校验和是" + str(checksum_changed_self))

def udp():
    #Ether(src="ab:ab:ab:ab:ab:ab", dst="12:12:12:12:12:12")
    #/ IP(src="127.0.0.1", dst="192.168.1.1")
    #/ UDP(sport=80, dport=5355)
    #conf.L3socket = L3RawSocket
    ippkg = IP()
    udppkg = UDP()
    udppkg.dport = 53
    udppkg.sport = 47777
    ippkg.src = "192.168.1.3"
    ippkg.dst = "192.168.1.1"
    payload = '12345'
    udppkg = udppkg / payload
    udppkg1 = ippkg/ udppkg
    print("===========udp show2=========")
    udppkg1.show2()
    y = raw(udppkg1)
    udpraw = UDP(y)
    print("===========udp show=========")
    udpraw.show()
    # print("icmp_packet_payload len:" + str(icmp.len))
    chsum_scapy = udpraw[UDP].chksum
    print("添加数据后scapy自动计算的ICMP首部校验和是: %04x (%s)" % (chsum_scapy, str(chsum_scapy)))

    checksum_changed_self = calculateUDPChksum(udppkg1,udppkg)
    print("改变数据长度后IP首部的校验和是"+str(checksum_changed_self))
    #print("改变数据长度后IP首部的校验和是: %04x (%s)" % (checksum_changed_self, checksum_changed_self))
    #udppkg.chksum=checksum_changed_self
    #udppkg1.chksum = checksum_changed_self
    send(udppkg1)
    #send(IP(dst="192.168.1.1") / UDP(dport=68) / "aaaaaa")

def calculateUDPChksum(ip_packet,udp_packet_payload):
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

    checksum_changed_self = calc_checksum(udp_content)
    #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
    return checksum_changed_self

def calculateTCPChksum(ip_packet,tcp_packet_payload):
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

    checksum_changed_self = calc_checksum(tcp_content)
    #checksum_changed_self = self.IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
    return checksum_changed_self


def calc_checksum(sum_data):
     join_sum_data = []
     for i in range(0, len(sum_data), 2):    #先需要将前后二个数合并成16位长度的16进制的数
         print("i=========="+str(i))
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


def ip(name):
    e = Ether()
    ip_packet = IP(dst='192.168.1.1',src='192.168.1.3')
    ip_packet.show()
    sendp(e/ip_packet)

def ip_1():
    #ip = IP(dst='192.168.1.1',src='192.168.1.3')
    ip=IP()
    e = Ether()
    ip.version=4
    ip.ihl=5
    ip.tos=0
    ip.len=20
    ip.id=1
    ip.flags=0
    ip.frag=0
    ip.ttl=64
    ip.proto=4

    #ip.chksum=0xf794
    ip.src='192.168.1.3'
    ip.dst='192.168.1.1'
    payload='pppppppppppppppp'
    ip.len = 20+len(payload)
    ip_packet_payload = ip / payload
    ip_packet_payload.show()

    y=raw(ip_packet_payload)
    ipraw=IP(y)
    ipraw.show()
    print("ip_packet_payload len:" + str(ip_packet_payload.len))
    chsum_scapy=ipraw[IP].chksum
    print("添加数据后scapy自动计算的IP首部校验和是: %04x (%s)" %(chsum_scapy, str(chsum_scapy)))
    #print("ip_packet_payload.len======="+str(ip_packet_payload.len))


    #ip_packet_payload.len = 20+len(payload)
    #ip_packet_payload.len = 20
    ip_packet_payload.chksum=0
    ip_packet_payload.ihl=5
    ip_packet_payload[IP].show
    print("/n 报文长度是： %s" %str(ip_packet_payload.len+len(payload)))
    y=raw(ip_packet_payload)
    ipString = "".join("%02x" % orb(y) for y in y)
    print("ipString====sss==="+ipString)
    ipbytes = bytearray.fromhex(ipString)
    #checksum_changed_self = ip_checksum(ipbytes[0:20], 20)
    #checksum_changed_self = ip_checksum(ipbytes[0:ip_packet_payload.ihl*4], 20)
    checksum_changed_self = IP_headchecksum(ipbytes[0:ip_packet_payload.ihl * 4])
    print("改变数据长度后IP首部的校验和是 : %04x (%s)" %(checksum_changed_self, str(checksum_changed_self)))
    if chsum_scapy == checksum_changed_self:
        print("校验和正确")
    else:
        print("校验和不正确")
    ip_packet_payload.chksum =  checksum_changed_self

    sendp(e/ip)


def ip_checksum(ip_header, size):
    cksum = 0
    pointer = 0

    # The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
    # together, converted to integers, and then added to the sum.
    while size > 1:
        cksum += int((str("%02x" % (ip_header[pointer],)) +
                      str("%02x" % (ip_header[pointer + 1],))), 16)
        size -= 2
        pointer += 2
    if size:  # This accounts for a situation where the header is odd
        cksum += ip_header[pointer]

    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)

    return (~cksum) & 0xFFFF

def IP_headchecksum(IP_head):
    checksum = 0
    headlen = len(IP_head)
    print("headlen==="+str(headlen))
    if headlen % 2 == 1:
        IP_head += b"\0"
        print("IP_head====="+IP_head)
    i = 0
    while i < headlen:
        temp = struct.unpack('!H', IP_head[i:i+2])[0]
        checksum = checksum+temp
        i = i+2
    checksum = (checksum >> 16)+(checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    return ~checksum & 0xffff

def arpcheat(name):
    e = Ether()
    #a = ARP(op = "is-at", psrc = "192.168.1.10", hwsrc = "38:F9:D3:4F:EF:7B", pdst = "192.168.1.1", hwdst = "2c:56:dc:d3:ab:b3")
    a = ARP()
    a.op = 2
    a.psrc = "192.168.1.3"
    a.hwsrc = "38:F9:D3:4F:EF:7a"
    a.pdst = "192.168.1.1"
    a.hwdst = "2c:56:dc:d3:ab:b3"
    print((e/a).show())
    #sendp(e/a, inter=2, loop=1)
    sendp(e/a, inter=2)

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    #print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.
    #e = Ether(src = '38:F9:D3:4F:EF:7A')
#    ls(Ether)
#    e.dst = 'ff:ff:ff:ff:ff:ff'

#    e.show()
#    sendp(e/'ssss')
#    ls(ARP)
    e = Ether()
    a = ARP(psrc = '192.168.1.3')
    a.pdst = '192.168.1.1'
    a.hwsrc = "38:F9:D3:4F:EF:7A"
    a.op=1
    a.show()
    w = e / a
    #ans, unans = sr(a)
    #ans.show()
    sendp(w)
    #srp(w)


#    w.show()
#    sendp(w)
    #send(a)

#    a.pdst = '192.168.1.1'
#    b = e/a

#    a.show()
#    b.show()
    #sendp(b)
    #send(a)
#    ans, unans = sr(w)
#    ans.show()
    #ls(Ether)

def ipv6():
    i = IPv6()
    i.dst = "fe80::22:2df5:cd94:906d"
    q = ICMPv6EchoRequest()
    p = (i / q)
    sr1(p)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')
    #arpcheat('PyCharm')
    ip('PyCharm')
    #tcp1()
    #http()
    #dns()
    #ping_trail()
    #ping_one()
    #ping()
    #udp()
    #ip_1()
    #ipv6()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

