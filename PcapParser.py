import xml.etree.ElementTree as ET
import collections
import os
import pickle


#getCnt = 0
#eventDetailLog = open("eventDetailLog.txt", 'w')
#summaryLog = open("summaryLog.txt", 'w')

class EventParser:
    def _NewObj(self, pkt): # compose done: return True, not yet: return False
        if self.stage == 0:
            self.stage = 1
            self.src = pkt["ip"].src
            self.dst = pkt["ip"].dst
            self.start_time = pkt["frame"].time_relative

            self.seqL = pkt["tcp"].tcp_seq
            self.ackL = pkt["tcp"].tcp_ack
            self.lenL = pkt["tcp"].tcp_len

            self.seqR = 1
            self.ackR = 1
            self.lenR = 0

        elif self.stage == 1: #suppose to be download mode
            if pkt["ip"].src == self.src:
                self.seqL = pkt["tcp"].tcp_seq
                self.ackL = pkt["tcp"].tcp_ack
                self.lenL = pkt["tcp"].tcp_len
                if self.ackR >= self.seqL and self.ackR <= self.seqL + self.lenL:
                    pass
                else:
                    #print "pktLoss", "frame_number", pkt["frame"].frame_number
                    #print "ackR:", self.ackR, "seqL:", self.seqL, "lenL:", self.lenL
                    #print self.id
                    self.pktLoss += 1
            else:
                self.seqR = pkt["tcp"].tcp_seq
                self.ackR = pkt["tcp"].tcp_ack
                self.lenR = pkt["tcp"].tcp_len
                if self.ackL >= self.seqR and self.ackL <= self.seqR + self.lenR:
                    pass
                else:
                    #print "pktLoss", "frame_number", pkt["frame"].frame_number
                    #print "ackL:", self.ackL, "seqR:", self.seqR, "lenR:", self.lenR
                    #print self.id
                    self.pktLoss += 1

        if "http" in pkt and pkt["http"].method == "OK":
            self.end_time = pkt["frame"].time_relative
            #self.show(pkt)
            return True
        else:
            return False
    def _OpenTCP(self, pkt):
        if self.stage == 0:
            self.stage = 1
            self.src = pkt["ip"].src
            self.dst = pkt["ip"].dst
            self.start_time = pkt["frame"].time_relative
            return False
        elif self.stage == 1:
            if (self.src == pkt["ip"].dst 
                and self.dst == pkt["ip"].src
                and "SYN" in pkt["tcp"].flags 
                and "ACK" in pkt["tcp"].flags):
                self.stage = 2
                return False
        elif self.stage == 2:
            if (self.src == pkt["ip"].src
                and self.dst == pkt["ip"].dst 
                and "ACK" in pkt["tcp"].flags):
                self.stage = 3
                self.end_time = pkt["frame"].time_relative
                #self.show(pkt)
                return True

        self.pktLoss += 1
        return False
    def _DNS(self, pkt):
        if self.stage == 0:
            self.stage = 1
            self.src = pkt["ip"].src
            self.dst = ""
            self.start_time = pkt["frame"].time_relative
        if self.stage == 1: #suppose to be query mode
            if pkt["dns"].qryFlg is True:
                #print "query"
                self.stage = 2
            else:
                self.pktLoss += 1
                #print "dns timeout"
        elif self.stage == 2: #suppose to be response mode
            if pkt["dns"].qryFlg is False:
                #print "response"
                self.stage = 1
            else:
                self.pktLoss += 1
                #print "dns timeout"

        if pkt["dns"].count_answers > 0:
            #print "get dns answer"
            self.end_time = pkt["frame"].time_relative
            #self.show(pkt)
            return True
        else:
            return False

    composeDic= {
            'NewObj': _NewObj,
            'OpenTCP': _OpenTCP,
            'DNS': _DNS,
            }
    def compose(self, pkt):
        self.pktCnt += 1
        self.byteCnt += pkt["frame"].frame_len
        if self.type:
            if self.type == "NewObj" or self.type == "OpenTCP":
                self.rttSum += pkt["tcp"].tcp_rtt
            else:
                self.rttSum = 0
            return self.composeDic[self.type](self, pkt)
        else:
            return False
    def show(self, pkt):
        #eventDetailLog.write("----------------")
        #eventDetailLog.write("\n")
        #eventDetailLog.write("event type: " + self.type)
        #eventDetailLog.write("\n")
        #eventDetailLog.write("frame_number: " + str(self.frame_number))
        #eventDetailLog.write("\n")
        #eventDetailLog.write("SRC: " + self.src + " DST: " + self.dst)
        #eventDetailLog.write("\n")
        #eventDetailLog.write("start_time: " + str(self.start_time) + "end_time: " + str(self.end_time))
        #eventDetailLog.write("\n")
        #eventDetailLog.write("packets involved: " + str(self.pktCnt))
        #eventDetailLog.write("\n")
        #eventDetailLog.write("packets loss: " + str(self.pktLoss))
        #eventDetailLog.write("\n")
        #eventDetailLog.write("bytes involved: " + str(self.byteCnt))
        #eventDetailLog.write("\n")
        #eventDetailLog.write("sum of all RTT: " + str(self.rttSum))
        #eventDetailLog.write("\n")

        print "----------------"
        print "event type:", self.type
        print "frame_number:", self.frame_number
        print "SRC:", self.src, "DST:", self.dst
        print "start_time:", self.start_time, "end_time:", self.end_time
        print "packets involved:", self.pktCnt
        print "packets loss:", self.pktLoss
        print "bytes involved:", self.byteCnt
        print "sum of all RTT:", self.rttSum

    def __init__(self, pkt):
        self.stage = 0
        self.pktLoss = 0
        self.pktCnt = 0
        self.byteCnt = 0
        self.rttSum = 0
        if(("http" in pkt) and (pkt["http"].method == "GET")):
            self.type = "NewObj"
            #global getCnt
            #getCnt += 1
            #print getCnt
        elif("tcp" in pkt and "SYN" in pkt["tcp"].flags):
            self.type = "OpenTCP"
        elif("dns" in pkt):
            self.type = "DNS"
        else:
            self.type = False

        self.id = self.getId(pkt)
        self.compose(pkt)
        self.frame_number = pkt["frame"].frame_number

    @staticmethod
    def getId(pkt):
        if("dns" in pkt):
            return pkt["dns"].id
        elif("ip" in pkt):
            src = pkt["ip"].src
            srcport = pkt["tcp"].tcp_srcport
            dst = pkt["ip"].dst
            dstport = pkt["tcp"].tcp_dstport
            if(src < dst):
                return src+":"+str(srcport)+"<->"+dst+":"+str(dstport)
            else:
                return dst+":"+str(dstport)+"<->"+src+":"+str(srcport)
        else:
            return False


            
class FrameParser:
    def _time_epoch(self, chd):
        self.time_epoch = float(chd.attrib["show"])
    def _time_delta(self, chd):
        self.time_delta = float(chd.attrib["show"])
    def _time_relative(self, chd):
        self.time_relative = float(chd.attrib["show"])
    def _frame_number(self, chd):
        self.frame_number = int(chd.attrib["show"])
    def _frame_len(self, chd):
        self.frame_len = int(chd.attrib["show"])

    parserDic = {
            'frame.time_epoch': _time_epoch,
            'frame.time_delta': _time_delta,
            'frame.time_relative': _time_relative,
            'frame.number': _frame_number,
            'frame.len': _frame_len,
            }

    def __init__(self, xmlObj):
        attr = xmlObj.attrib
        for chd in xmlObj:
            chdType = chd.attrib['name']
            if chdType in self.parserDic:
                self.parserDic[chdType](self, chd)
        #print self.time_epoch
        #print self.time_delta
        #print self.time_relative

class EthParser:
    def __init__(self, xmlObj):
        attr = xmlObj.attrib
        ls = attr['showname'].split(',')
        self.tag = xmlObj.tag
        self.protocol = ls[0]
        self.src = ls[1].split()[1]
        self.dst = ls[2].split()[1]
        #print self.protocol
        #print self.src
        #print self.dst

class IpParser:
    def __init__(self, xmlObj):
        #{'size': '20', 'pos': '14', 'showname': 'Internet Protocol Version 4, Src: 192.168.42.196 (192.168.42.196), Dst: 199.59.149.240 (199.59.149.240)', 'name': 'ip'}
        attr = xmlObj.attrib
        ls = attr['showname'].split(',')
        self.tag = xmlObj.tag
        self.protocol = ls[0]
        self.src = ls[1].split()[1]
        self.dst = ls[2].split()[1]
        #print self.protocol
        #print self.src
        #print self.dst

class TcpParser:
    def _tcp_flags(self, chd):
        #.... 0000 0001 0010 = Flags: 0x012 (SYN, ACK)
        #.... 0000 0001 1000 = Flags: 0x018 (PSH, ACK)

        key = chd.attrib["showname"]
        #print key
        self.flags = {}
        if key.find("SYN") >= 0:
            self.flags["SYN"] = True
        if key.find("ACK") >= 0:
            self.flags["ACK"] = True
        if key.find("PSH") >= 0:
            self.flags["PSH"] = True
        if key.find("FIN") >= 0:
            self.flags["FIN"] = True

    def _tcp_len(self, chd):
        self.tcp_len = int(chd.attrib["show"])
    def _tcp_seq(self, chd):
        self.tcp_seq= int(chd.attrib["show"])
    def _tcp_ack(self, chd):
        self.tcp_ack = int(chd.attrib["show"])
    def _tcp_srcport(self, chd):
        self.tcp_srcport = int(chd.attrib["show"])
    def _tcp_dstport(self, chd):
        self.tcp_dstport = int(chd.attrib["show"])

    def _tcp_rtt(self, chd):
        self.tcp_rtt = float(chd.attrib["show"])
        #print self.tcp_rtt

    def _tcp_analysis(self, xmlObj):
        for chd in xmlObj:
            chdType = chd.attrib['name']
            if chdType == "tcp.analysis.ack_rtt":
                self._tcp_rtt(chd)

    parserDic = {
            'tcp.flags': _tcp_flags,
            'tcp.len': _tcp_len,
            'tcp.seq': _tcp_seq,
            'tcp.ack': _tcp_ack,
            'tcp.srcport': _tcp_srcport,
            'tcp.dstport': _tcp_dstport,
            'tcp.analysis': _tcp_analysis,
            }


    def __init__(self, xmlObj):
        #{'size': '40', 'pos': '34', 'showname': 'Transmission Control Protocol, Src Port: 37300 (37300), Dst Port: 80 (80), Seq: 0, Len: 0', 'name': 'tcp'}

        attr = xmlObj.attrib
        ls = attr['showname'].split(',')
        self.tag = xmlObj.tag
        self.protocol = ls[0]
        self.src = ls[1].split()[2]
        self.dst = ls[2].split()[2]
        self.tcp_rtt = 0

        for chd in xmlObj:
            chdType = chd.attrib['name']
            if chdType in self.parserDic:
                self.parserDic[chdType](self, chd)
        #print self.protocol
        #print self.src
        #print self.dst
        #print self.flags

class UdpParser:
    def __init__(self, xmlObj):
        attr = xmlObj.attrib
        ls = attr['showname'].split(',')
        self.tag = xmlObj.tag
        self.protocol = ls[0]
        self.src = ls[1].split()[2]
        self.dst = ls[2].split()[2]
        #print self.protocol
        #print self.src
        #print self.dst

class HttpParser:
    def __init__(self, xmlObj):
        #first field example
        #{'value': '474554202f20485454502f312e310d0a'  , 'show': 'GET / HTTP/1.1\\r\\n', 'pos': '54', 'name': '', 'size': '16'jk}
        #{'value': '485454502f312e3120323030204f4b0d0a', 'show': 'HTTP/1.1 200 OK\\r\\n', 'pos': '0', 'name': '', 'size': '1jk7'}
        attr = xmlObj.attrib
        text = xmlObj[0].attrib['show']
        self.method = "None"
        if "GET" in text:
            self.method = "GET"
        elif "OK" in text:
            self.method = "OK"
        #print self.method


class DnsParser:
    #self.qryFlg #True: query False: response
    #self.ansNum
    #self.ansLs
    def _id(self, chd):
        self.id = chd.attrib["value"]
    def _flags(self, chd):
        #print chd[0].attrib["showname"]
        self.qryFlg = (chd[0].attrib["showname"][0] == '0')
        #print self.qryFlg
    def _count_queries(self, chd):
        self.count_queries = int(chd.attrib["show"])
    def _count_answers(self, chd):
        self.count_answers = int(chd.attrib["show"])
    parserDic = {
            'dns.id': _id,
            'dns.flags': _flags,
            'dns.count.queries': _count_queries,
            'dns.count.answers': _count_answers,
            }

    def __init__(self, xmlObj):
        attr = xmlObj.attrib
        for chd in xmlObj:
            chdType = chd.attrib['name']
            if chdType in self.parserDic:
                self.parserDic[chdType](self, chd)
        #self.id
        #self.qryFlg



class PcapParser:
    halfEventMap = {}
    fullEventQueue = []
    parserDic = {
                'ip': IpParser,
                'eth': EthParser,
                'tcp': TcpParser,
                'udp': UdpParser,
                'frame': FrameParser,
                'http': HttpParser,
                'dns': DnsParser,
                 }
    def __init__(self, fileName):
        self.tree = ET.parse(fileName)
        self.root = self.tree.getroot()
        self.xmlPktLs = []
        self.pktLs = []
        #print self.root.tag, self.root.attrib
        for xmlPkt in self.root:
            self.xmlPktLs.append(xmlPkt)
            pkt = {}

            #parse pkt information
            for xmlObj in xmlPkt:
                #print cc.tag, cc.attrib
                xmlObjType = xmlObj.attrib['name']
                if xmlObjType in self.parserDic:
                    pkt[xmlObjType] = self.parserDic[xmlObjType](xmlObj)

            #create a new event or compose the pkt into an old event
            iden = EventParser.getId(pkt)
            if iden in self.halfEventMap:
                if self.halfEventMap[iden].compose(pkt):
                    #self.halfEventMap[iden].show()
                    self.fullEventQueue.append(self.halfEventMap[iden])
                    del self.halfEventMap[iden]
            else:
                event = EventParser(pkt)
                if event.type:
                    self.halfEventMap[iden] = event

            self.pktLs.append(pkt)
    def analyze(self):
        self.time = 0.

        self.pktLoss = 0
        self.pktCnt = 0
        self.rttSum = 0

        self.tcpTime = 0.
        self.dnsTime = 0.
        self.objTime = 0.

        self.tcpCnt = 0
        self.dnsCnt = 0
        self.objCnt = 0

        for event in self.fullEventQueue:
            period = event.end_time - event.start_time
            self.time += period
            self.pktLoss += event.pktLoss
            self.pktCnt += event.pktCnt
            self.rttSum += event.rttSum

            if event.type == "OpenTCP":
                self.tcpTime += period
                self.tcpCnt += 1
            elif event.type == "NewObj":
                self.objTime += period
                self.objCnt += 1
            elif event.type == "DNS":
                self.dnsTime += period
                self.dnsCnt += 1

        for iden, event in self.halfEventMap.items():
            self.pktCnt += event.pktCnt
            self.pktLoss += event.pktCnt
            self.rttSum += event.rttSum

    def show(self):
        self.summaryLog.write("----------------")
        self.summaryLog.write("\n")
        self.summaryLog.write("senario: "+ self.senario+ " web: "+ self.web)
        self.summaryLog.write("\n")
        self.summaryLog.write("pktLoss: "+ str(self.pktLoss)+ " pktCnt:+"+ str(self.pktCnt))
        self.summaryLog.write("\n")
        self.summaryLog.write("tcpTime: "+ str(self.tcpTime)+ " objTime: "+ str(self.objTime) + " dnsTime: "+ str(self.dnsTime))
        self.summaryLog.write("\n")
        self.summaryLog.write("tcpCnt: "+ str(self.tcpCnt)+ " objCnt: "+ str(self.objCnt)+ " dnsCnt: "+ str(self.dnsCnt))
        self.summaryLog.write("\n")
        self.summaryLog.write("rttSum: "+ str(self.rttSum))
        self.summaryLog.write("\n")

        #print "----------------"
        #print "senario:", self.senario, "web:", self.web
        #print "pktLoss:", self.pktLoss, "pktCnt:", self.pktCnt
        #print "tcpTime:", self.tcpTime, "objTime:", self.objTime, "dnsTime", self.dnsTime
        #print "tcpCnt:", self.tcpCnt, "objCnt:", self.objCnt, "dnsCnt", self.dnsCnt
        #print "rttSum:", self.rttSum

        #print len(self.halfEventMap)








if __name__ == "__main__":
    #psr = PcapParser("t-mobile_android_twitter.com_1329408284.32.xml")
    xmlLs = os.listdir("./xml")
    senarioMap = {}
    log = open("log.txt", 'w')
    for xml in xmlLs:
        if xml.endswith("xml"):
            print xml
            ls = xml.split("_")
            senario = ls[0]+"_"+ls[1]
            web = ls[2]
            xml = "./xml/" + xml
            psr = PcapParser(xml)
            psr.senario = senario
            psr.web = web
            psr.summaryLog = log
            psr.analyze()
            psr.show()
            if senario in senarioMap:
                senarioMap[senarioMap].append((web, psr))

    open("senarioMap.pk", 'w').write(pickle.dumps(senarioMap))
            #print len(fullEventQueue), len(halfEventMap)


