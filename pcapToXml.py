import os
pcapLs = os.listdir("./pcapLs")
for pcap in pcapLs:
    xml = pcap.replace("pcap", "xml")
    cmd = "tshark -r pcapLs/"+ pcap +" -T pdml>" + "./xml/" + xml
    print cmd
    os.system(cmd)
