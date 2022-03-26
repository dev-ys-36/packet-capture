from scapy.all import *

# protocols
# 2 : IGMP
# 6 : TCP
# 17 : UDP

def showPacket(packet):

    #print(packet.show())
    print('[' + str(packet[0][1].proto) + '] ' + packet[0][1].src + ' -> ' + packet[0][1].dst)


sniff(filter = 'ip', prn = showPacket)