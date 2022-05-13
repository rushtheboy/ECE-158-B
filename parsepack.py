import dpkt
import datetime
from dpkt.utils import mac_to_str,inet_to_str


filename = 'ftp.pcap'
f = open(filename, 'rb')
pcap = dpkt.pcap.Reader(f)

# For each packet in the pcap process the contents
prevtime = 0
cnt = 0
intertime = 0
loadsizes = []

for timestamp, buf in pcap:

    # Print out the timestamp in UTC
    print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
    bruh = datetime.datetime.utcfromtimestamp(timestamp)
    #bruh_time = bruh.strftime("%H:%M:%S")
    if cnt == 0:
      print("Time diff: ", bruh-datetime.timedelta(0))
      prevtime = datetime.datetime.utcfromtimestamp(timestamp)
      intertime = datetime.timedelta(0)
    elif cnt > 0:
      intertime = intertime + (bruh-prevtime)
      print("Time diff: ", bruh-prevtime)
      print("Abs arrival: ", intertime)

    cnt+=1

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

    # Make sure the Ethernet frame contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        continue

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data
    print("Packet size: ", ip.len)
    loadsizes.append(ip.len)

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    # Print out the info
    print ('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)) 

    prevtime = datetime.datetime.utcfromtimestamp(timestamp)