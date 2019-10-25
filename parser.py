#Credits : https://github.com/vnetman/pcap2csv/blob/master/pcap2csv.py

import argparse
import os.path
import sys
import time
import numpy as np
import statistics

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

def mean(packetlength):
    return sum(packetlength)/len(packetlength)

def parse(in_pcap, out_csv):

    pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
    pcap_pyshark.load_packets()
    pcap_pyshark.reset()
    totalfwdpacket = 0
    packetlength = []
    duration = []
    with open(out_csv, 'w') as fh_csv:

        for (pkt_scapy, _) in RawPcapReader(in_pcap):

            pkt_pyshark = pcap_pyshark.next_packet()
            count_fin_flag = 0
            count_syn_flag = 0
            count_rst_flag = 0
            count_psh_flag = 0
            count_ack_flag = 0
            count_urg_flag = 0
            time1 = time.time()
            ethernet_header = Ether(pkt_scapy)

            if ethernet_header.type == 0x800:
                ip_header = ethernet_header[IP]
                proto = ip_header.fields['proto']

                totallengthoffwdpacket = ip_header.len
                fwdpacketlengthmax = pkt_pyshark.length
                packetlength.append(int(fwdpacketlengthmax))
                maxfwdpacketlength = np.max(packetlength)
                minfwdpacketlength = np.min(packetlength)
                meanfwdpacketlength = mean(packetlength)
                stdfwdpacketlength = np.std(packetlength)
                iat = pkt_pyshark.time

                if proto == 17:
                    totalfwdpacket += 1
                    udp_header = ip_header[UDP]
                    payloadbytes = bytes(udp_header.payload)
                    sourceport = udp_header.sport
                    destinationport = udp_header.dport
                    timestamp = time.time() - time1
                    flowbytes = ip_header.len/timestamp
                    fwdpacket = totalfwdpacket/timestamp

                elif proto == 6:
                    totalfwdpacket += 1
                    tcp_header = ip_header[TCP]
                    payloadbytes = bytes(tcp_header.payload)
                    sourceport = tcp_header.sport
                    destinationport = tcp_header.dport
                    timestamp = time.time() - time1
                    flowbytes = ip_header.len/timestamp
                    fwdpacket = totalfwdpacket/timestamp
                    flags = tcp_header.flags

                    if flags == 0x01:
                        count_fin_flag = 1
                        count_syn_flag = 0
                        count_rst_flag = 0
                        count_psh_flag = 0
                        count_ack_flag = 0
                        count_urg_flag = 0
                    elif flags == 0x02:
                        count_fin_flag = 0
                        count_syn_flag = 1
                        count_rst_flag = 0
                        count_psh_flag = 0
                        count_ack_flag = 0
                        count_urg_flag = 0
                    elif flags == 0x04:
                        count_fin_flag = 0
                        count_syn_flag = 0
                        count_rst_flag = 1
                        count_psh_flag = 0
                        count_ack_flag = 0
                        count_urg_flag = 0
                    elif flags == 0x08:
                        count_fin_flag = 0
                        count_syn_flag = 0
                        count_rst_flag = 0
                        count_psh_flag = 1
                        count_ack_flag = 0
                        count_urg_flag = 0
                    elif flags == 0x10:
                        count_fin_flag = 0
                        count_syn_flag = 0
                        count_rst_flag = 0
                        count_psh_flag = 0
                        count_ack_flag = 1
                        count_urg_flag = 0
                    elif flags == 0x20:
                        count_fin_flag = 0
                        count_syn_flag = 0
                        count_rst_flag = 0
                        count_psh_flag = 0
                        count_ack_flag = 0
                        count_urg_flag = 1

                fmt = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15}'

                print(fmt.format(destinationport,
                                pkt_pyshark.time,
                                totalfwdpacket,
                                maxfwdpacketlength,
                                minfwdpacketlength,
                                meanfwdpacketlength,
                                stdfwdpacketlength,
                                flowbytes,
                                fwdpacket,
                                count_fin_flag,
                                count_syn_flag,
                                count_rst_flag,
                                count_psh_flag,
                                count_ack_flag,
                                count_urg_flag,
                                totallengthoffwdpacket),file=fh_csv)

    print('Parsing done !')

def command_line():

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>', help='pcap file to parse', required=True)
    parser.add_argument('--csv', metavar='<output csv file>', help='csv file to create', required=True)
    args = parser.parse_args()
    return args

def main():

    args = command_line()
    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" not exist'.format(args.pcap),file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(args.csv):
        print('Already exist'.format(args.csv),file=sys.stderr)
        sys.exit(-1)
    parse(args.pcap, args.csv)


if __name__ == '__main__':

    main()
