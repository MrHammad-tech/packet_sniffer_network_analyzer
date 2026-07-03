import os
import csv
from pathlib import Path
from datetime import datetime
from scapy.all import ARP, TCP, UDP, IP, Ether, srp, sniff

# WE will set the file path from src/ to data/ to strore captured_packets.csv
current_file = Path(__file__).resolve()

SCRIPT_DIR = current_file.parent

if SCRIPT_DIR.name == "src":
    ROOT_DIR = SCRIPT_DIR.parent  
else:
    ROOT_DIR = SCRIPT_DIR
     
DATA_DIR = ROOT_DIR / "data"
CSV_FILE = DATA_DIR / "captured_packets.csv"

DATA_DIR_STR = str(DATA_DIR)
CSV_FILE_STR = str(CSV_FILE)
os.makedirs(DATA_DIR_STR, exist_ok=True)

#Function to save the file into given path
def save_file(file_path, content):
    try:
        with open (file_path, 'a', encoding='utf-8') as file:
            file.write (content)
        print(f"File successfully saved to: {file_path}")
        return True
    except Exception as e:
        print(f"Failed to save file:{e}")
        return False   
    
# Configure packet_count=0 for continuous live capturing loops
PACKET_COUNT = 0
PROTOCOL_MAP = {1: "ICMP", 2:"IGMP", 6:"TCP", 17:"UDP"}

#First Scan the local network and take data from them
def NetworkScan(ip_range):
    """Appends dissected packet metadata records to local storage."""
    print(f"Scaning Network Range: {ip_range}")
    
    arp_request = ARP(pdst=ip_range)
    broadcast =  Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    print("Target IP \t\t MAC Address")
    print("-" * 50)
    devices = []
    
    for element in answered_list:
        device_info = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device_info)
        print(f"{device_info['IP']}\t\t{device_info['MAC']}")
        
    return devices

#Made the csv file rows where data is store sequencely
def initialize_csv():
    """Initializes the storage CSV file with structural headers."""
    os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
    
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([ "Timestamp", "Source IP", "Destination IP",
                "Protocol", "Source Port", "Destination Port", "Packet Size (Bytes)"])
        print(f"[*] Iniitialized log file at: {CSV_FILE}")
        
#Now made a Packet callback that can callback the TCP, IP, UDP, ARP in the program to collect the data from local device
def packet_callback(packet):
    """Callback execution block responsible for parsing layer metadata."""
    timestamp = datetime.now().strftime(("%Y-%m-%d %H:%M:%S"))
    packet_size = len(packet)
    
    src_ip = "N/A"
    dst_ip = "N/A"
    protocol = "other"
    src_port = "N/A"
    dst_port = "N/A"
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        protocol = PROTOCOL_MAP.get(proto_num, f"Proto-{proto_num}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if packet.haslayer('RAW'):
                payload = packet['RAW'].load.decode(errors='ignore')
                if "GET" in payload or "POST" in payload:
                    first_line = payload.splitlines()[0]
                    print(f"[HTTP Data]: {first_line}")
                    
                    alert_msg = f"[{timestamp}] HTTP Alert! size: {packet_size} Bytes |Request: {first_line}\n"
                    save_file(CSV_FILE, alert_msg)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"
        
    if src_ip != "N/A":
        row = [timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size]
        with open(CSV_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(row)
        print(f"[{protocol}] {src_ip} -> {dst_ip}:{dst_port} | {packet_size}Bytes")
        
#Made some additional function if main function cannot run than this function can execute
def StartSniff(interface=None):
    """Triggers the raw engine listener channel."""
    print(f"\n[*] Starting Packet Sniffer on Interface: {interface or 'Default'}.....")
    print("[*] Press CTRL+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=0, count=PACKET_COUNT)        
        
#NOW write the main program where attched all the function that we made earlier
def main():
    print("=" *60)
    print("PACKET SNIFFER & TRAFFIC ANALYZER INSTALIZING")
    print("=" * 60)
        
    initialize_csv()
    StartSniff() 
    print("[*] Starting Live Packet Capture...... press CTRL+C To Terminate the program")
    print("=" * 60)

#Here To Run the Program
if __name__ == "__main__":
    main()