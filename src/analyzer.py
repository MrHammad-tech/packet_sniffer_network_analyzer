import os
import pandas as pd

# Define the file path to access the file and analyze the file
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

if os.path.basename(CURRENT_DIR) == "src":
    ROOT_DIR = os.path.dirname(CURRENT_DIR)
else:
    ROOT_DIR = CURRENT_DIR

DATA_DIR = os.path.join(ROOT_DIR, "data")
CSV_FILE = os.path.join(DATA_DIR, "captured_packets.csv")

# Build a class to made it easier to load or collect data
class TrafficAnalyzer:
    # main function we use as OOPS programing
    def __init__(self, file_path):
        self.file_path = file_path
        self.df = None
        
    # we load data to analyze it
    def load_data(self):
        if not os.path.exists(self.file_path):
            print(f"[-] Error: '{self.file_path}' does not exists. Run the sniffer first")
            return False
        try:
            self.df = pd.read_csv(self.file_path)
            self.df['Timestamp'] = pd.to_datetime(self.df['Timestamp'], errors='coerce')
            return True
        except Exception as e:
            print(f"[-] Error reading data: {e}")
            return False
        
    # we get the bandwidth of the data
    def get_bandwidth_metrics(self):
        total_packets = len(self.df)
        total_bytes = self.df['Packet Size (Bytes)'].sum()
        Avg_packet_size = self.df['Packet Size (Bytes)'].mean()
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_kb":total_bytes / 1024,
            "avg_packet_size": Avg_packet_size
        }
    
    # this function can count the protocol
    def Get_Protocol_Count(self):
        return self.df['Protocol'].value_counts()
    
    # This function can count the top protocol
    def Get_Top_Talker(self, limit=5):
        return self.df['Source IP'].value_counts().head(limit)
    
    # This function can count the Top listener
    def Get_Top_Listeners(self, limit=5):
        return self.df['Destination IP'].value_counts().head(limit)
    
    # This function can group or sort the conversations
    def Get_Heavy_Conversation(self, limit=5):
        conversation = self.df.groupby(['Source IP', 'Destination IP']).size()
        return conversation.sort_values(ascending=False).head(limit)
     
# main function is for output
def main():
    print("[*] Launching Network Traffic Analyzer Engine.....")
    analyzer = TrafficAnalyzer(CSV_FILE)
    
    if not analyzer.load_data():
        return
    
    metrics = analyzer.get_bandwidth_metrics()
    print("\n" + "=" * 50)
    print("        NETWORK METRICS REPORT        ")
    print("=" * 50)
    print(f"Captured Elements   : {metrics['total_packets']:,} packets")
    print(f"Throughput Volume   : {metrics['total_kb']:.2f} KB ({metrics['total_bytes']:,} bytes)")
    print(f"Average Frame Size  : {metrics['avg_packet_size']:.1f} Bytes")
    print("-" * 50)
    
    print("\n [Protocol Distribution (Layer 3/4)]")
    proto_counts = analyzer.Get_Protocol_Count()
    for proto, count in proto_counts.items():
        percentage = (count / metrics['total_packets']) * 100
        print(f"  {proto:<12} : {count:<6} ({percentage:.1f}%)")
        
    print("\n[Top 5 Source IP Addresses]")
    for ip, count in analyzer.Get_Top_Talker().items():
        print(f"  {ip:<18} : {count} packets")
        
    print("\n[Top 3 Active Conversation]")
    for index_tuple , count in analyzer.Get_Heavy_Conversation(limit=3).items():
        src, dst = index_tuple
        print(f"  {src} --> {dst} ({count} packets)")
    print("=" * 50 + "\n")

# To run the main function
if __name__ == "__main__":
    main()