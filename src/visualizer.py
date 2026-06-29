import os
import pandas as pd
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt

# This file path is to collect data from data/ captured_packets.csv and made a graph
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

if os.path.basename(CURRENT_DIR) == "src":
    ROOT_DIR = os.path.dirname(CURRENT_DIR)
else:
    ROOT_DIR = CURRENT_DIR

DATA_DIR = os.path.join(ROOT_DIR, "data")
CSV_FILE = os.path.join(DATA_DIR, "captured_packets.csv")

# This file path to store the graph in figures/ folder
current_file = Path(__file__).resolve()
SCRIPT_DIR = current_file.parent
if SCRIPT_DIR.name == "src":
    ROOT_DIR = SCRIPT_DIR.parent
else:
    ROOT_DIR = SCRIPT_DIR

FIG_DIR = ROOT_DIR / "figures"
FIG_DIR_STR = str(FIG_DIR)
OUTPUT_DIR = os.path.join(FIG_DIR_STR)
os.makedirs(FIG_DIR_STR, exist_ok=True)

# First We can load network data that we collect from sniffer
def load_network_data():
    if not os.path.exists(CSV_FILE):
        print(f"[-] Error: Data Source '{CSV_FILE}' Not Found first run the sniffer")
        return None
    try:
        df = pd.read_csv(CSV_FILE)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        return df
    except Exception as e:
        print(f"[-] Error reading CSV file: {e}")
        return None
    
# We made the first graph of protocol distribution
def plot_protocol_distribution(df):
    plt.figure(figsize=(8, 6))
    proto_counts = df['Protocol'].value_counts()
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
    plt.pie( proto_counts,
        labels=proto_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=colors[:len(proto_counts)],
        wedgeprops={'edgecolor': 'white', 'linewidth': 1.5})
    
    plt.title("Network Protocol Distribution", fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    
    output_path = os.path.join(OUTPUT_DIR, "protocol_distribution.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    
    print(f"[+] Saved Protocol Distribution chart to: {output_path}")
    
# Second graph we made for Top IP Addresses to meet other IP Addresses
def plot_top_talker(df):
    plt.figure(figsize=(10, 5))
    top_ips = df['Source IP'].value_counts().head(5)
    bars = plt.barh(top_ips.index[::1], top_ips.values[::-1], color='#2bc4c4', edgecolor='#178787')
    
    plt.title("Top 5 Source IP Addresses(Traffic Volume)", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Packet Count", fontsize=11, labelpad=10)
    plt.ylabel("Source IP Address", fontsize=11)
    plt.grid(axis='x', linestyle='--', alpha=0.5)
    
    for bar in bars:
        width = bar.get_width()
        plt.text(width + (width * 0.01), bar.get_y() + bar.get_height() / 2,
                 f'{int(width)}',
                 va='center', ha='left', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    
    output_path  = os.path.join(OUTPUT_DIR, "Top_Talker.png")
    plt.savefig(output_path, dpi=300)
    plt.close()
    
    print(f"[+] Saved Top Talker Chart to: {output_path}")
    
# THis is the additional function for summarize that we can made
def display_summary_statistics(df):
    total_packets = len(df)
    total_bytes = df['Packet Size (Bytes)'].sum()
    avg_packet_size = df['Packet Size (Bytes)'].mean()
    
    print("\n" + "=" * 50)
    print("             Traffic Analysis Summary             ")
    print("=" * 50)
    print(f'Total Captures Packets: {total_packets}')
    print(f'Total Bandwidth Thru: {total_bytes / 1024:.2f} KB ({total_bytes} Bytes)')
    print(f"Average Packet Size: {avg_packet_size:.2f} Bytes")
    print("-" * 50)
    
    print("\n[Protocol Breakdowns]")
    print(df['Protocol'].value_counts().to_string())
    
    print("\n[Top Active Connection (Source -> Destination)]")
    connections = df.groupby(['Source IP', 'Destination IP']).size().sort_values(ascending=False).head(3)
    for (src, dst), count in connections.items():
        print(f"  {src} --> {dst}   ({count} Packets)")
    print("=" * 50 + "\n")
    
# main function is for output    
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    df = load_network_data()
    if df is not None:
        if df.empty:
            print("[-] Warning: The csv file is empty. Generate the sniffer first")
            return
        
        display_summary_statistics(df)
        plot_protocol_distribution(df)
        plot_top_talker(df)
        
# This condition can run the main function
if __name__ == "__main__":
    main()