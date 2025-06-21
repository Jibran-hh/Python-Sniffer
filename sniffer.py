# sniffer.py
from scapy.all import sniff
from decoder import decode_packet
import subprocess
import os
import platform

class Sniffer:
    def __init__(self, interface, callback, proto_filter, logger=None, mode="promiscuous"):
        self.interface = interface
        self.callback = callback
        self.proto_filter = proto_filter
        self.logger = logger
        self.running = True
        self.mode = mode
        
        # Set up the interface in the appropriate mode
        self.setup_interface()

    def setup_interface(self):
        """Set up the network interface in the appropriate mode"""
        if self.mode == "monitor":
            self.enable_monitor_mode()
        else:
            self.enable_promiscuous_mode()
    
    def enable_monitor_mode(self):
        """Enable monitor mode for wireless interfaces"""
        try:
            if platform.system() == "Linux":
                # Bring interface down
                subprocess.run(["ifconfig", self.interface, "down"], check=True)
                # Enable monitor mode
                subprocess.run(["iwconfig", self.interface, "mode", "monitor"], check=True)
                # Bring interface back up
                subprocess.run(["ifconfig", self.interface, "up"], check=True)
                print(f"[+] {self.interface} is now in monitor mode")
            else:
                print(f"[!] Monitor mode is only supported on Linux systems")
                print(f"[!] Falling back to promiscuous mode")
                self.enable_promiscuous_mode()
        except Exception as e:
            print(f"[!] Failed to enable monitor mode: {e}")
            print(f"[!] Falling back to promiscuous mode")
            self.enable_promiscuous_mode()
    
    def enable_promiscuous_mode(self):
        """Enable promiscuous mode for the interface"""
        try:
            if platform.system() == "Linux":
                subprocess.run(["ifconfig", self.interface, "promisc"], check=True)
                print(f"[+] {self.interface} is now in promiscuous mode")
            elif platform.system() == "Windows":
                # Windows doesn't require explicit promiscuous mode setting
                # as scapy handles this automatically
                print(f"[+] {self.interface} is ready for packet capture")
        except Exception as e:
            print(f"[!] Failed to enable promiscuous mode: {e}")

    def handle_packet(self, packet):
        parsed = decode_packet(bytes(packet))
        if parsed and self.proto_filter.match(parsed):
            self.callback(parsed)
            if self.logger:
                self.logger.log(parsed)

    def sniff(self):
        sniff(iface=self.interface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False
        # Reset interface to normal mode
        try:
            if platform.system() == "Linux":
                subprocess.run(["ifconfig", self.interface, "-promisc"], check=True)
                print(f"[+] {self.interface} reset to normal mode")
        except Exception as e:
            print(f"[!] Failed to reset interface: {e}")
