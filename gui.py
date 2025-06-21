import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread
import json
from datetime import datetime
from sniffer import Sniffer
from filters import ProtocolFilter
from logger import FileLogger
from utils import list_interfaces, check_admin

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PySniffX - Packet Sniffer")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.accent_color = "#4a6fa5"
        self.text_color = "#333333"
        self.root.configure(bg=self.bg_color)
        
        self.sniffer_thread = None
        self.running = False
        self.sniffer = None
        self.packet_count = 0
        
        # Store all captured packets
        self.captured_packets = []

        # Variables
        self.interface_var = tk.StringVar()
        self.log_var = tk.BooleanVar(value=True)
        self.protocol_filter_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="promiscuous")
        self.display_filter_var = tk.StringVar(value="All")
        
        # Common protocols
        self.protocols = [
            "All", "Web", "HTTP", "DNS", "TCP", "UDP", "ARP", "ICMP", "IP", "ETH", 
            "DHCP", "NTP", "SNMP"
        ]

        self.create_widgets()
        self.create_status_bar()

    def create_widgets(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = tk.LabelFrame(main_frame, text="Control Panel", bg=self.bg_color, fg=self.text_color)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        interface_frame = tk.Frame(control_frame, bg=self.bg_color)
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(interface_frame, text="Network Interface:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=5)
        self.interface_menu = ttk.Combobox(interface_frame, textvariable=self.interface_var, width=30)
        self.interface_menu['values'] = list_interfaces()
        self.interface_menu.pack(side=tk.LEFT, padx=5)
        
        # Mode selection
        mode_frame = tk.Frame(control_frame, bg=self.bg_color)
        mode_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(mode_frame, text="Capture Mode:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Promiscuous", variable=self.mode_var, value="promiscuous").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Monitor", variable=self.mode_var, value="monitor").pack(side=tk.LEFT, padx=5)
        
        # Protocol filter for capture
        filter_frame = tk.Frame(control_frame, bg=self.bg_color)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(filter_frame, text="Capture Filter:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=5)
        self.protocol_menu = ttk.Combobox(filter_frame, textvariable=self.protocol_filter_var, values=self.protocols, width=15)
        self.protocol_menu.current(0)  # Default to "All"
        self.protocol_menu.pack(side=tk.LEFT, padx=5)
        
        # Options
        options_frame = tk.Frame(control_frame, bg=self.bg_color)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.log_checkbox = tk.Checkbutton(options_frame, text="Log Packets to File", variable=self.log_var, 
                                          bg=self.bg_color, fg=self.text_color, selectcolor=self.accent_color)
        self.log_checkbox.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = tk.Frame(control_frame, bg=self.bg_color)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.start_btn = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing,
                                  bg=self.accent_color, fg="white", width=15, relief=tk.RAISED)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="Stop", command=self.stop_sniffing,
                                 bg="#d9534f", fg="white", width=15, relief=tk.RAISED, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="Clear", command=self.clear_output,
                                  bg="#5bc0de", fg="white", width=15, relief=tk.RAISED)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Packet display
        display_frame = tk.LabelFrame(main_frame, text="Captured Packets", bg=self.bg_color, fg=self.text_color)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Display filter
        display_filter_frame = tk.Frame(display_frame, bg=self.bg_color)
        display_filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(display_filter_frame, text="Display Filter:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=5)
        self.display_filter_menu = ttk.Combobox(display_filter_frame, textvariable=self.display_filter_var, 
                                               values=self.protocols, width=15)
        self.display_filter_menu.current(0)  # Default to "All"
        self.display_filter_menu.pack(side=tk.LEFT, padx=5)
        
        self.apply_filter_btn = tk.Button(display_filter_frame, text="Apply Filter", command=self.apply_display_filter,
                                         bg="#5cb85c", fg="white", width=15, relief=tk.RAISED)
        self.apply_filter_btn.pack(side=tk.LEFT, padx=5)
        
        # Create a scrolled text widget with custom tags
        self.output_box = scrolledtext.ScrolledText(display_frame, wrap=tk.NONE, bg="white", fg=self.text_color)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for different packet types
        self.output_box.tag_configure("http", foreground="#007bff")
        self.output_box.tag_configure("dns", foreground="#28a745")
        self.output_box.tag_configure("tcp", foreground="#ffc107")
        self.output_box.tag_configure("udp", foreground="#17a2b8")
        self.output_box.tag_configure("arp", foreground="#dc3545")
        self.output_box.tag_configure("icmp", foreground="#6c757d")
        self.output_box.tag_configure("ip", foreground="#6f42c1")
        self.output_box.tag_configure("eth", foreground="#fd7e14")
        
        # Add horizontal scrollbar
        h_scrollbar = tk.Scrollbar(self.output_box, orient=tk.HORIZONTAL, command=self.output_box.xview)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.output_box.config(xscrollcommand=h_scrollbar.set)

    def create_status_bar(self):
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message):
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def clear_output(self):
        self.output_box.delete(1.0, tk.END)
        self.captured_packets = []
        self.packet_count = 0
        self.update_status(f"Output cleared. Packets captured: {self.packet_count}")

    def apply_display_filter(self):
        """Filter the displayed packets based on the selected protocol"""
        selected_protocol = self.display_filter_var.get().lower()
        
        # Clear the display
        self.output_box.delete(1.0, tk.END)
        
        # Create a filter for the display
        display_filter = ProtocolFilter([selected_protocol] if selected_protocol != "all" else None)
        
        # Filter and display packets
        filtered_count = 0
        for packet in self.captured_packets:
            if display_filter.match(packet):
                filtered_count += 1
                self.display_packet_in_box(packet)
        
        self.update_status(f"Displaying {filtered_count} of {self.packet_count} packets (Filter: {selected_protocol})")

    def display_packet_in_box(self, packet):
        """Display a packet in the output box with appropriate formatting"""
        # Format packet for display
        timestamp = packet.get('timestamp', datetime.now().strftime("%H:%M:%S"))
        protocol = packet.get('protocol', 'unknown').lower()
        
        # Create a formatted string for display
        display_text = f"[{timestamp}] Packet #{packet.get('number', '?')}\n"
        display_text += f"    Layer     : {packet.get('layer', 'Unknown')}\n"
        display_text += f"    Source    : {packet.get('src', 'N/A')}"
        
        if 'src_port' in packet:
            display_text += f":{packet['src_port']}"
        display_text += "\n"
        
        display_text += f"    Destination: {packet.get('dst', 'N/A')}"
        if 'dst_port' in packet:
            display_text += f":{packet['dst_port']}"
        display_text += "\n"
        
        display_text += f"    Protocol  : {packet.get('protocol', 'N/A')}\n"
        
        if 'info' in packet and packet['info']:
            display_text += f"    Info      : {packet['info']}\n"
            
        display_text += "-" * 50 + "\n"
        
        # Insert with appropriate tag
        self.output_box.insert(tk.END, display_text)
        
        # Apply tag to the entire packet block
        start_index = self.output_box.index("end-2c linestart")
        end_index = self.output_box.index("end-1c")
        self.output_box.tag_add(protocol, start_index, end_index)
        
        # Scroll to the end
        self.output_box.see(tk.END)

    def start_sniffing(self):
        check_admin()
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface.")
            return

        # Get selected protocol filter
        selected_protocol = self.protocol_filter_var.get().lower()
        filters = None if selected_protocol == "all" else [selected_protocol]
        proto_filter = ProtocolFilter(filters)
        
        # Create logger if enabled
        logger = FileLogger() if self.log_var.get() else None

        # Get selected mode
        mode = self.mode_var.get()

        # Create sniffer
        self.sniffer = Sniffer(
            interface=interface,
            callback=self.display_packet,
            proto_filter=proto_filter,
            logger=logger,
            mode=mode
        )
        
        # Start sniffing in a separate thread
        self.running = True
        self.sniffer_thread = Thread(target=self.sniffer.sniff, daemon=True)
        self.sniffer_thread.start()

        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.update_status(f"Sniffing on {interface} - Mode: {mode} - Filter: {selected_protocol}")

    def stop_sniffing(self):
        self.running = False
        if self.sniffer:
            self.sniffer.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_status(f"Stopped. Packets captured: {self.packet_count}")

    def display_packet(self, packet):
        self.packet_count += 1
        
        # Add timestamp and packet number
        packet['timestamp'] = datetime.now().strftime("%H:%M:%S")
        packet['number'] = self.packet_count
        
        # Store the packet
        self.captured_packets.append(packet)
        
        # Display the packet
        self.display_packet_in_box(packet)
        
        # Update status
        self.update_status(f"Capturing on {self.interface_var.get()} - Packets: {self.packet_count}")
