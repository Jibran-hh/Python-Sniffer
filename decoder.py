import struct

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def format_ip(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def decode_packet(data):
    packet = {'info': ''}
    if len(data) < 14:
        return None

    # Ethernet Header
    dest_mac = format_mac(data[:6])
    src_mac = format_mac(data[6:12])
    proto = struct.unpack('!H', data[12:14])[0]
    
    packet.update({
        'layer': 'Ethernet',
        'src': src_mac,
        'dst': dest_mac,
        'protocol': 'eth'
    })
    data = data[14:]

    # IPv4
    if proto == 0x0800 and len(data) >= 20:
        version_hlen = data[0]
        ihl = (version_hlen & 0xF) * 4
        tos = data[1]
        total_length = struct.unpack('!H', data[2:4])[0]
        id = struct.unpack('!H', data[4:6])[0]
        flags_frag = struct.unpack('!H', data[6:8])[0]
        ttl = data[8]
        protocol = data[9]
        checksum = struct.unpack('!H', data[10:12])[0]
        src_ip = format_ip(data[12:16])
        dst_ip = format_ip(data[16:20])
        
        packet.update({
            'layer': 'IP',
            'src': src_ip,
            'dst': dst_ip,
            'protocol': 'ip',
            'ttl': ttl,
            'info': f'TTL: {ttl}, ID: {id}'
        })
        data = data[ihl:]

        # TCP
        if protocol == 6 and len(data) >= 20:
            src_port, dst_port = struct.unpack('!HH', data[:4])
            seq = struct.unpack('!I', data[4:8])[0]
            ack = struct.unpack('!I', data[8:12])[0]
            flags = struct.unpack('!H', data[12:14])[0]
            
            # Extract TCP flags
            fin = (flags & 0x01) != 0
            syn = (flags & 0x02) != 0
            rst = (flags & 0x04) != 0
            psh = (flags & 0x08) != 0
            ack_flag = (flags & 0x10) != 0
            urg = (flags & 0x20) != 0
            
            flag_str = []
            if fin: flag_str.append("FIN")
            if syn: flag_str.append("SYN")
            if rst: flag_str.append("RST")
            if psh: flag_str.append("PSH")
            if ack_flag: flag_str.append("ACK")
            if urg: flag_str.append("URG")
            
            packet.update({
                'layer': 'TCP',
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 'tcp',
                'info': f'Flags: {" ".join(flag_str)}'
            })
            
            # Detect HTTP/HTTPS
            if dst_port in (80, 443) or src_port in (80, 443):
                packet['protocol'] = 'http'
                if dst_port == 80 or src_port == 80:
                    packet['info'] += ' (HTTP)'
                elif dst_port == 443 or src_port == 443:
                    packet['info'] += ' (HTTPS)'

        # UDP
        elif protocol == 17 and len(data) >= 8:
            src_port, dst_port = struct.unpack('!HH', data[:4])
            length = struct.unpack('!H', data[4:6])[0]
            checksum = struct.unpack('!H', data[6:8])[0]
            
            packet.update({
                'layer': 'UDP',
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': 'dns' if dst_port == 53 or src_port == 53 else 'udp',
                'info': f'Length: {length}'
            })
            
            # Add more specific protocol detection
            if dst_port == 53 or src_port == 53:
                packet['info'] += ' (DNS)'
            elif dst_port == 67 or src_port == 67 or dst_port == 68 or src_port == 68:
                packet['protocol'] = 'dhcp'
                packet['info'] += ' (DHCP)'
            elif dst_port == 123 or src_port == 123:
                packet['protocol'] = 'ntp'
                packet['info'] += ' (NTP)'
            elif dst_port == 161 or src_port == 161 or dst_port == 162 or src_port == 162:
                packet['protocol'] = 'snmp'
                packet['info'] += ' (SNMP)'

        # ICMP
        elif protocol == 1 and len(data) >= 8:
            icmp_type = data[0]
            icmp_code = data[1]
            checksum = struct.unpack('!H', data[2:4])[0]
            
            # Map ICMP types to names
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request",
                11: "Time Exceeded",
                13: "Timestamp",
                14: "Timestamp Reply",
                15: "Information Request",
                16: "Information Reply"
            }
            
            icmp_type_name = icmp_types.get(icmp_type, f"Unknown ({icmp_type})")
            
            packet.update({
                'layer': 'ICMP',
                'protocol': 'icmp',
                'info': f'Type: {icmp_type_name}, Code: {icmp_code}'
            })

    # ARP
    elif proto == 0x0806 and len(data) >= 28:
        hw_type = struct.unpack('!H', data[0:2])[0]
        proto_type = struct.unpack('!H', data[2:4])[0]
        hw_len = data[4]
        proto_len = data[5]
        opcode = struct.unpack('!H', data[6:8])[0]
        
        # Map ARP opcodes to names
        arp_opcodes = {
            1: "Request",
            2: "Reply",
            3: "RARP Request",
            4: "RARP Reply"
        }
        
        opcode_name = arp_opcodes.get(opcode, f"Unknown ({opcode})")
        
        # Extract MAC and IP addresses
        sender_mac = format_mac(data[8:14])
        sender_ip = format_ip(data[14:18])
        target_mac = format_mac(data[18:24])
        target_ip = format_ip(data[24:28])
        
        packet.update({
            'layer': 'ARP',
            'src': sender_mac,
            'dst': target_mac,
            'protocol': 'arp',
            'info': f'Opcode: {opcode_name}, Sender IP: {sender_ip}, Target IP: {target_ip}'
        })

    return packet