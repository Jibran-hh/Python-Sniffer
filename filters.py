class ProtocolFilter:
    def __init__(self, filters=None):
        self.filters = set(f.lower() for f in filters) if filters else None
        
        # Protocol aliases for easier filtering
        self.protocol_aliases = {
            'web': ['http', 'https'],
            'dns': ['dns'],
            'tcp': ['tcp'],
            'udp': ['udp'],
            'arp': ['arp'],
            'icmp': ['icmp'],
            'ip': ['ip'],
            'eth': ['eth'],
            'dhcp': ['dhcp'],
            'ntp': ['ntp'],
            'snmp': ['snmp']
        }

    def match(self, packet):
        if not self.filters:
            return True
            
        proto = packet.get('protocol', '').lower()
        
        # Check if the protocol matches any of the filters directly
        if proto in self.filters:
            return True
            
        # Check if the protocol is an alias for any of the filters
        for filter_proto in self.filters:
            if filter_proto in self.protocol_aliases and proto in self.protocol_aliases[filter_proto]:
                return True
                
        return False