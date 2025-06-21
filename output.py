# output.py

class ConsoleOutput:
    def display(self, packet):
        print("[+] Packet Captured")
        print(f"    Layer     : {packet.get('layer', 'Unknown')}")
        print(f"    Source    : {packet.get('src', 'N/A')}", end="")
        if 'src_port' in packet:
            print(f":{packet['src_port']}")
        else:
            print()
        print(f"    Destination: {packet.get('dst', 'N/A')}", end="")
        if 'dst_port' in packet:
            print(f":{packet['dst_port']}")
        else:
            print()
        print(f"    Protocol  : {packet.get('protocol', 'N/A')}")
        print("-" * 50)
