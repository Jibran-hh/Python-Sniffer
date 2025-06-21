import json
from datetime import datetime

class FileLogger:
    def __init__(self, filename=None):
        self.filename = filename or f"pysniffx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    def log(self, packet):
        try:
            with open(self.filename, 'a') as f:
                f.write(json.dumps(packet, default=str) + '\n')
        except Exception as e:
            print(f"Logging error: {e}")