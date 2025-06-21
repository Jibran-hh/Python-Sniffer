# utils.py
import os
import socket
import psutil
import ctypes

def check_admin():
    """Check administrator/root privileges"""
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise SystemExit("[!] Run as Administrator!")
    else:
        if os.geteuid() != 0:
            raise SystemExit("[!] Run as root!")

def list_interfaces():
    """Get available network interfaces"""
    return list(psutil.net_if_addrs().keys())

def print_banner():
    banner = r'''
 ____        _        _  __        __   _     _           
|  _ \ _   _| |_ ___ | | \ \      / /__| |__ (_)_ __  ___ 
| |_) | | | | __/ _ \| |  \ \ /\ / / _ \ '_ \| | '_ \/ __|
|  __/| |_| | || (_) | |   \ V  V /  __/ |_) | | | | \__ \
|_|    \__,_|\__\___/|_|    \_/\_/ \___|_.__/|_|_| |_|___/
    '''
    print(banner)
