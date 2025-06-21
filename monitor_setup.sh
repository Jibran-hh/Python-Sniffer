#!/bin/bash

# Usage: sudo ./monitor_setup.sh <interface> [monitor|promiscuous]

INTERFACE=$1
MODE=$2

if [ -z "$INTERFACE" ] || [ -z "$MODE" ]; then
  echo "Usage: sudo $0 <interface> [monitor|promiscuous]"
  exit 1
fi

echo "[*] Configuring interface $INTERFACE..."

# Bring interface down
sudo ifconfig $INTERFACE down

if [ "$MODE" = "monitor" ]; then
  echo "[*] Enabling monitor mode..."
  sudo iwconfig $INTERFACE mode monitor
elif [ "$MODE" = "promiscuous" ]; then
  echo "[*] Enabling promiscuous mode..."
  sudo ifconfig $INTERFACE promisc
else
  echo "[!] Unknown mode: $MODE"
  exit 1
fi

# Bring interface back up
sudo ifconfig $INTERFACE up

echo "[+] $INTERFACE is now in $MODE mode."
