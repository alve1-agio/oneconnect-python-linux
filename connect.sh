#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: $0 <vpn_address>"
    exit 1
fi

# Check if vpnc-script exists, use it for DNS configuration
VPNC_SCRIPT=""
if [ -x /usr/share/vpnc-scripts/vpnc-script ]; then
    VPNC_SCRIPT="--script /usr/share/vpnc-scripts/vpnc-script"
elif [ -x /etc/vpnc/vpnc-script ]; then
    VPNC_SCRIPT="--script /etc/vpnc/vpnc-script"
fi

.venv/bin/python oneconnect.py | sudo openconnect "$1" \
    --cookie-on-stdin \
    --useragent="OpenConnect (Clavister OneConnect VPN)" \
    --os="win" \
    $VPNC_SCRIPT