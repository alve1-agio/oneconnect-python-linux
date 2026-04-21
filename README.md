# Linux OpenConnect VPN with OneID Authentication

Clavister OneConnect has no Linux client. This script reverse-engineers the Clavister authentication protocol — submitting credentials and polling for OneTouch push notification approval — then pipes the resulting session cookie to the standard `openconnect` CLI. It spoofs the Windows client user-agent, which is required for the server to accept the connection.

> **Note:** This project is not actively maintained. It may break if the Clavister server-side protocol changes.

## Prerequisites

- Linux (tested on Ubuntu/Debian)
- Python 3.8+
- `openconnect` and `vpnc-scripts`
- OneID app installed and configured on your mobile device
- sudo access

## Installation

### 1. Install OpenConnect

```bash
# Ubuntu/Debian
sudo apt install openconnect vpnc-scripts

# Fedora
sudo dnf install openconnect vpnc-scripts

# Arch Linux
sudo pacman -S openconnect vpnc
```

### 2. Set Up Python Environment

```bash
cd /path/to/oneconnect-python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure

Copy `.env.example` to `.env` and fill in your values:

```env
SERVER_URI=https://<your-vpn-server>
UID_USERNAME=your.email@company.com
UID_DEVICE=<generated-device-id>
```

Generate a `UID_DEVICE`:
```bash
echo -n "$(hostname)-$(date +%s)" | sha256sum | cut -d' ' -f1
```

> **Important:** Once set, never change `UID_DEVICE` — it is tied to your authentication profile on the server.

Protect the file:
```bash
chmod 600 .env
```

## Usage

```bash
source .venv/bin/activate
./connect.sh https://<your-vpn-server>
```

Approve the push notification in your OneID app with your PIN. The script polls until approved, then hands off to `openconnect`.

> Don't connect while on office WiFi — you already have direct access and VPN will cause routing conflicts.

### Disconnecting

Press `Ctrl+C`, or from another terminal:
```bash
sudo pkill openconnect
```

## Troubleshooting

**Can't resolve VPN hostname:**
```bash
resolvectl flush-caches
```

**Authentication times out:** Ensure your OneID app is up to date and you have network connectivity.

**VPN connects but can't reach internal resources:**
```bash
ip route | grep tun
```

**Permission denied on connect.sh:**
```bash
chmod +x connect.sh
```

## Files

- `connect.sh` — Launches the Python auth handler and pipes the session cookie to `openconnect`
- `oneconnect.py` — Implements the Clavister authentication protocol
- `configauthxml.py` — XML configuration parser for Clavister's config-auth format
- `.env.example` — Configuration template
- `.gitignore` — Excludes `.env` and the Python virtual environment from version control
