"""PacketVault - a tamper-evident network forensics store.

Converts a PCAP capture into a hash-chained (SHA-256), encrypted
(AES-256-GCM / PBKDF2) and digitally signed (RSA-2048) evidence bundle that
any third party can verify with the investigator's public key.
"""

__version__ = "0.1.0"
