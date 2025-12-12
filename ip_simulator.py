# ip_simulator.py (Complete)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# --- Simulated Network Constants ---
SIM_SRC_IP = b"10.0.0.100"  # Client's simulated internal IP
SIM_DST_IP = b"10.0.0.1"    # Server's simulated internal IP (Gateway)

# --- Encapsulation and Decapsulation ---

def encapsulate_with_ip(payload: bytes) -> bytes:
    """
    Prepends a simulated IP header to the original application data before encryption.
    The header format is [SIM_SRC_IP : SIM_DST_IP].
    """
    separator = b':'
    simulated_header = SIM_SRC_IP + separator + SIM_DST_IP
    
    # Final data to be encrypted is the simulated header + original payload
    return simulated_header + payload

def decapsulate_ip_header(data_with_header: bytes) -> tuple[bytes, bytes]:
    """
    Strips the simulated IP header from the decrypted data.
    Returns the original payload and the simulated header for logging/routing.
    """
    separator = b':'
    try:
        # Find the end of the destination IP, marked by the separator after the source IP
        header_end_index = data_with_header.find(separator) + len(SIM_DST_IP) + 1
        
        simulated_header = data_with_header[:header_end_index]
        original_payload = data_with_header[header_end_index:]
        
        return simulated_header, original_payload
    
    except Exception:
        # Fallback if header format is unexpected
        return b"Error: Header Invalid", data_with_header