# ip_simulator.py

SIM_SRC_IP = b"10.0.0.100"  # Client's simulated internal IP
SIM_DST_IP = b"10.0.0.1"    # Server's simulated internal IP (Gateway)
IP_HEADER_SIZE = 18         # Length of SIM_SRC_IP + SIM_DST_IP + separator

# The simulated header format will be: [SRC_IP | DST_IP | Original Payload]

def encapsulate_with_ip(payload: bytes) -> bytes:
    """
    Prepends a simulated IP header to the original application data.
    This simulates the client sending an IP packet into the VPN tunnel.
    """
    # Header format: 10.0.0.100:10.0.0.1 (10 bytes + 1 byte separator + 9 bytes = 20 total)
    # Let's use a standard length and format for simplicity:
    # Format: [10.0.0.100][10.0.0.1]
    
    # We use a 1-byte separator to ensure the header is easily identifiable.
    separator = b':' 
    
    simulated_header = SIM_SRC_IP + separator + SIM_DST_IP
    
    # The IP header is now 10 + 1 + 9 = 20 bytes long
    
    # The final data to be encrypted is the simulated header + original payload
    return simulated_header + payload

def decapsulate_ip_header(data_with_header: bytes) -> tuple[bytes, bytes]:
    """
    Strips the simulated IP header from the decrypted data.
    Returns the original payload and the simulated header for logging/routing.
    """
    # Look for the separator, or simply hardcode the header size (20 bytes)
    separator = b':'
    try:
        # Find the end of the destination IP (10.0.0.1)
        header_end_index = data_with_header.find(separator) + len(SIM_DST_IP) + 1
        
        # Strip the header
        simulated_header = data_with_header[:header_end_index]
        original_payload = data_with_header[header_end_index:]
        
        return simulated_header, original_payload
    
    except Exception:
        # Fallback if header format is unexpected
        return b"Error: Header Invalid", data_with_header