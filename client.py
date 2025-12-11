import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '127.0.0.1'
PORT = 65432
MAX_PACKET_SIZE = 4096

# --- Helper Function for Reliable Data Reception (Buffer Management) ---
# Aryan: We use the same helper on the client side to reliably read the ACK message.
def recv_all(s, max_size=MAX_PACKET_SIZE):
    """
    Receives all data from the socket up to the MAX_PACKET_SIZE.
    """
    data = b''
    try:
        chunk = s.recv(max_size)
        data += chunk
        return data
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
        return None

# --- Client Logic ---
def run_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        s.connect((HOST, PORT))
        logging.info("Connected to server successfully.")
        
        # --- Part 2 Placeholder: Diffie-Hellman Key Exchange ---
        handshake = recv_all(s)
        if handshake and handshake.decode('utf-8') == "KEY_EXCHANGE_START":
            logging.info(f"[SERVER] Handshake received: {handshake.decode('utf-8')}")
            # --- Part 2: Key exchange logic will go here ---
            shared_key = None # Placeholder for the negotiated session key
            logging.info(f"KEY EXCHANGE Complete. Shared Key: {shared_key if shared_key else 'PENDING'}")
        else:
            logging.error("Key exchange failed or unexpected server response.")
            s.close()
            return

        # Main client loop to send multiple packets
        while True:
            message = input("Type data to tunnel (or 'quit'): ")
            
            if message.lower() == 'quit':
                break
            
            if not message:
                continue

            # --- Part 2 Placeholder: ENCRYPTION and Encapsulation ---
            # Data must be encrypted and encapsulated into a tunnel packet format here
            # e.g., encrypted_packet = encrypt_data(message, shared_key)
            
            # For now, we simulate the raw packet (Needs to be bytes)
            raw_data = message.encode('utf-8') 
            encrypted_packet = raw_data # Placeholder: In Part 2, this will be ciphertext + IV
            
            # 1. Logging Sent Packet
            logging.info(f"PACKET SENT - Original Data: '{message[:20]}' - Size: {len(encrypted_packet)} bytes.")
            
            # 2. Data Transmission (Sending the encapsulated packet)
            s.sendall(encrypted_packet)
            
            # 3. Receive Server Response
            response = recv_all(s)
            
            if not response:
                logging.warning("Server closed connection or no response received.")
                break
                
            logging.info(f"[SERVER] Response: {response.decode('utf-8', errors='ignore')}")
            
    except ConnectionRefusedError:
        logging.critical("Error: Server is not running or port is closed.")
    except Exception as e:
        logging.error(f"Client runtime error: {e}")
        
    finally:
        logging.info("Closing client connection.")
        s.close()

if __name__ == "__main__":
    run_client()