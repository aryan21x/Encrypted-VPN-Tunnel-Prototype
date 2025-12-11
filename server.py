import socket
import threading
import logging # Using standard logging module for better output control

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '127.0.0.1'
PORT = 65432
MAX_PACKET_SIZE = 4096 # Maximum size for a single encrypted packet

# --- Helper Function for Reliable Data Reception (Buffer Management) ---

def recv_all(conn, max_size=MAX_PACKET_SIZE):
    """
    Receives all data from the socket up to the MAX_PACKET_SIZE.
    In a real-world scenario, a header indicating the packet length would be used.
    """
    data = b''
    try:
        # For simplicity, we'll read up to the maximum size here.
        # Once encapsulation is implemented (Part 2), we'll read the header first,
        # then read exactly the number of bytes specified in the header.
        chunk = conn.recv(max_size)
        data += chunk
        return data
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
        return None

# --- Main Client Handler ---
def handle_client(conn, addr):
    logging.info(f"[CONNECTION] Client connected: {addr[0]}:{addr[1]}")
    
    # --- Part 2 Placeholder: Diffie-Hellman Key Exchange ---
    try:
        logging.info(f"[{addr[1]}] Starting KEY EXCHANGE...")
        conn.sendall(b"KEY_EXCHANGE_START")
        # --- Part 2: Key exchange logic will go here ---
        shared_key = None # Placeholder for the negotiated session key
        logging.info(f"[{addr[1]}] KEY EXCHANGE Complete. Shared Key: {shared_key if shared_key else 'PENDING'}")
    except Exception as e:
        logging.error(f"[{addr[1]}] Key Exchange Failed: {e}")
        conn.close()
        return

    while True:
        try:
            # 1. Data Reception (Improved Buffer Management)
            encrypted_data_with_iv = recv_all(conn)
            
            if not encrypted_data_with_iv:
                break # Connection closed or error

            # 2. Logging Encrypted Packet Arrival
            logging.info(f"[{addr[1]}] PACKET ARRIVED - Size: {len(encrypted_data_with_iv)} bytes. Encrypted Data: {encrypted_data_with_iv[:20]!r}...")

            # --- Part 2 Placeholder: Decryption and Decapsulation ---
            decrypted_message = f"*** DECRYPTED MESSAGE PENDING (Size: {len(encrypted_data_with_iv)}) ***"
            logging.warning(f"[{addr[1]}] DECRYPTED: {decrypted_message}")
            
            # 3. Send Acknowledgment
            ack_message = f"ACK: Received & processed packet. ({len(encrypted_data_with_iv)} bytes)"
            conn.sendall(ack_message.encode('utf-8'))
            
        except ConnectionResetError:
            break
        except Exception as e:
            logging.error(f"[{addr[1]}] Unexpected error in client loop: {e}")
            break
            
    logging.info(f"[DISCONNECT] Client disconnected: {addr[0]}:{addr[1]}")
    conn.close()

# --- Server Startup ---
def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Good practice for quick restarts
    
    try:
        s.bind((HOST, PORT))
        s.listen()
        logging.info(f"--- VPN SERVER INITIATED ---")
        logging.info(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            
            # Start a new thread for the connected client (Efficient concurrent handling)
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            
            logging.info(f"New client connected. Active connections: {threading.active_count() - 1}")
            
    except Exception as e:
        logging.critical(f"Server Fatal Error: {e}")
        
    finally:
        logging.info("Server shutting down.")
        s.close()

if __name__ == "__main__":
    run_server()