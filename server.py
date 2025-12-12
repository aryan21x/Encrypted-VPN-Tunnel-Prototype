# server.py (Complete)

import socket
import threading
import logging
import signal
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Assuming ip_simulator.py is in the same directory, we only need the custom functions
from ip_simulator import decapsulate_ip_header, HOST

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PORT = 65432
MAX_PACKET_SIZE = 4096

# Global flag for graceful shutdown
SERVER_RUNNING = True
SERVER_SOCKET = None

# --- Utility Functions ---

def recv_all(conn, max_size=MAX_PACKET_SIZE):
    """Receives all data from the socket up to the MAX_PACKET_SIZE."""
    data = b''
    try:
        chunk = conn.recv(max_size)
        data += chunk
        return data
    except Exception as e:
        # Handle exceptions gracefully during receive
        return None

def decrypt_message(aes_key, data: bytes):
    """Decrypts data (Nonce + Ciphertext) using the AES-GCM key."""
    aesgcm = AESGCM(aes_key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

def encrypt_message(aes_key, plaintext: bytes):
    """Encrypts plaintext and prepends the 12-byte Nonce for encapsulation."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

# --- Graceful Shutdown Handler ---
def signal_handler(sig, frame):
    """Handles Ctrl+C signal for clean server shutdown."""
    global SERVER_RUNNING
    logging.warning("\n[SHUTDOWN] Ctrl+C received. Shutting down server gracefully...")
    SERVER_RUNNING = False
    if SERVER_SOCKET:
        SERVER_SOCKET.close() # Close the listening socket
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# --- Main Client Handler ---
def handle_client(conn, addr):
    global SERVER_RUNNING
    logging.info(f"[CONNECTION] Client connected: {addr[0]}:{addr[1]}")
    aes_key = None
    
    try:
        # --- DH Key Exchange --- 
        logging.info(f"[{addr[1]}] Starting KEY EXCHANGE (DH)...")
        conn.sendall(b"KEY_EXCHANGE_START")
        
        # 1. Generate DH Parameters on Server
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        logging.info(f"[{addr[1]}] DH Keys generated. Sending parameters to client...")
        
        # 2. Send DH Parameters to Client
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        conn.sendall(param_bytes)
        
        # 3. Receive Client Public Key
        cli_pub_key = recv_all(conn)
        logging.info(f"[{addr[1]}] Received client public key")
        client_public_key = serialization.load_pem_public_key(cli_pub_key)
        
        # 4. Send Server Public Key
        ser_pub_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(ser_pub_key)
        logging.info(f"[{addr[1]}] Sent server public key")
        
        # 5. Calculate Shared Key and Derive AES Key
        shared_key = private_key.exchange(client_public_key)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 32 bytes = AES-256 key
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        
        logging.info(f"[{addr[1]}] KEY EXCHANGE Complete. AES Key Derived.")
        
    except Exception as e:
        logging.error(f"[{addr[1]}] Key Exchange Failed: {e}")
        conn.close()
        return

    # --- Main Data Tunnel Loop ---
    while SERVER_RUNNING:
        try:
            # 1. Data Reception (Encrypted)
            encrypted_data_with_iv = recv_all(conn)
            
            if not encrypted_data_with_iv:
                break # Connection closed or error

            logging.info(
                f"[{addr[1]}] PACKET ARRIVED - Size: {len(encrypted_data_with_iv)} bytes | Preview: {encrypted_data_with_iv[:20]!r}"
            )

            # 2. Decryption and Decapsulation
            plaintext_bytes = decrypt_message(aes_key, encrypted_data_with_iv)
            
            # Simulated IP Decapsulation
            simulated_header, original_payload = decapsulate_ip_header(plaintext_bytes)
            decrypted_message = original_payload.decode("utf-8")
            
            logging.info(f"[{addr[1]}] DECRYPTED: Header={simulated_header.decode('utf-8')} -> Payload='{decrypted_message}'")
            
            # 3. Send Encrypted Acknowledgment (ACK)
            header_str = simulated_header.decode('utf-8')
            src_ip = header_str.split(':')[0]
            ack_message = f"ACK: Received payload '{decrypted_message[:15]}' from {src_ip}."
            conn.sendall(encrypt_message(aes_key, ack_message.encode('utf-8')))
            
        except ConnectionResetError:
            break
        except Exception as e:
            if SERVER_RUNNING: # Only log if not shutting down
                logging.error(f"[{addr[1]}] Unexpected error in client loop: {e}")
            break
            
    logging.info(f"[DISCONNECT] Client disconnected: {addr[0]}:{addr[1]}")
    conn.close()

# --- Server Startup ---
def run_server():
    global SERVER_SOCKET, SERVER_RUNNING
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1.0) # Set timeout for graceful shutdown check
        s.bind((HOST, PORT))
        s.listen()
        SERVER_SOCKET = s
        
        logging.info(f"--- VPN SERVER INITIATED ---")
        logging.info(f"Server listening on {HOST}:{PORT}")
        
        while SERVER_RUNNING:
            try:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                client_thread.start()
                
                logging.info(f"New client connected. Active connections: {threading.active_count() - 1}")
            except socket.timeout:
                continue # Check the SERVER_RUNNING flag
            
    except OSError as e:
        if SERVER_RUNNING: # Don't log error if it's the expected shutdown close()
            logging.critical(f"Server Fatal Error: {e}")
            
    finally:
        if SERVER_SOCKET:
             SERVER_SOCKET.close()
        logging.info("Server shut down complete.")

if __name__ == "__main__":
    run_server()