import socket
import threading
import logging # Using standard logging module for better output control
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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

#decryption function
#gus
def decrypt_message(aes_key, data: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

#encryption with the shared key
#Gus
def encrypt_message(aes_key, plaintext: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)   # AES-GCM requires a **12-byte nonce**
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

# --- Main Client Handler ---
def handle_client(conn, addr):
    logging.info(f"[CONNECTION] Client connected: {addr[0]}:{addr[1]}")
    
    # --- Part 2 Placeholder: Diffie-Hellman Key Exchange ---
    try:
        logging.info(f"[{addr[1]}] Starting KEY EXCHANGE...")
        conn.sendall(b"KEY_EXCHANGE_START")
        # --- Part 2: Key exchange logic will go here ---
        #make our parameters, and both keys
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        logging.info(f"Keys made sending to client the parameters")
        #send the client the parameters
        param_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        conn.sendall(param_bytes)
        #grab the clients public key and send our public
        cli_pub_key = recv_all(conn)
        logging.info(f"received from client")
        client_public_key = serialization.load_pem_public_key(cli_pub_key)

        ser_pub_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(ser_pub_key)
        logging.info(f"sending to the client")

        shared_key = private_key.exchange(client_public_key)

        logging.info(f"[{addr[1]}] KEY EXCHANGE Complete. Shared Key: {shared_key if shared_key else 'PENDING'}")
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,             # 32 bytes = AES-256 key
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
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

            

            
            plaintext_bytes = decrypt_message(aes_key, encrypted_data_with_iv)
            decrypted_message = plaintext_bytes.decode("utf-8")

            logging.info(f"[{addr[1]}] DECRYPTED: {decrypted_message}")
            
            # 3. Send Acknowledgment
            ack_message = f"ACK: Received & processed packet. ({len(encrypted_data_with_iv)} bytes)"
            conn.sendall(encrypt_message(aes_key, ack_message.encode('utf-8')))
            
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