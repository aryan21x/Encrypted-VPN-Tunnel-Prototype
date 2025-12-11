import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
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

#encryption with the shared key
#Gus
def encrypt_message(aes_key, plaintext: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)   # AES-GCM requires a **12-byte nonce**
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

#decryption function
#gus
def decrypt_message(aes_key, data: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


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
            #get the parameters from the client
            param_bytes = recv_all(s)
            parameters = serialization.load_pem_parameters(param_bytes)
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            logging.info(f"key's generated sending the key")
            #send the public key
            cli_pub_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            s.sendall(cli_pub_key)
            logging.info(f"sent the public key")

            ser_pub_key = recv_all(s)
            logging.info(f"received the server public key")

            server_public_key = serialization.load_pem_public_key(ser_pub_key)

            shared_key = private_key.exchange(server_public_key)
            logging.info(f"KEY EXCHANGE Complete. Shared Key: {shared_key if shared_key else 'PENDING'}")
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,             # 32 bytes = AES-256 key
                salt=None,
                info=b'handshake data'
            ).derive(shared_key)
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
            plaintext_bytes = message.encode('utf-8')

            # Encrypt the message properly
            encrypted_packet = encrypt_message(aes_key, plaintext_bytes)
            
            # 1. Logging Sent Packet
            logging.info(f"PACKET SENT - Original Data: '{message}' - Size: {len(encrypted_packet)} bytes.")
            
            # 2. Data Transmission (Sending the encapsulated packet)
            s.sendall(encrypted_packet)
            
            # 3. Receive Server Response and decrypt it
            response = recv_all(s)
            
            if not response:
                logging.warning("Server closed connection or no response received.")
                break

                
            logging.info(f"[SERVER] Response: {decrypt_message(aes_key, response).decode('utf-8', errors='ignore')}")
            
    except ConnectionRefusedError:
        logging.critical("Error: Server is not running or port is closed.")
    except Exception as e:
        logging.error(f"Client runtime error: {e}")
        
    finally:
        logging.info("Closing client connection.")
        s.close()

if __name__ == "__main__":
    run_client()