import socket

HOST = '127.0.0.1'
PORT = 65432

def run_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        s.connect((HOST, PORT))
        print("Connected to server. Ready to send.")
        
        # Initial message from server (expected KEY_EXCHANGE_START)
        handshake = s.recv(1024).decode('utf-8')
        print(f"[SERVER] Handshake received: {handshake}")
        
        # Main client loop to send multiple packets
        while True:
            message = input("Type data (or 'quit'): ")
            
            if message.lower() == 'quit':
                break
                
            # Placeholder for ENCRYPTION logic here
            s.sendall(message.encode('utf-8'))
            print("Sent packet.")
            
            response = s.recv(1024)
            print(f"Server response: {response.decode('utf-8')}")
            
    except ConnectionRefusedError:
        print("Error: Server is not running or port is closed.")
    except Exception as e:
        print(f"Client error: {e}")
        
    finally:
        print("Closing client connection.")
        s.close()

if __name__ == "__main__":
    run_client()