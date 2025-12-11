import socket
import threading

HOST = '127.0.0.1'  
PORT = 65432        

# Function to handle a single client connection
def handle_client(conn, addr):
    print(f"[CONNECTION] Client connected: {addr}")
    
    # Placeholder for Key Exchange logic here
    conn.sendall(b"KEY_EXCHANGE_START")
    
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            
            print(f"[{addr[1]}] Received Raw: {data.decode('utf-8', errors='ignore')}")
            
            conn.sendall(b"ACK: Received encrypted packet.")
            
        except ConnectionResetError:
            # Handles when the client abruptly closes
            break
            
    print(f"[DISCONNECT] Client disconnected: {addr}")
    conn.close()

def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            
            # Start a new thread for the connected client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            
            print(f"Active connections: {threading.active_count() - 1}")
            
    except Exception as e:
        print(f"Server error: {e}")
        
    finally:
        s.close()

if __name__ == "__main__":
    run_server()