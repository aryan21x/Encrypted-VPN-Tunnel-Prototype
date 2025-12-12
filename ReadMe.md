# Encrypted VPN Tunnel Prototype

This project is a prototype of an encrypted VPN (Virtual Private Network) tunnel implemented in Python. It demonstrates the core concepts of a VPN, including secure key exchange, authenticated encryption, and IP packet encapsulation/decapsulation.

The project consists of a multi-threaded TCP server and a GUI-based client application built with **ReactPy**.

## Features

*   **Secure Key Exchange:** Uses **Diffie-Hellman (DH)** key exchange to securely establish a shared secret between the client and server over an insecure channel.
*   **Strong Encryption:** Uses **AES-GCM** (Advanced Encryption Standard in Galois/Counter Mode) for authenticated encryption and decryption of data packets.
*   **VPN Simulation:** Simulates network layer encapsulation by wrapping application data with a simulated IP header (Source/Destination IPs) before encryption.
*   **Interactive GUI:** The client features a web-based user interface (powered by ReactPy) to visualize the connection status, key exchange process, and real-time traffic logs (showing encrypted vs. decrypted data).
*   **Traffic Logging:** Displays detailed logs of sent and received packets, including packet size, type, and payload content.

## Prerequisites

*   Python 3.7+
*   `pip` (Python package manager)

## Installation

1.  Clone the repository or download the source code.
2.  Navigate to the project directory.
3.  Install the required dependencies using `pip`:

    ```bash
    pip install -r requirement.txt
    ```

## Usage

To run the prototype, you need to start the server first, and then the client.

### 1. Start the Server

Open a terminal and run:

```bash
python server.py
```

The server will start listening on `127.0.0.1:65432`.

### 2. Start the Client

Open a separate terminal and run:

```bash
python client.py
```

This will launch the ReactPy application. Depending on your environment, it may open a browser window automatically or provide a URL (usually `http://127.0.0.1:8000`) to access the client interface.

### 3. Using the Client Interface

1.  **Connect:** Click the **"Connect"** button to initiate the TCP connection and the Diffie-Hellman key exchange with the server.
2.  **Status:** Watch the "Connection Status" and "Key Exchange Status" indicators update.
3.  **Send Data:** Type a message in the input box and click **"Send"**.
4.  **View Logs:** Observe the "Traffic Log" to see how your message is:
    *   **Encapsulated:** Wrapped with simulated IP headers.
    *   **Encrypted:** Converted into ciphertext.
    *   **Sent:** Transmitted to the server.
    *   **Received (Echo):** The server (in this prototype) may echo back data or acknowledge receipt, which will be decrypted and displayed.

## Project Structure

*   **`server.py`**: The VPN server implementation. It handles incoming connections, performs the server-side DH key exchange, and decrypts/decapsulates incoming traffic.
*   **`client.py`**: The VPN client implementation with a ReactPy GUI. It handles the client-side DH key exchange, encapsulates/encrypts outgoing messages, and displays traffic logs.
*   **`ip_simulator.py`**: A utility module that simulates IP packet encapsulation (adding fake source/destination IP headers) and decapsulation.
*   **`requirement.txt`**: List of Python dependencies required for the project.

## Technical Details

### Cryptographic Flow
1.  **Connection:** Client connects to Server via TCP.
2.  **Key Exchange:**
    *   Server generates DH parameters and sends them to the Client.
    *   Client generates its public/private key pair and sends the public key to the Server.
    *   Server sends its public key to the Client.
    *   Both parties compute the **Shared Secret**.
3.  **Key Derivation:** Both parties use **HKDF** (HMAC-based Key Derivation Function) to derive a symmetric **AES-256** key from the shared secret.
4.  **Data Transmission:**
    *   **Encapsulation:** `[Simulated IP Header] + [Payload]`
    *   **Encryption:** AES-GCM encrypts the encapsulated data.
    *   **Transport:** The encrypted packet (Nonce + Ciphertext) is sent over the TCP socket.
