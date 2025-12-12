# client.py (Robust Version)

import time
import socket
import threading
import logging
import asyncio
from reactpy import component, html, run, use_state, use_effect, use_ref, use_callback

# Import cryptography and simulator functions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Assuming ip_simulator.py is in the same directory
from ip_simulator import encapsulate_with_ip, SIM_SRC_IP, SIM_DST_IP, HOST

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants ---
PORT = 65432
MAX_PACKET_SIZE = 4096

# --- Utility Functions ---

def recv_all(conn, max_size=MAX_PACKET_SIZE):
    """Receives all data from the socket up to the MAX_PACKET_SIZE."""
    data = b''
    try:
        chunk = conn.recv(max_size)
        data += chunk
        return data
    except Exception as exc:
        logging.error(f"Error receiving data: {exc}")
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

@component
def VpnClientApp():
    # State hooks for the UI components
    connection_status, set_connection_status = use_state("Disconnected")
    key_exchange_status, set_key_exchange_status = use_state("Awaiting connection...")
    server_ack, set_server_ack = use_state("")
    traffic_log, set_traffic_log = use_state([]) 
    message_input, set_message_input = use_state("")

    # Refs to track socket, keys, and component lifecycle
    sock_ref = use_ref(None)
    aes_key_ref = use_ref(None)
    is_active = use_ref(True)  # <-- NEW: Tracks if the app is currently running
    loop_ref = use_ref(asyncio.get_event_loop())

    # Helper function to update the traffic log
    def update_log(direction, type_val, size, payload, encrypted_data=None, decrypted_data=None):
        if not is_active.current: return # Check before updating
        
        log_entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "direction": direction,
            "type": type_val,
            "size": size,
            "payload": payload,
            "encrypted": encrypted_data,
            "decrypted": decrypted_data
        }
        set_traffic_log(lambda current: [log_entry] + current[:19])

    # Helper to safely update status (prevents errors if app is closed)
    def safe_set_status(status):
        if is_active.current:
            print(f"[CLIENT] Connection Status: {status}")  # Debug log
            loop_ref.current.call_soon_threadsafe(set_connection_status, status)

    def safe_set_key_status(status):
        if is_active.current:
            print(f"[CLIENT] Key Exchange Status: {status}")  # Debug log
            loop_ref.current.call_soon_threadsafe(set_key_exchange_status, status)

    # --- Connection and Key Exchange Logic ---
    
    def handle_connect(event):
        if connection_status == "Connected":
            return

        # Reset states
        set_connection_status("Connecting...")
        set_key_exchange_status("Initiating Handshake...")
        set_server_ack("")
        aes_key_ref.current = None
        
        def connect_and_handshake():
            try:
                logging.info("[CLIENT] Starting connection...")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((HOST, PORT))
                sock_ref.current = s
                safe_set_status("Connected")
                logging.info("[CLIENT] Connected to server")

                # 1. Start Handshake
                safe_set_key_status("Awaiting server handshake...")
                logging.info("[CLIENT] Waiting for handshake...")
                handshake = recv_all(s)
                logging.info(f"[CLIENT] Received handshake: {handshake}")
                
                if handshake and handshake.decode('utf-8') == "KEY_EXCHANGE_START":
                    safe_set_key_status("Receiving DH Parameters...")
                    logging.info("[CLIENT] Receiving DH parameters...")
                    
                    # 2. Receive DH Parameters from Server
                    param_bytes = recv_all(s)
                    logging.info(f"[CLIENT] Received parameters: {len(param_bytes) if param_bytes else 0} bytes")
                    parameters = serialization.load_pem_parameters(param_bytes)
                    
                    safe_set_key_status("Generating keys...")
                    logging.info("[CLIENT] Generating DH keys...")
                    
                    # 3. Generate DH Keys (Client)
                    private_key = parameters.generate_private_key()
                    public_key = private_key.public_key()
                    
                    # 4. Send Client Public Key
                    safe_set_key_status("Sending client key...")
                    logging.info("[CLIENT] Sending client public key...")
                    cli_pub_key = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    s.sendall(cli_pub_key)
                    
                    # 5. Receive Server Public Key
                    safe_set_key_status("Receiving server key...")
                    logging.info("[CLIENT] Waiting for server public key...")
                    ser_pub_key = recv_all(s)
                    logging.info(f"[CLIENT] Received server key: {len(ser_pub_key) if ser_pub_key else 0} bytes")
                    server_public_key = serialization.load_pem_public_key(ser_pub_key)
                    
                    # 6. Calculate Shared Key
                    safe_set_key_status("Deriving AES-256 key...")
                    logging.info("[CLIENT] Deriving shared key...")
                    shared_key = private_key.exchange(server_public_key)
                    
                    # 7. Derive AES Key using HKDF
                    logging.info("[CLIENT] Deriving AES-256 key with HKDF...")
                    aes_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data'
                    ).derive(shared_key)
                    
                    aes_key_ref.current = aes_key
                    safe_set_key_status("Key Exchange Success!")
                    logging.info("[CLIENT] Key exchange completed successfully!")
                    
                else:
                    safe_set_key_status("Key Exchange Failed: No Handshake Start.")
                    logging.error("[CLIENT] Key exchange failed - no handshake")
                
            except ConnectionRefusedError:
                safe_set_status("Connection Refused (Server Down)")
                safe_set_key_status("Key Exchange Failed.")
                logging.critical("[CLIENT] Connection refused - server down")
            except Exception as e:
                # Ignore errors if we intentionally closed the socket
                if is_active.current: 
                    safe_set_status("Error")
                    safe_set_key_status(f"Fatal Error: {e!r}")
                    logging.error(f"[CLIENT] Error: {e}")
            
        # Start the thread
        thread = threading.Thread(target=connect_and_handshake, daemon=True)
        thread.start()

    def handle_disconnect(event):
        if sock_ref.current:
            try:
                sock_ref.current.close()
            except:
                pass
            sock_ref.current = None
        
        aes_key_ref.current = None
        set_connection_status("Disconnected")
        set_key_exchange_status("Disconnected")
        set_server_ack("")

    @use_effect(dependencies=[])
    def cleanup_on_unmount():
        is_active.current = True
        def cleanup():
            is_active.current = False
            if sock_ref.current:
                try:
                    sock_ref.current.close()
                except:
                    pass
        return cleanup

    # --- Key Exchange Step Tracker ---
    def get_key_exchange_steps():
        """Returns a list of key exchange steps with their status."""
        status = key_exchange_status
        steps = [
            {
                "name": "Initiate Handshake", 
                "icon": "fa-handshake", 
                "status": "complete" if any(x in status for x in ["Receiving DH", "Generating", "Sending", "Receiving server", "Deriving", "Success"]) else ("active" if any(x in status for x in ["Initiating", "Awaiting"]) else "pending")
            },
            {
                "name": "Receive DH Parameters", 
                "icon": "fa-key", 
                "status": "complete" if any(x in status for x in ["Generating", "Sending", "Receiving server", "Deriving", "Success"]) else ("active" if "Receiving DH" in status else "pending")
            },
            {
                "name": "Send/Receive Keys", 
                "icon": "fa-lock", 
                "status": "complete" if any(x in status for x in ["Deriving", "Success"]) else ("active" if any(x in status for x in ["Sending", "Receiving server"]) else "pending")
            },
            {
                "name": "Derive AES-256 Key", 
                "icon": "fa-shield", 
                "status": "complete" if "Success" in status else ("active" if "Deriving" in status else "pending")
            },
        ]
        return steps

    # --- Send Packet Logic ---
    @use_callback(dependencies=[aes_key_ref, message_input, connection_status, key_exchange_status])
    def send_packet(event):
        s = sock_ref.current
        aes_key = aes_key_ref.current
        
        if not s or not aes_key or connection_status != "Connected":
            set_server_ack("Error: Not connected or key exchange failed.")
            return

        message = message_input
        if not message:
            return

        try:
            plaintext_bytes = message.encode('utf-8')
            
            # Encapsulation (Simulated IP Header)
            plaintext_with_ip = encapsulate_with_ip(plaintext_bytes)
            
            # Encryption (AES-GCM)
            encrypted_packet = encrypt_message(aes_key, plaintext_with_ip)
            
            # Send
            s.sendall(encrypted_packet)

            logging.info(
                "PACKET SENT - Original: '%s' | Encrypted bytes: %d",
                message,
                len(encrypted_packet)
            )
            
            # Update Log (OUT direction) with encrypted and decrypted data
            update_log(
                "OUT", 
                "Encrypted", 
                len(encrypted_packet), 
                f"[IP Header] + '{message[:30]}{'...' if len(message) > 30 else ''}'",
                encrypted_data=encrypted_packet.hex(),
                decrypted_data=plaintext_with_ip.decode('utf-8', errors='ignore')
            )
            
            # Clear input
            set_message_input("")

            # Receive and Decrypt ACK
            response = recv_all(s)
            
            if response:
                logging.info(f"[CLIENT] ACK received, {len(response)} bytes")
                decrypted_ack = decrypt_message(aes_key, response).decode('utf-8')
                if is_active.current:
                    set_server_ack(decrypted_ack)
                
                # Update Log (IN direction) with encrypted and decrypted data
                update_log(
                    "IN", 
                    "Encrypted (ACK)", 
                    len(response), 
                    decrypted_ack[:60],
                    encrypted_data=response.hex(),
                    decrypted_data=decrypted_ack
                )
            else:
                logging.warning("[CLIENT] No server response (connection may be closed)")
                if is_active.current:
                    set_server_ack("Error: No server response received.")
                    set_connection_status("Disconnected")
                
        except Exception as e:
            logging.error(f"[CLIENT] Packet send error: {e}")
            if is_active.current:
                set_server_ack(f"Packet Send Error: {e!r}")
            
    # --- UI Rendering ---

    # Connection Status Light
    color = "red"
    if connection_status == "Connected" and aes_key_ref.current:
        color = "green"
    elif connection_status == "Connected":
        color = "yellow"
    elif connection_status == "Error":
        color = "red"
        
    status_light = html.div(
        {"style": {"width": "20px", "height": "20px", "borderRadius": "50%", "backgroundColor": color, "display": "inline-block", "marginRight": "10px"}}
    )
    
    # Key Exchange Progress Bar
    progress_style = {"width": "100%", "height": "20px", "backgroundColor": "#e9ecef", "borderRadius": "5px"}
    bar_style = {"height": "100%", "color": "white", "textAlign": "center", "borderRadius": "5px", "transition": "width 0.5s"}
    
    progress_width = (
    "100%" if key_exchange_status == "Key Exchange Success!" else
    "75%" if "Exchanging" in key_exchange_status else
    "50%" if "Receiving" in key_exchange_status else
    "25%" if "Awaiting" in key_exchange_status else
    "0%"
    )

    bar_color = "linear-gradient(90deg, #17a2b8, #28a745)" if key_exchange_status == "Key Exchange Success!" else "#17a2b8"

    # Status badges for quick glance
    connection_badge = html.span({
        "className": "badge",
        "style": {
            "backgroundColor": "#22c55e" if connection_status == "Connected" else ("#facc15" if connection_status.startswith("Connecting") else "#ef4444"),
            "color": "#0f172a",
            "padding": "6px 10px",
            "borderRadius": "999px",
            "fontWeight": "600",
            "letterSpacing": "0.02em"
        }
    }, connection_status)

    key_badge = html.span({
        "className": "badge",
        "style": {
            "backgroundColor": "#0ea5e9" if "Success" in key_exchange_status else "#e2e8f0",
            "color": "#0f172a",
            "padding": "6px 10px",
            "borderRadius": "999px",
            "fontWeight": "600",
            "letterSpacing": "0.02em"
        }
    }, key_exchange_status)
    
    # --- Key Exchange Steps Display ---
    steps = get_key_exchange_steps()
    
    steps_display = html.div(
        {"style": {"display": "flex", "justifyContent": "space-between", "alignItems": "center", "padding": "20px", "backgroundColor": "#f8f9fa", "borderRadius": "8px", "border": "1px solid #dee2e6"}},
        *[
            html.div(
                {"style": {
                    "textAlign": "center",
                    "flex": "1",
                    "position": "relative",
                    "padding": "10px"
                }},
                # Step Icon Circle
                html.div(
                    {"style": {
                        "width": "50px",
                        "height": "50px",
                        "borderRadius": "50%",
                        "backgroundColor": "#28a745" if step["status"] == "complete" else ("#007bff" if step["status"] == "active" else "#e9ecef"),
                        "display": "flex",
                        "alignItems": "center",
                        "justifyContent": "center",
                        "margin": "0 auto 10px",
                        "transition": "all 0.3s ease",
                        "boxShadow": "0 2px 8px rgba(0,0,0,0.1)" if step["status"] == "active" else "none",
                    }},
                    html.i({
                        "className": f"fa-solid {step['icon']}",
                        "style": {
                            "color": "white",
                            "fontSize": "20px"
                        }
                    })
                ),
                # Step Name
                html.small({
                    "style": {
                        "display": "block",
                        "fontWeight": "600",
                        "color": "#333",
                        "marginBottom": "4px"
                    }
                }, step["name"]),
                # Step Status Badge
                html.span({
                    "className": f"badge {'bg-success' if step['status'] == 'complete' else ('bg-primary' if step['status'] == 'active' else 'bg-secondary')}",
                    "style": {"fontSize": "10px"}
                }, "✓ Done" if step["status"] == "complete" else ("⟳ Active" if step["status"] == "active" else "○ Pending")),
                # Connector Line (except for last step)
                html.div({
                    "style": {
                        "position": "absolute",
                        "top": "35px",
                        "right": "-50%",
                        "width": "100%",
                        "height": "3px",
                        "backgroundColor": "#28a745" if step["status"] == "complete" else "#e9ecef",
                        "display": "none" if steps.index(step) == len(steps) - 1 else "block"
                    }
                })
            )
            for step in steps
        ]
    )
    
    # Status Message Box
    status_message = html.div(
        {"style": {
            "marginTop": "15px",
            "padding": "12px 15px",
            "borderRadius": "6px",
            "backgroundColor": "#d4edda" if "Success" in key_exchange_status else "#cfe2ff",
            "border": f"1px solid {'#198754' if 'Success' in key_exchange_status else '#084298'}",
            "color": f"{'#155724' if 'Success' in key_exchange_status else '#084298'}"
        }},
        html.strong({}, f"{'✓ ' if 'Success' in key_exchange_status else '⟳ '}{key_exchange_status}")
    )
    
    key_exchange_content = html.div(
        {},
        html.div(
            {"style": {"fontSize": "0.9em", "color": "#666", "marginBottom": "15px"}},
            "Establishing secure connection using Diffie-Hellman (2048-bit) with AES-256-GCM"
        ),
        steps_display,
        status_message,
        # Progress Bar
        html.div(
            {"style": {**progress_style, "marginTop": "15px"}},
            html.div({
                "style": {**bar_style, "width": progress_width, "backgroundColor": bar_color}
            })
        )
    )

    security_panel_content = html.div({},
        html.p(html.strong("Tunnel Status: "), status_light, html.span(connection_status)),
        
        html.div({"className": "mb-3"},
            html.button({
                "className": "btn btn-success btn-sm me-2", 
                "on_click": handle_connect,
                "disabled": connection_status == "Connected"
            }, "Connect"),
            html.button({
                "className": "btn btn-danger btn-sm", 
                "on_click": handle_disconnect,
                "disabled": connection_status == "Disconnected"
            }, "Disconnect")
        ),

        html.hr(),
        html.p(html.strong({}, "Encryption: "), "AES-256 GCM"),
        html.p(html.strong({}, "Key Exch: "), "DH (2048-bit)"),
        html.p(
            html.strong({}, "Simulated IPs: "), 
            html.br(),
            SIM_SRC_IP.decode(), 
            " ", 
            html.i({"className": "fa-solid fa-arrow-right", "style": {"color": "#28a745"}}),
            " ", 
            SIM_DST_IP.decode()
        ),
        html.p(
            html.strong({}, "Session Key: "), 
            html.span(
                {"style": {"color": "#28a745" if aes_key_ref.current else "red"}}, 
                "Yes" if aes_key_ref.current else "No"
            )
        ),
    )

    # Traffic Log Table with detailed information
    traffic_table = html.table({"className": "table table-striped table-sm", "style": {"fontSize": "0.9em"}},
        html.thead(
            html.tr(
                html.th("Time"),
                html.th("Dir"),
                html.th("Type"),
                html.th("Size"),
                html.th("Plaintext"),
                html.th("Encrypted (hex)"),
                html.th("Decrypted"),
            )
        ),
        html.tbody(
            [html.tr(
                html.td(entry["timestamp"]),
                html.td(
                    html.strong(
                        {"style": {"color": "#007bff" if entry["direction"] == "OUT" else "#28a745"}},
                        entry["direction"]
                    )
                ),
                html.td(html.small({}, entry["type"])),
                html.td(str(entry["size"])),
                html.td(
                    html.code(
                        {"style": {"fontSize": "0.85em", "backgroundColor": "#f5f5f5", "padding": "2px 4px", "borderRadius": "2px"}}, 
                        entry["payload"][:40] + "..." if len(entry["payload"]) > 40 else entry["payload"]
                    )
                ),
                html.td(
                    html.code(
                        {
                            "style": {
                                "fontSize": "0.8em",
                                "backgroundColor": "#ffeaa7",
                                "padding": "2px 4px",
                                "borderRadius": "2px",
                                "maxHeight": "30px",
                                "overflow": "hidden",
                                "display": "block",
                                "wordBreak": "break-all"
                            }
                        }, 
                        entry["encrypted"][:60] + "..." if entry["encrypted"] and len(entry["encrypted"]) > 60 else (entry["encrypted"] or "N/A")
                    )
                ),
                html.td(
                    html.code(
                        {
                            "style": {
                                "fontSize": "0.85em",
                                "backgroundColor": "#d1e7dd",
                                "padding": "2px 4px",
                                "borderRadius": "2px",
                                "maxHeight": "30px",
                                "overflow": "hidden",
                                "display": "block",
                                "wordBreak": "break-all"
                            }
                        }, 
                        entry["decrypted"][:40] + "..." if entry["decrypted"] and len(entry["decrypted"]) > 40 else (entry["decrypted"] or "N/A")
                    )
                ),
            ) for entry in traffic_log]
        )
    )

    return html.div({"className": "container-fluid p-3", "style": {"minHeight": "100vh", "background": "#f0f2f5", "color": "#333"}},
        html.link({
            "rel": "stylesheet", 
            "href": "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
        }),
        html.link({
            "rel": "stylesheet", 
            "href": "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"
        }),
        html.style({
            "children": [
"""
body { color: #333; }
.glass-card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
.accent-title { color: #0284c7; letter-spacing: 0.01em; font-weight: 600; }
.subtitle { color: #64748b; font-size: 0.9em; }
.card-border { border-top: 3px solid #0284c7; }
.log-table code { color: #0f172a; }
.pill { border-radius: 999px; padding: 6px 12px; font-weight: 600; }
"""
            ]
        }),

        # Header - Compact
        html.div({"className": "d-flex justify-content-between align-items-center mb-3"},
            html.div(
                html.h4({"className": "mb-0", "style": {"color": "#1e293b", "fontWeight": "700"}}, 
                    html.i({"className": "fa-solid fa-lock me-2"}), "Secure VPN Tunnel"
                ),
                html.small({"className": "subtitle"}, "Diffie-Hellman 2048 + AES-256-GCM")
            ),
            connection_badge
        ),

        # Top Section: Status, Key Exchange, Crypto, Send Packet
        html.div({"className": "row g-3 mb-3"},
            # Left Column: Status & Crypto & Send Packet
            html.div({"className": "col-md-4 d-flex flex-column gap-3"},
                # Status Panel
                html.div({"className": "glass-card card-border p-3"},
                    html.h5({"className": "accent-title mb-3"}, "Control Panel"),
                    security_panel_content
                ),
                # Crypto Details (Compact)
                html.div({"className": "glass-card card-border p-3"},
                     html.h6({"style": {"marginBottom": "10px", "fontWeight": "bold"}}, "Cryptographic Details"),
                     html.table({"className": "table table-sm", "style": {"marginBottom": "0", "fontSize": "0.85em"}},
                        html.tbody(
                            html.tr(
                                html.td(html.strong("Connection Status:")),
                                html.td(connection_status, " (", "🟢 Secure" if connection_status == "Connected" and aes_key_ref.current else "🔴 Insecure", ")")
                            ),
                            html.tr(
                                html.td(html.strong("Session AES-256 Key:")),
                                html.td(
                                    html.code({
                                        "style": {
                                            "fontSize": "0.8em",
                                            "wordBreak": "break-all",
                                            "padding": "4px 6px",
                                            "backgroundColor": "#f5f5f5",
                                            "borderRadius": "3px",
                                            "display": "block",
                                            "color": "#d946ef" if aes_key_ref.current else "#999"
                                        }
                                    }, 
                                    aes_key_ref.current.hex() if aes_key_ref.current else "Not derived yet"
                                    )
                                )
                            ),
                            html.tr(
                                html.td(html.strong("Key Length:")),
                                html.td(f"{len(aes_key_ref.current) * 8} bits" if aes_key_ref.current else "N/A")
                            ),
                            html.tr(
                                html.td(html.strong("Algorithm:")),
                                html.td("AES-256-GCM")
                            ),
                            html.tr(
                                html.td(html.strong("Nonce Size:")),
                                html.td("96 bits (12 bytes)")
                            ),
                        )
                    )
                ),
                 # Send Packet (Compact)
                html.div({"className": "glass-card card-border p-3"},
                    html.h6({"className": "card-title", "style": {"color": "#333"}}, "Send Encrypted Packet"),
                    html.div({"className": "input-group mb-2"},
                        html.input({
                            "type": "text",
                            "className": "form-control",
                            "placeholder": "Enter data...",
                            "value": message_input,
                            "on_change": lambda event: set_message_input(event['target']['value'])
                        }),
                        html.button({
                            "className": "btn btn-primary",
                            "on_click": send_packet,
                            "disabled": connection_status != "Connected" or key_exchange_status != "Key Exchange Success!"
                        }, html.i({"className": "fa-solid fa-paper-plane"}))
                    ),
                    html.div({"className": "alert p-2 mb-0", "role": "alert", "style": {"backgroundColor": "#e0f2fe", "color": "#0369a1", "border": "1px solid #bae6fd", "fontSize": "0.85em"}}, 
                        html.strong("Server ACK: "), " ", server_ack or "Waiting..."
                    )
                )
            ),
            
            # Right Column: Key Exchange Visualization
            html.div({"className": "col-md-8"},
                html.div({"className": "glass-card card-border p-3 h-100"},
                    html.div({"className": "d-flex align-items-center justify-content-between mb-2"},
                        html.h5({"className": "accent-title mb-0"}, "Key Exchange Protocol"),
                        key_badge
                    ),
                    key_exchange_content
                )
            )
        ),

        # Bottom Section: Traffic Log (Expanded)
        html.div({"className": "row"},
            html.div({"className": "col-12"},
                html.div({"className": "glass-card card-border h-100"},
                    html.div({"className": "card-body p-0"},
                        html.div({"className": "p-3 border-bottom"},
                            html.h5({"className": "card-title mb-0", "style": {"color": "#333"}}, "📊 Traffic Log & Packet Analysis")
                        ),
                        html.div({"style": {"height": "calc(100vh - 450px)", "minHeight": "400px", "overflowY": "auto", "fontSize": "0.9em"}}, traffic_table)
                    )
                )
            )
        )
    )

if __name__ == "__main__":
    print("\n--- STARTING VPN CLIENT GUI ---")
    print("Open your browser to the displayed address (e.g., http://127.0.0.1:8000)")
    run(VpnClientApp)