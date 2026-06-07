"""Simple local secure chat server for the Applied Cryptography demo.

The server does not manage users or sessions. It only relays encrypted chat
packets and verifies HMAC + replay protection before forwarding them.
"""

import json
import socket
import threading
from datetime import datetime, timezone

from Crypto.Hash import HMAC, SHA256

HOST = "127.0.0.1"
PORT = 5000
SHARED_SECRET = b"SecureStudentChatDemoKey"

clients = {}
seen_message_ids = set()


def hmac_digest(ciphertext: bytes) -> str:
    mac = HMAC.new(SHARED_SECRET, ciphertext, SHA256)
    return mac.hexdigest()


def broadcast(packet: dict, sender_conn: socket.socket):
    payload = json.dumps(packet).encode("utf-8")
    for conn in list(clients.keys()):
        if conn is sender_conn:
            continue
        try:
            conn.sendall(payload)
        except OSError:
            conn.close()
            clients.pop(conn, None)


def handle_client(conn: socket.socket, addr):
    nickname = "Unknown"
    try:
        while True:
            raw = conn.recv(4096)
            if not raw:
                break
            packet = json.loads(raw.decode("utf-8"))
            if packet.get("type") != "chat":
                continue

            message_id = packet.get("message_id")
            if message_id in seen_message_ids:
                conn.sendall(json.dumps({"type": "error", "message": "Replay Attack Detected"}).encode("utf-8"))
                continue

            encrypted_message = bytes.fromhex(packet.get("encrypted_message", packet.get("ciphertext", "")))
            expected = hmac_digest(encrypted_message)
            if not packet.get("hmac") == expected:
                conn.sendall(json.dumps({"type": "error", "message": "Integrity Check Failed"}).encode("utf-8"))
                continue

            seen_message_ids.add(message_id)
            nickname = packet.get("sender", nickname)
            print(f"[{datetime.now(timezone.utc).isoformat()}] {nickname} -> {packet.get('receiver', 'ALL')}")
            broadcast(packet, conn)
    except Exception as exc:
        print(f"Client error: {exc}")
    finally:
        clients.pop(conn, None)
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    print("Secure chat server listening on", f"{HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            clients[conn] = addr
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
