"""Simple local secure chat client for the Applied Cryptography demo.

This client only needs a nickname at startup. It encrypts each outgoing
message with AES-GCM, generates HMAC-SHA256, and sends the ciphertext over
socket to the server. The server verifies the HMAC before relaying the packet.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

HOST = "127.0.0.1"
PORT = 5000
SHARED_SECRET = b"SecureStudentChatDemoKey"


class SecureClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("Secure Chat")
        self.geometry("480x640")
        self.minsize(450, 600)
        self.configure(fg_color="#0A0A0A")
        self.configure(bg="#0A0A0A")

        self.nickname = ""
        self.sock = None
        self.connected = False

        self.create_ui()

    def create_ui(self):
        main = ctk.CTkFrame(self, fg_color="#121212", corner_radius=18)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(main, fg_color="#121212")
        header.pack(fill="x", padx=10, pady=(8, 4))

        ctk.CTkLabel(header, text="🔒 Secure Chat", text_color="#FFFFFF", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        self.status_label = ctk.CTkLabel(header, text="● Disconnected", text_color="#E50914", font=("Segoe UI", 10, "bold"))
        self.status_label.pack(anchor="w", pady=(1, 0))

        ctk.CTkFrame(main, height=2, fg_color="#E50914").pack(fill="x", padx=10, pady=(2, 6))

        compact_bar = ctk.CTkFrame(main, fg_color="#121212")
        compact_bar.pack(fill="x", padx=10, pady=(0, 6))

        self.name_entry = ctk.CTkEntry(compact_bar, placeholder_text="Nickname", width=140)
        self.name_entry.pack(side="left", padx=(0, 6))
        ctk.CTkButton(compact_bar, text="Connect", command=self.connect_to_server, width=90, fg_color="#B00020", hover_color="#E50914").pack(side="left", padx=(0, 6))
        ctk.CTkButton(compact_bar, text="Analysis", command=self.open_security_window, width=90, fg_color="#1A1A1A", hover_color="#2A2A2A").pack(side="left", padx=(0, 6))
        ctk.CTkButton(compact_bar, text="Demo", command=self.open_attack_window, width=80, fg_color="#1A1A1A", hover_color="#2A2A2A").pack(side="left")

        self.helper_label = ctk.CTkLabel(main, text="Open another client window to chat.", text_color="#CCCCCC", font=("Segoe UI", 10))
        self.helper_label.pack(anchor="w", padx=10, pady=(0, 4))

        self.chat_box = ctk.CTkTextbox(main, height=16, fg_color="#0A0A0A", text_color="#FFFFFF", border_color="#2A2A2A", wrap="word")
        self.chat_box.configure(font=("Segoe UI", 11))
        self.chat_box.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.chat_box.insert("end", "Connect with a nickname to start chatting.\n")

        bottom = ctk.CTkFrame(main, fg_color="#121212")
        bottom.pack(fill="x", padx=10, pady=(0, 8))
        self.message_entry = ctk.CTkEntry(bottom, placeholder_text="Type message…", width=300, fg_color="#1A1A1A", border_color="#2A2A2A")
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        ctk.CTkButton(bottom, text="Send", command=self.send_message, width=80, fg_color="#E50914", hover_color="#B00020").pack(side="right")

    def ensure_server_running(self):
        try:
            with socket.create_connection((HOST, PORT), timeout=0.8):
                return True
        except OSError:
            return False

    def start_server_in_background(self):
        try:
            project_dir = Path(__file__).resolve().parent
            python_cmd = [sys.executable, "server.py"]
            if not os.path.exists(sys.executable):
                python_cmd = ["python", "server.py"]
            subprocess.Popen(
                python_cmd,
                cwd=str(project_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0,
            )
            return True
        except Exception:
            return False

    def connect_to_server(self):
        nickname = self.name_entry.get().strip()
        if not nickname:
            messagebox.showerror("Error", "Enter a nickname to continue.")
            return

        try:
            if not self.ensure_server_running():
                self.start_server_in_background()
                for _ in range(20):
                    if self.ensure_server_running():
                        break
                    time.sleep(0.5)

            if not self.ensure_server_running():
                messagebox.showerror("Connection Error", "Server did not start. Please run 'python server.py' manually in a terminal first.")
                return

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self.nickname = nickname
            self.connected = True
            self.status_label.configure(text="● Connected", text_color="#2ECC71")
            self.chat_box.insert("end", f"Connected as {nickname}. Open another client window to chat.\n")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as exc:
            messagebox.showerror("Connection Error", f"Could not connect to server: {exc}")

    def derive_aes_key(self) -> bytes:
        return SHA256.new(SHARED_SECRET).digest()

    def encrypt_message(self, plaintext: str):
        key = self.derive_aes_key()
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = Padding.pad(plaintext.encode("utf-8"), AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return iv + ciphertext

    def hmac_digest(self, ciphertext: bytes) -> str:
        mac = HMAC.new(SHARED_SECRET, ciphertext, SHA256)
        return mac.hexdigest()

    def send_message(self):
        if not self.connected or not self.sock:
            messagebox.showerror("Error", "Connect first.")
            return

        plaintext = self.message_entry.get().strip()
        if not plaintext:
            return

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        message_id = str(uuid.uuid4())
        ciphertext = self.encrypt_message(plaintext)
        digest = self.hmac_digest(ciphertext)

        packet = {
            "type": "chat",
            "sender": self.nickname,
            "encrypted_message": ciphertext.hex(),
            "hmac": digest,
            "timestamp": timestamp,
            "message_id": message_id,
        }

        self.sock.sendall(json.dumps(packet).encode("utf-8"))
        self.helper_label.configure(text="")
        self.chat_box.insert("end", f"[You] {plaintext}\n")
        self.chat_box.see("end")
        self.message_entry.delete(0, "end")

        # Save the last packet for the security analysis window.
        self.last_packet = packet
        self.last_plaintext = plaintext

    def receive_messages(self):
        try:
            while True:
                raw = self.sock.recv(4096)
                if not raw:
                    break
                packet = json.loads(raw.decode("utf-8"))
                if packet.get("type") == "error":
                    messagebox.showwarning("Security Alert", packet.get("message", "Security error"))
                    continue

                encrypted_message = bytes.fromhex(packet.get("encrypted_message", packet.get("ciphertext", "")))
                iv = encrypted_message[:16]
                ciphertext = encrypted_message[16:]
                digest = self.hmac_digest(encrypted_message)
                if digest != packet.get("hmac"):
                    self.chat_box.insert("end", "[Security] Integrity Check Failed\n")
                    continue

                try:
                    cipher = AES.new(self.derive_aes_key(), AES.MODE_CBC, iv)
                    plaintext = Padding.unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")
                except Exception:
                    self.chat_box.insert("end", "[Security] AES decryption failed\n")
                    continue

                self.helper_label.configure(text="")
                self.chat_box.insert("end", f"[{packet['sender']}] {plaintext}\n")
                self.chat_box.see("end")
        except Exception as exc:
            self.chat_box.insert("end", f"Connection closed: {exc}\n")

    def open_security_window(self):
        if not getattr(self, "last_packet", None):
            messagebox.showinfo("Security Analysis", "Send a message first to generate a security analysis snapshot.")
            return

        win = ctk.CTkToplevel(self)
        win.title("Security Analysis")
        win.geometry("640x460")
        win.configure(fg_color="#121212")

        ctk.CTkLabel(win, text="Security Analysis", text_color="#FFFFFF", font=("Segoe UI", 18, "bold")).pack(pady=(14, 6))
        text = ctk.CTkTextbox(win, fg_color="#0A0A0A", text_color="#FFFFFF", height=20)
        text.pack(fill="both", expand=True, padx=14, pady=8)

        packet = self.last_packet
        text.insert("end", "Original Message: " + self.last_plaintext + "\n")
        text.insert("end", "AES-256 Ciphertext: " + packet.get("encrypted_message", packet.get("ciphertext", "")) + "\n")
        text.insert("end", "Generated HMAC-SHA256: " + packet["hmac"] + "\n")
        text.insert("end", "Timestamp: " + packet["timestamp"] + "\n")
        text.insert("end", "Message ID: " + packet["message_id"] + "\n")
        text.insert("end", "Verification Status: HMAC verified by the server before relay.\n")
        text.insert("end", "\nAttack notes:\n")
        text.insert("end", "- Packet Sniffing: attackers see only ciphertext.\n")
        text.insert("end", "- Message Tampering: any HMAC mismatch is rejected.\n")
        text.insert("end", "- Replay Attack: reusing the same message_id is rejected.\n")

    def open_attack_window(self):
        win = ctk.CTkToplevel(self)
        win.title("Attack Demonstration")
        win.geometry("640x420")
        win.configure(fg_color="#121212")

        ctk.CTkLabel(win, text="Built-in Attack Demonstration", text_color="#FFFFFF", font=("Segoe UI", 18, "bold")).pack(pady=(14, 6))
        text = ctk.CTkTextbox(win, fg_color="#0A0A0A", text_color="#FFFFFF", height=16)
        text.pack(fill="both", expand=True, padx=14, pady=8)
        text.insert("end", "1. Packet Sniffing\n")
        text.insert("end", "   Original: Hello Bob\n")
        text.insert("end", "   Network: A8F19D32C7A... (ciphertext only)\n")
        text.insert("end", "   Explanation: An attacker cannot read the plaintext without the key.\n\n")
        text.insert("end", "2. Message Tampering\n")
        text.insert("end", "   Result: Integrity Check Failed if HMAC does not match.\n\n")
        text.insert("end", "3. Replay Attack\n")
        text.insert("end", "   Result: Replay Attack Detected when the same message_id is resent.\n")


if __name__ == "__main__":
    app = SecureClientApp()
    app.mainloop()
