import socket
import sys
from getpass import getpass

PINK = '\033[38;5;206m'
RESET = '\033[0m'

class Client:
    def __init__(self, host='127.0.0.1', port=50158):
        self.host = host
        self.port = port
        self.sock = None
        self.token = None
        self.user = None

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_frame(self, data):
        frame = f"LEN:{len(data)} {data}"
        self.sock.send(frame.encode())

    def recv_response(self):
        resp = self.sock.recv(4096).decode().strip()
        print(f"[SERVER] {resp}")
        return resp

    def register(self):
        print(f"\n{PINK}--- REGISTER ---{RESET}")
        u = input("Username: ").strip()
        p = getpass("Password: ")
        c = getpass("Confirm: ")
        if p != c:
            print("Passwords don't match")
            return False
        self.send_frame(f"REGISTER {u} {p}")
        return "OK" in self.recv_response()

    def login(self):
        print(f"\n{PINK}--- LOGIN ---{RESET}")
        u = input("Username: ").strip()
        p = getpass("Password: ")
        self.send_frame(f"LOGIN {u} {p}")
        resp = self.recv_response()
        if "Token:" in resp:
            self.token = resp.split("Token:")[1].strip()
            self.user = u
            print(f"Logged in as {u}")
            return True
        return False

    def logout(self):
        print(f"\n{PINK}--- LOGOUT ---{RESET}")
        if self.token:
            self.send_frame("LOGOUT")
            self.recv_response()
            self.token = None
            self.user = None
        else:
            print("[SERVER] Not logged in")

    def run(self):
        if not self.connect():
            return

        while True:
            print(f"\n{PINK}--- Menu ---{RESET}")
            print("1. Register")
            print("2. Login")
            print("3. Logout")

            choice = input("Choice: ").strip()

            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
            elif choice == '3':
                self.logout()
            elif choice == '':
                break
            else:
                print("Invalid choice")

        self.disconnect()

if __name__ == "__main__":
    Client().run()