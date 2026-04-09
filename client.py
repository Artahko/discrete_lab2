import rsa
import hashlib

import socket
import threading


def get_hash(message):
    """Get hash of the message"""
    return hashlib.sha256(message.encode()).hexdigest()

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

        # Server's public and private keys
        self.e = -1
        self.d = -1
        self.n = -1

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())


        client_e, client_d, client_n = rsa.generate_keys()

        # Send client's public key to the server so that server can share it's private key
        self.s.send(f"{client_e} {client_n}".encode())

        # Get server keys and decrypt them
        server_keys = self.s.recv(1024).decode()
        server_keys = rsa.decrypt(server_keys, client_d, client_n)
        self.e, self.d, self.n = [int(el) for el in server_keys.split()]

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(1024).decode()

            message_hash, message = message.split(":", 1)
            # Decrypt message using server's private key
            message = rsa.decrypt(message, self.d, self.n)

            if str(get_hash(message)) == message_hash:
                print(message)
            else:
                print("Message is corrupted")

    def write_handler(self):
        while True:
            message = input()

            message_hash = str(get_hash(message))
            # Encrypt message using server's public key
            message = rsa.encrypt(message, self.e, self.n)

            self.s.send(f"{message_hash}:{message}".encode())


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
