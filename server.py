import rsa
import socket
import threading

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        # Generate keys
        e, d, n = rsa.generate_keys()
        self.e = e
        self.d = d
        self.n = n

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(rsa.encrypt(f'new person has joined: {username}', self.e, self.n))
            self.username_lookup[c] = username
            self.clients.append(c)

            # Get client's public key
            client_public_key = c.recv(1024).decode()
            client_e, client_n = [int(el) for el in client_public_key.split()]

            # Send encrypted server's public and private keys to the client
            c.send(rsa.encrypt(f"{self.e} {self.d} {self.n}", client_e, client_n).encode())

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:

            client.send(msg.encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)

if __name__ == "__main__":
    s = Server(9001)
    s.start()
