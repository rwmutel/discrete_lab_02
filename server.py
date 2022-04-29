import socket
import threading
import encryption

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        self.p, self.q, self.e = encryption.generate_key(20)
        self.d = encryption.generate_secret_key(self.e, self.p, self.q)


        while True:
            c, addr = self.s.accept()
            n, e, username = c.recv(1024).decode().split(',')
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = (int(n), int(e), username)
            c.send(f'{self.p * self.q},{self.e}'.encode())
            self.clients.append(c)

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients: 

            encrypted = encryption.encrypt(msg, self.username_lookup[client][1], self.username_lookup[client][0])
            print(f'message:{msg}')
            print(f'encr msg: {encrypted}')
            client.send(encrypted.encode())

    def handle_client(self, c: socket, addr): 
        while True:
            msg = c.recv(1024).decode()
            decrypted = encryption.decrypt(msg, self.d, self.p * self.q)

            for client in self.clients:
                if client != c:
                    encrypted = encryption.encrypt(decrypted, self.username_lookup[client][1], self.username_lookup[client][0])
                    print(f'message:{msg}')
                    print(f'decrypted: {decrypted}')
                    print(f'encr msg: {encrypted}')
                    client.send(encrypted.encode())

if __name__ == "__main__":
    s = Server(9001)
    s.start()
