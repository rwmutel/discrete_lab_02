import socket
import threading
import encryption
from hashlib import sha224

class Client:
    def __init__(self, server_ip: str, port: int) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = input('Enter username: ')

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return


        # create key pairs
        self.p, self.q, self.e = encryption.generate_key(20)
        self.d = encryption.generate_secret_key(self.e, self.p, self.q)

        # exchange public keys
        self.s.send(f'{self.p * self.q},{self.e},{self.username}'.encode())

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        self.server_n = 0
        self.server_e = 0
        while True:
            msg = self.s.recv(1024).decode()
            if self.server_e == 0:
                self.server_n, self.server_e = map(int, msg.split(','))
                # print(f'SERVER KEYS:{self.server_n, self.server_e}')
            else:
                # print(f'MESSAGE: {msg}')
                decrypted = encryption.decrypt(msg, self.d, self.p * self.q)

                print(decrypted)

    def write_handler(self):
        while True:
            message = input()

            # encrypt message with the secrete key
            encrypted = encryption.encrypt(message, self.server_e, self.server_n)

            # calculate the hash to check later
            msg_hash = sha224(message.encode()).hexdigest()

            self.s.send(f'{encrypted}:{msg_hash}'.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001)
    cl.init_connection()
