
import socket
from util import u

def test():
    sock = socket.socket()
    sock.connect((u.host, u.listen_port))
    sock.send(b'h1')
    sock.recv(20)


if __name__ == '__main__':
    test()