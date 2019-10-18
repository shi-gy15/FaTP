import socket
import os
import sys
import threading
import random
from util import u
from util import debug, info
from util import Command, User, ClientState


class Server:
    thread_id = 0

    def __init__(self):
        self.clients = {}
        self.busy_ports = set()
        self.x = threading.local()
        self.sock = socket.socket()
        self.sock.bind((u.host, u.listen_port))
        self.sock.listen(u.max_client)
        self.user_verification = {
            'anonymous': '*',
            'a': '*'
        }
        self.handler_map = {
            'USER': self.handle_user,
            'PASS': self.handle_password,
            'SYST': self.handle_system,
            'TYPE': self.handle_type,
            'PWD': self.handle_pwd
        }

    def new_port(self):
        while True:
            port = random.randint(u.port_start, 65535)
            if port not in self.busy_ports:
                self.busy_ports.add(port)
                return port

    def send_response(self, status: int, param: str):
        Command(status, param).send(self.x.client.sock)

    def auth(self, username: str, password: str):
        try:
            assert username in self.user_verification
            assert self.user_verification[username] in ['*', password]
        except AssertionError:
            return False
        self.x.client.authed = True
        self.x.client.user.password = password
        return True

    def handle_user(self, cmd: Command):
        username = cmd.param
        if self.x.client.authed:
            self.send_response(230, 'Already logged in.')
        else:
            self.x.client.user = User(username)
            self.send_response(331, 'Specify password.')

    def handle_password(self, cmd: Command):
        password = cmd.param

        if self.x.client.authed:
            self.send_response(202, 'Already logged in.')
        elif self.x.client.User is None:
            self.send_response(503, 'User first.')
        else:
            if self.auth(self.x.client.user.username, password):
                self.send_response(230, 'Logged in.')
            else:
                self.send_response(530, 'Auth failed.')

    def handle_system(self, cmd: Command):
        self.send_response(215, 'System type is Windows 10.')

    def handle_type(self, cmd: Command):
        trans_type = cmd.param

        if trans_type == 'I':
            self.send_response(200, 'Type set to I.')
        else:
            self.send_response(504, f'Type {trans_type} not implemented.')

    def handle_pwd(self, cmd: Command):
        self.send_response(257, os.getcwd())

    def handle_list(self, cmd: Command):
        pass

    def mainloop(self, thread_id, sock_c, addr_c):
        debug('Serve new client', thread_id, addr_c)
        self.x.client = ClientState(thread_id, sock=sock_c, addr=addr_c)
        while True:
            cmdstr = self.x.client.sock.recv(u.buflen)
            cmd = Command.from_str(cmdstr)
            debug(cmd)

            self.handler_map[cmd.verb](cmd)
            # self.handle_cmd(cmd)

    def run(self):
        debug('Server start')
        while True:
            sock_c, addr_c = self.sock.accept()
            debug('New connection arrives', sock_c, addr_c)

            thread = threading.Thread(target=self.mainloop, name=str(self.thread_id), args=(self.thread_id, sock_c, addr_c))
            self.thread_id += 1
            thread.start()


if __name__ == '__main__':
    Server().run()
