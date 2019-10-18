

class Util:
    host = '127.0.0.1'
    listen_port = 6789
    max_client = 100
    buflen = 8192
    port_start = 20000

u = Util


class CmdParseException(Exception):
    def __init__(self, *args):
        super(CmdParseException, self).__init__(*args)


def fprint(t, *s):
    fs = ' '.join(str(si) for si in s)
    print(f'[{t}] {fs}')


def debug(*s):
    fprint('DEBUG', *s)


def info(*s):
    fprint('INFO', *s)


class Command:
    def __init__(self, verb: int = None, param: str = None):
        self.verb = verb
        self.param = param

    @classmethod
    def from_str(cls, cmdstr: str):
        ps = cmdstr.split(' ')
        try:
            return Command(int(ps[0]), ps[1].replace('\r\n', ''))
        except:
            raise CmdParseException()

    def __str__(self):
        return f'[{self.verb}] [{self.param}]'

    def send(self, conn):
        if self.param is not None:
            fs = f'{self.verb} {self.param}\r\n'
        else:
            fs = f'{self.verb}\r\n'
        conn.send(fs.encode('utf-8'))


class User:

    def __init__(self, username: int = None):
        self.username = username
        self.password = None


class ClientState:
    def __init__(self, thread_id, sock=None, addr=None):
        self.thread_id = thread_id
        self.User = None
        self.authed = False
        self.sock = None
        self.addr = None
