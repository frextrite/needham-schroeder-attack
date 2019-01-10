from helpers import rsa
from helpers import aes
from helpers import ns


# connection for public key server
PKS_HOST = '127.0.0.1'
PKS_PORT = 65432

# connection for Bob
BOB_HOST = '127.0.0.2'
BOB_PORT = 65433

# connection for Mallory
MAL_HOST = '127.0.0.3'
MAL_PORT = 65434

# signals
RESP_VERIFIED = 200
RESP_DENIED = 401
SIG_START = '419'
SIG_GOOD = '420'
SIG_BAD = '421'
SIG_END = '422'

# modes of file transfer
UPLOAD = 'u'
DOWNLOAD = 'd'
