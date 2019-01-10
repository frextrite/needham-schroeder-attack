from socket import socket, AF_INET, SOCK_STREAM
import sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from helpers import *


# connection details
HOST = '127.0.0.1'
PORT = 65432

def setup():
    """() -> NoneType

    Opens the public key server for importing RSA public keys.
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        conn, addr = sock.accept()
        with conn:
            print('PKS: connection from address', addr)
            while True:
                request = conn.recv(1024)
                if not request:
                    break
                # parse request
                host, pub_key = request.split(b'$')
                # save extracted public key as local file
                host = host.decode("utf-8")
                with open("pks\\" + host + ".asc", "wb") as outputStream:
                    outputStream.write(pub_key)
                # send response back to client
                print("PKS: recieved", host, "public key")
                response = bytes("RESPONSE: public key for " + host + " imported", "utf-8")
                conn.sendall(response)


def extract():
    """() -> NoneType

    Opens the public key server to extract RSA public keys.
    The public keys must have already been imported to the server.
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen()
        conn, addr = sock.accept()
        with conn:
            print('PKS: connection from address', addr)
            while True:
                # A, B --->
                request = conn.recv(1024)
                if not request:
                    break
                host_names = request.decode("utf-8").split(',')
                name_a, name_b = host_names
                # get public keys from local files
                key_a = rsa.import_key("..\\pks\\" + name_a + ".asc")
                key_b = rsa.import_key("..\\pks\\" + name_b + ".asc")
                # encrypt the public key in chunks
                pub_key_b = rsa.export_public_key(key_b).decode("utf-8")
                response = "{},{}".format(pub_key_b, name_b)
                cipherchunks = rsa.big_encrypt(key_a, response)
                # <--- {K_PB, B}(K_PA)
                response = b','.join(cipherchunks)
                conn.sendall(response)
                print("PKS: public key of " + name_b + " sent to " + name_a)


if __name__ == "__main__":
    print("PKS: I am the Public Key Server!")
    import getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options')
        print ('Options:')
        print ('\t -s, --setup')
        print ('\t -e, --extract')
        sys.exit(2)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hse", ["help", "setup", "extract"])
        if not opts:
            raise getopt.GetoptError("Enter an option")
    except getopt.GetoptError as err:
        print(err)
        usage()
    # extract parameters
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-s", "--setup"):
            print("PKS: listening for RSA keys to be added")
            setup()
        elif opt in ("-e", "--extract"):
            print("PKS: listening for a key to be extracted")
            extract()
