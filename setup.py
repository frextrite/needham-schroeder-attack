from helpers import nshelpers
from socket import socket, AF_INET, SOCK_STREAM
import sys
import subprocess

# connection details
PKS_HOST = '127.0.0.1'
PKS_PORT = 65432

def main():
    # generate RSA keys
    alice_key = nshelpers.generate_rsa_key()
    print("RSA key successfully generated for Alice")
    bob_key = nshelpers.generate_rsa_key()
    print("RSA key successfully generated for Bob")
    mallory_key = nshelpers.generate_rsa_key()
    print("RSA key successfully generated for Mallory")

    # save private keys to respective directories
    nshelpers.save_rsa_key(alice_key, "alice\\RsaKey.asc")
    print("RSA key successfully saved for Alice")
    nshelpers.save_rsa_key(bob_key, "bob\\RsaKey.asc")
    print("RSA key successfully saved for Alice")
    nshelpers.save_rsa_key(mallory_key, "mallory\\RsaKey.asc")
    print("RSA key successfully saved for Mallory")

    # start up public key server
    subprocess.Popen([sys.executable, "pks\\pks.py", "--setup"])

    # get public keys to send to public key server to save
    alice_pk = nshelpers.export_public_key(alice_key)
    bob_pk = nshelpers.export_public_key(bob_key)
    mallory_pk = nshelpers.export_public_key(mallory_key)

    # begin communications with PKS
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((PKS_HOST, PKS_PORT))
        # send Alice's public key
        sock.sendall(b'alice$' + alice_pk)
        resp = sock.recv(1024)
        print('Received', resp)
        # send Bob's public key
        sock.sendall(b'bob$' + bob_pk)
        resp = sock.recv(1024)
        print('Received', resp)
        # send Mallory's public key
        sock.sendall(b'mallory$' + mallory_pk)
        resp = sock.recv(1024)
        print('Received', resp)


if __name__ == "__main__":
    main()
