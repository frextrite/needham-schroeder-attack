"""
This file represents Bob, a simple file storage server.
"""
from socket import socket, AF_INET, SOCK_STREAM
import subprocess, sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from helpers import *


NAME = "bob"


def ns_authentication(conn):
    """(socket, str) -> bytes or NoneType
    Performs authentication via Needham-Schroeder public-key protocol.
    Returns a symmetric session key and client's name if authentication
    is successful, a None otherwise.

    :sock: connection to storage server
    :server_name: name of storage server
    """
    # get RSA key of Bob for decrypting
    rsa_key = rsa.import_key("RsaKey.asc")

    # A -- {N_A, A}(K_PB) --> B
    request = rsa.decrypt(rsa_key, conn.recv(1024))
    client_nonce, client_name = request.split(',')
    print("Bob: recieved nonce {} from client {}".format(client_nonce, client_name))

    # get client's public key
    subprocess.Popen([sys.executable, "..\\pks\\pks.py", "--extract"])
    pks_address = (PKS_HOST, PKS_PORT)
    client_pkey = ns.get_public_key(pks_address, client_name, NAME, rsa_key)
    client_pkey = rsa.import_key(client_pkey)

    # A <-- {N_A, N_B} -- B
    bob_nonce = ns.generate_nonce()
    response = "{},{}".format(client_nonce, bob_nonce)
    response = rsa.encrypt(client_pkey, response)
    conn.sendall(response)
    print("Bob: sent nonces {}, {} to {}".format(client_nonce, bob_nonce, client_name))

    # A -- {K, N_B} --> B
    request = rsa.decrypt(rsa_key, conn.recv(1024))
    ssn_key, bob_resp_nonce = request.split(',')
    ssn_key = bytes(ssn_key, "utf-8")
    bob_resp_nonce = int(bob_resp_nonce)
    print("Bob: recieved session key {} and nonce {}".format(ssn_key, bob_resp_nonce))

    # check if client did actually recieve Bob's nonce
    if bob_resp_nonce == bob_nonce:
        response = bytes(str(RESP_VERIFIED), "utf-8")
        conn.sendall(response)
        print("Bob: connection verified!")
        return ssn_key, client_name
    else:
        print("Bob: nonces {} and {} do not match!".format(bob_nonce, bob_resp_nonce))


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
        return print("Bob: something went wrong with file transfer")
    response = aes.encrypt(ssn_key, SIG_GOOD)
    conn.sendall(response)
    print("Bob: beginning transfer for {}...".format(file_name))

    # get file contents from client
    contents = list()
    completed_upload = False
    response = aes.encrypt(ssn_key, SIG_GOOD)
    while not completed_upload:
        request = aes.decrypt(ssn_key, conn.recv(1024))
        if request == SIG_END:
            completed_upload = True
            print("Bob: completed transfer for {}".format(file_name))
        else:
            contents.append(request)
        conn.sendall(response)

    # save file to server folder
    file_path = "{}/{}".format(client_name, file_name)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as outputStream:
        outputStream.write(''.join(contents))
    print("Bob: file saved in {}".format(file_path))


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
        return print("Bob: something went wrong with file transfer")
    print("Bob: beginning transfer for {}...".format(file_name))
    # upload file contents to client
    for i, content in enumerate(contents):
        response = aes.encrypt(ssn_key, content)
        conn.sendall(response)
        if aes.decrypt(ssn_key, conn.recv(1024)) != SIG_GOOD:
            return print("Bob: something went wrong with file transfer, exiting...")
        print("Bob: transferring file... ({}/{})".format(i+1, len(contents)))
    # send signal that transfer is complete
    request = aes.encrypt(ssn_key, SIG_END)
    conn.sendall(request)
    if aes.decrypt(ssn_key, conn.recv(1024)) != SIG_GOOD:
        return print("Bob: something went wrong with file transfer, exiting...")
    print("Bob: successful upload for {}".format(file_name))


def serve_client():
    """() -> NoneType

    Communicates with the client by first ensuring mutual authentication via the Needham-Schroeder
    protocol, then securely transfer the file between the client and server.
    """
    # begin to serve client
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((BOB_HOST, BOB_PORT))
        sock.listen()
        conn, addr = sock.accept()
        with conn:
            print('Bob: connection from client with address', addr)
            while True:
                # get session key and client name from NS auth
                ssn_key = client_name = None
                result = ns_authentication(conn)
                if result:
                    ssn_key, client_name = result
                else:
                    return print("Bob: something went wrong with authentication, exiting...")
                print("Bob: using session key {} from client {}".format(ssn_key, client_name))

                # get file name and mode of transfer
                request = aes.decrypt(ssn_key, conn.recv(1024))
                file_name, mode = request.split(',')
                response = aes.encrypt(ssn_key, SIG_GOOD)
                print("Bob: recieved request of file {} for mode {}".format(file_name, mode))

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
                        return print("Bob: {} does not exist in server, exiting...".format(file_name))
                # done, stop server
                return print("Bob: transfer complete, shutting down...")
    

if __name__ == "__main__":
    print("Bob: storage server")
    print("Bob: beginning to serve clients...")
    serve_client()
