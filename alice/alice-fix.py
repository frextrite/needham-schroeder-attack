"""
This file represents Alice, a client who wants to transfer a file to a storage server.
Includes Lowe's fix.
"""
from socket import socket, AF_INET, SOCK_STREAM
import subprocess, sys, os
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from helpers import *


NAME = "alice"


def ns_authentication(sock, server_name):
    """(socket, str) -> bytes or NoneType
    Performs authentication via Needham-Schroeder public-key protocol.
    Returns a symmetric session key if authentication is successful,
    a None otherwise.

    :sock: connection to storage server
    :server_name: name of storage server
    """
    # get RSA key of Alice
    rsa_key = rsa.import_key("RsaKey.asc")

    # get public key of file transfer server
    subprocess.Popen([sys.executable, "..\\pks\\pks.py", "--extract"])
    pks_address = (PKS_HOST, PKS_PORT)
    server_pkey = ns.get_public_key(pks_address, server_name, NAME, rsa_key)
    server_pkey = rsa.import_key(server_pkey)

    # A -- {N_A, A}(K_PB) --> B
    alice_nonce = ns.generate_nonce()
    request = "{},{}".format(alice_nonce, NAME)
    request = rsa.encrypt(server_pkey, request)
    sock.sendall(request)
    print("Alice: sent nonce {} to {}".format(alice_nonce, server_name))

    # Lowe's fix: A <-- {N_A, N_B, B}(K_PA) -- B
    response = rsa.decrypt(rsa_key, sock.recv(1024))
    alice_resp_nonce, server_nonce, resp_name = response.split(',')
    alice_resp_nonce = int(alice_resp_nonce)
    server_nonce = int(server_nonce)
    print("Alice: recieved nonces {}, {} from {}".format(alice_resp_nonce, server_nonce, resp_name))

    # if server names do not match, it must be an attack
    if resp_name != server_name:
        request = bytes(str(RESP_DENIED), "utf-8")
        sock.sendall(request)
        return print("Alice: detected attempted NS-attack from {}!".format(server_name))

    # check if Bob actually did recieve Alice's nonce
    if alice_resp_nonce == alice_nonce:
        # A -- {K, N_B}(K_PB) --> B
        ssn_key = aes.generate_key()
        request = "{},{}".format(ssn_key.decode("utf-8"), server_nonce)
        request = rsa.encrypt(server_pkey, request)
        sock.sendall(request)
        print("Alice: sent session key {} and {}'s nonce {}".format(ssn_key, server_name, server_nonce))
        # get confirmation
        response = int(sock.recv(1024))
        if response == RESP_VERIFIED:
            print("Alice: connection verified!")
            return ssn_key
        else:
            print("Alice: connection cannot be verified, something went wrong")
    else:
        print("Alice: nonces do not match")


def upload_file(sock, ssn_key, file_name):
    """(socket, bytes, str) -> NoneType

    Uploads a file to the storage server.

    :sock: connection to storage server
    :ssn_key: session key for symmetric encryption
    :file_name: name of file to upload
    """
    # read file contents
    contents = None
    with open(file_name, "r") as fileStream:
        buffer = fileStream.read()
        contents = [buffer[0+i:16+i] for i in range(0, len(buffer), 16)]
    print("Alice: {} is read and ready for upload".format(file_name))

    # send signal to begin upload of contents
    request = aes.encrypt(ssn_key, SIG_START)
    sock.sendall(request)
    if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
        return print("Alice: something went wrong with file transfer, exiting...")
    print("Alice: beginning file upload...")

    # upload file contents
    for i, content in enumerate(contents):
        request = aes.encrypt(ssn_key, content)
        sock.sendall(request)
        if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
            return print("Alice: something went wrong with file transfer, exiting...")
        print("Alice: uploading file... ({}/{})".format(i+1, len(contents)))

    # send signal that upload is complete
    request = aes.encrypt(ssn_key, SIG_END)
    sock.sendall(request)
    if aes.decrypt(ssn_key, sock.recv(1024)) != SIG_GOOD:
        return print("Alice: something went wrong with file transfer, exiting...")
    print("Alice: successful upload for {}".format(file_name))


def download_file(sock, ssn_key, file_name):
    """(socket, bytes, str) -> NoneType

    Downloads a file to the storage server.

    :sock: connection to storage server
    :ssn_key: session key for symmetric encryption
    :file_name: name of file to download
    """
    # send signal to begin download
    request = aes.encrypt(ssn_key, SIG_START)
    sock.sendall(request)
    print("Alice: beginning download for {}...".format(file_name))

    # get file contents from client
    contents = list()
    completed_upload = False
    request = aes.encrypt(ssn_key, SIG_GOOD)
    while not completed_upload:
        response = aes.decrypt(ssn_key, sock.recv(1024))
        if response == SIG_END:
            completed_upload = True
            print("Alice: completed download for {}".format(file_name))
        else:
            contents.append(response)
        sock.sendall(request)

    # save file to current folder
    with open(file_name, "w") as outputStream:
        outputStream.write(''.join(contents))
    print("Alice: file saved in {}".format(file_name))


def communicate_storage(server_name, file_name, mode):
    """(str, str, str) -> NoneType

    Communicates with the storage server to upload or download a file with the given name.

    :file_name: name of file to upload or download

    REQ: if server_name == bob, bob.py is running
    REQ: if server_name == mallory, bob.py and mallory.py are running
    """
    # if mode is upload, check if file exists
    if mode == UPLOAD and not os.path.isfile(file_name):
        return print("Alice: file {} does not exist".format(file_name))

    # get connection details of storage server
    address = None
    if server_name == "bob":
        address = (BOB_HOST, BOB_PORT)
    elif server_name == "mallory":
        address = (MAL_HOST, MAL_PORT)
    else:
        return print("Alice: not a valid file storage server!")

    # begin communication with Bob
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(address)

        # go through NS protocol, get session key
        ssn_key = ns_authentication(sock, server_name)

        # if connection is not verified, exit
        if not ssn_key:
            return print("Alice: something went wrong with authentication, exiting...")
        print("Alice: using session key {}".format(ssn_key))

        # send over file name and mode of transfer
        request = "{},{}".format(file_name, mode)
        sock.sendall(aes.encrypt(ssn_key, request))
        print("Alice: sent file name {} for mode {}".format(file_name, mode))

        response = aes.decrypt(ssn_key, sock.recv(1024))
        if response == SIG_BAD and mode == DOWNLOAD:
            return print("Alice: {} does not exist in server, exiting...".format(file_name))
        elif response != SIG_GOOD:
            return print("Alice: something went wrong with file transfer, exiting...")

        # upload or download file from server
        if mode == UPLOAD:
            upload_file(sock, ssn_key, file_name)
        elif mode == DOWNLOAD:
            download_file(sock, ssn_key, file_name)

    print("Alice: client shutting down...")


if __name__ == "__main__":
    import getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options input_file')
        print ('Options:')
        print ('\t -s server_name, --server=server_name')
        print ('\t -u, --upload')
        print ('\t -d, --download')
        sys.exit(2)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hs:ud", ["help", "server=", "upload", "download"])
        if not opts:
            raise getopt.GetoptError("Enter an option")
    except getopt.GetoptError as err:
        print(err)
        usage()
    # extract parameters
    mode = None
    host_name = None
    input_file = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
        elif opt in ("-s", "--server"):
            host_name = arg
        elif opt in ("-d", "--download"):
            mode = "d"
        elif opt in ("-u", "--upload"):
            mode = "u"
    # check arguments
    if host_name is None:
        print('host name option is missing\n')
        usage()
    if input_file is None:
        print('input file is missing\n')
        usage()
    if mode is None:
        print('select a mode: [u,d]\n')
        usage()        
    # run the command
    communicate_storage(host_name, input_file, mode)
