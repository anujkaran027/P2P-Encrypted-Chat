import socket
import errno
from cryptography.hazmat.primitives import serialization
from encryption import generate_rsa_keys
from network.utils import send_msg, recv_msg

def start_server(host='0.0.0.0', port=5000, max_tries=10):
    private_key, public_key = generate_rsa_keys()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host_ip = bound_port = None

    #binding to free port
    for candidate_port in range(port, port + max_tries):   
        try:
            server.bind((host, candidate_port))
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            _, bound_port = server.getsockname()
            break
        except OSError as e:
            if e.errno != errno.EADDRINUSE:
                raise
            if candidate_port == port + max_tries - 1:
                raise OSError(f'All ports from {port} to {port + max_tries -1} are in use')

    #yield the address for immediate use
    yield host_ip, bound_port

    server.listen(1)

    conn, addr = server.accept()

    #send public key
    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    send_msg(conn, pub_pem)
    
    #receive peer key
    peer_pub = recv_msg(conn)
    yield conn, private_key, peer_pub, addr, server