import socket
from cryptography.hazmat.primitives import serialization
from encryption import generate_rsa_keys
from network.utils import send_msg, recv_msg

def start_client(host, port):
    private_key, public_key = generate_rsa_keys()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    #recieve public key
    server_pub = recv_msg(s)

    #send public key
    pub_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
    send_msg(s, pub_pem)
    
    return s, private_key, server_pub