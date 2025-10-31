def send_msg(conn, data: bytes):
    length = len(data).to_bytes(4, 'big')
    conn.sendall(length + data)

def recv_msg(conn) -> bytes:
    length_bytes = recvall(conn, 4)
    if not length_bytes:
        return b''
    length = int.from_bytes(length_bytes, 'big')
    return recvall(conn, length)

def recvall(conn, n):
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data