import socket

async def port_scan(host: str):
    open_ports = []

    for port in [80, 443, 8080]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return {
        "open_ports": open_ports
    }