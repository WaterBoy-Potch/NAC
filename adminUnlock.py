import socket        # Network communication
import json          # JSON data handling
import ssl           # SSL/TLS security
import paths         # Import centralized paths

def discoverServerIp(timeout=10):
    # Discover server IP via UDP broadcast
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udpSocket.bind(('', 8888))  # Bind to port 8888
    udpSocket.settimeout(timeout)  # Set timeout to 10 seconds

    try:
        while True:
            data, addr = udpSocket.recvfrom(1024)  # Receive broadcast
            message = json.loads(data.decode())  # Decode JSON
            if message.get("serverName") == "WaterBoy LS":
                return addr[0]  # Return server IP
    except socket.timeout:
        return None  # Return None if timeout
    finally:
        udpSocket.close()  # Close socket

# Find server IP
serverIp = discoverServerIp()
if not serverIp:
    print("Could not find WaterBoy LS server!")  # Error if server not found
    exit(1)  # Exit with error code

# Set up SSL connection
sslContext = ssl.create_default_context()
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket = sslContext.wrap_socket(clientSocket, server_hostname=serverIp)

# Connect and send admin unlock request
clientSocket.connect((serverIp, 9999))  # Connect to port 9999
data = {"action": "admin_unlock", "mac": "admin", "password": "SECRET_ADMIN_KEY_123"}  # Admin unlock data
clientSocket.send(json.dumps(data).encode())  # Send JSON request
response = clientSocket.recv(1024).decode()  # Receive response
print(f"Server response: {response}")  # Display response
clientSocket.close()  # Close connection