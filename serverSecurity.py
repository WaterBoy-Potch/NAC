import socket
import json
import os
import ssl
from threading import Lock, Thread
import logging
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

# File paths and constants
credentialsFile = "A:\\serverData\\credentials.txt"
sharedFolder = "A:\\"  # Root of the A: drive, shared as "WaterBoy LS"
adminKey = "SECRET_ADMIN_KEY_123"
whitelist = {"00:11:22:33:44:55"}
certFile = "A:\\serverData\\server.crt"
keyFile = "A:\\serverData\\server.key"

# Global state variables
failedAttempts = {}
isLocked = False
threadLock = Lock()

# Configure logging
logging.basicConfig(
    filename="A:\\serverData\\server.log", level=logging.INFO,
    format= "%(asctime)s - %(levelname)s - %(message)s"
)

def generateSelfSignedCert():
    # Generate SSL certificate and key if they don't exist
    if not (os.path.exists(certFile) and os.path.exists(keyFile)):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "WaterBoy LS"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            privateKey.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False
        ).sign(privateKey, hashes.SHA256())

        # Save private key
        with open(certFile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logging.info("Generated self-signed SSL certificate and key.")

def getServerIp():
    # Get server's IP Address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        serverIp = s.getsockname()[0]
    except Exception:
        serverIp = '127.0.0.1'
    finally:
        s.close()
    return serverIp

def broadcastServerIp():
    # Broadcast server IP via UDP
    serverIp = getServerIp()
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = json.dumps({"serverName": "WaterBoy LS", "ip": serverIp}).encode()

    while True:
            try:
                udpSocket.sendto(message, ('255.255.255.255', 8888))
                logging.info(f"Broadcasting error: {str(e)}")
                time.sleep(5)
            except Exception as e:
                logging.error(f"Broadcast error: {str(e)}")
                time.sleep(5)

def loadCredentials():
    # Load MAC/password credentials from file
    credentials = {}
    if os.path.exists(credentialsFile):
        with open(credentialsFile, "r") as f:
            for line in f:
                mac, pwd = line.strip().split(",")
                credentials[mac] = pwd
    return credentials

def lockSharedFolder():
    # Lock the shared drive
    global isLocked
    with threadLock:
        isLocked = True
        os.system(f'icacls "{sharedFolder}" /deny "Everyone:(F)"')
        os.system(f'net share "WaterBoy LS" /delete')
        os.system("net session /delete")
        logging.info("Shared drive locked and all devices disconnected.")

def unlockSharedFolder():
    # Unloc the shared drive
    global isLocked
    with threadLock:
        isLocked = False
        os.system(f'icacls "{sharedFolder}" /grant "Everyone:(F)"')
        os.system(f'net share "WaterBoy LS"="{sharedFolder}" /grant:Everyone,FULL')
        logging.info("Shared drive unlocked and shared.")

def handleRequest(data):
    # Handle client requests
    global failedAttempts

    action = data.get("action")
    macAddress = data.get("mac")
    password = data.get("password")

    if macAddress in whitelist:
        unlockSharedFolder()
        logging.info(f"Whitelisted MAC {macAddress} granted access.")
        return {"status": "success", "message": "Access granted."}
    
    if isLocked:
        logging.warning(f"Access attempt by {macAddress} while server locked.")
        return {"status": "locked", "message": "Server is Locked. Contact IT/Admin."}
    
    if action == "unlock":
        credentials = loadCredentials()
        if macAddress in credentials[macAddress] == password:
            unlockSharedFolder()
            failedAttempts[macAddress] = 0
            logging.info(f"Access granted to {macAddress}.")
            return {"status": "success", "message": "Access granted"}
        else:
            with threadLock:
                failedAttempts[macAddress] = failedAttempts.get(macAddress, 0) + 1
                attempts = failedAttempts[macAddress]
                logging.warning(f"Failed attempt {attempts} by {macAddress}")
            if attempts == 2:
                return {"status": "warning", "message": "Wrong credentials. 2 attempts failed. Contact IT/Admin."}
            elif attempts >= 3:
                lockSharedFolder()
                return {"status": "locked", "message": "Server locked after 3 failed attempts. Contact IT/Admin."}
            else:
                return {"status": "error", "message": "Incorrect password"}
            
    elif action == "admin_unlock" and password == adminKey:
        unlockSharedFolder()
        failedAttempts.clear()
        logging.info("Server unlocked by admin.")
        return {"status": "success", "message": "Server unlocked by admin."}

    return {"status": "error", "message": "Invalid request"}

# Main execution starts here
serverIp = getServerIp()
logging.info(f"Server starting with IP: {serverIp}")

generateSelfSignedCert()

# Start IP broadcasting in a thread
broadcastThread = Thread(target=broadcastServerIp, daemon=True)
broadcastThread.start()

# Set up SSL-secured TCP server
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
sslContext.load_cert_chain(certfile=certFile, keyfile=keyFile)
serverSocket = sslContext.wrap_socket(serverSocket, server_side=True)
serverSocket.bind(('0.0.0.0', 9999))
serverSocket.listen(5)
logging.info("Server running on port 9999 with SSL...")

# Handle incoming connections
while True:
    try:
        clientSocket, addr = serverSocket.accept()
        data = clientSocket.recv(1024).decode()
        request = json.loads(data)
        response = handleRequest(request)
        clientSocket.send(json.dumps(response).encode())
        clientSocket.close()
    except Exception as e:
        logging.error(f"Server error: {str(e)}")
        