import socket                     # Network communication
import json                       # JSON data handling
import os                         # System commands
import ssl                        # SSL/TLS security
from threading import Lock, Thread  # Thread safety and background tasks
import logging                    # Event logging
import time                       # Timing for broadcasts
from cryptography import x509     # SSL certificate creation
from cryptography.hazmat.primitives import hashes, serialization  # Certificate details
from cryptography.hazmat.primitives.asymmetric import rsa  # RSA key generation
from cryptography.x509.oid import NameOID  # Certificate naming
import datetime                   # Certificate validity dates
import paths                      # Import centralized paths

# Configuration constants
adminKey = "SECRET_ADMIN_KEY_123"
whitelist = {"00:11:22:33:44:55"}  # Whitelisted MAC addresses

# Global state variables (reset on startup)
failedAttempts = {}
isLocked = False
threadLock = Lock()

# Configure logging
logging.basicConfig(filename=paths.SERVER_LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def generateSelfSignedCert():
    # Generate SSL certificate and key if missing
    if not (os.path.exists(paths.SERVER_CERT_FILE) and os.path.exists(paths.SERVER_KEY_FILE)):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "WaterBoy LS Server"),
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

        with open(paths.SERVER_KEY_FILE, "wb") as f:  # Save private key
            f.write(privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(paths.SERVER_CERT_FILE, "wb") as f:  # Save certificate
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logging.info("Generated self-signed SSL certificate and key.")

def getServerIp():
    # Get server’s IP address
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
            logging.info(f"Broadcasting server IP: {serverIp}")
            time.sleep(5)
        except Exception as e:
            logging.error(f"Broadcast error: {str(e)}")
            time.sleep(5)

def loadCredentials():
    # Load MAC/password credentials
    credentials = {}
    if os.path.exists(paths.SERVER_CREDENTIALS_FILE):
        with open(paths.SERVER_CREDENTIALS_FILE, "r") as f:
            for line in f:
                mac, pwd = line.strip().split(",")
                credentials[mac] = pwd
    return credentials

def lockSharedFolder():
    # Lock the shared drive
    global isLocked
    with threadLock:
        isLocked = True
        os.system(f'icacls "{paths.SERVER_SHARED_FOLDER}" /deny "Everyone:(F)"')
        os.system(f'net share "WaterBoy LS" /delete')
        os.system("net session /delete")
        logging.info("Shared drive locked and all devices disconnected.")

def unlockSharedFolder():
    # Unlock the shared drive
    global isLocked
    with threadLock:
        isLocked = False
        os.system(f'icacls "{paths.SERVER_SHARED_FOLDER}" /grant "Everyone:(F)"')
        os.system(f'net share "WaterBoy LS"="{paths.SERVER_SHARED_FOLDER}" /grant:Everyone,FULL')
        logging.info("Shared drive unlocked and shared.")

def handleRequest(data):
    # Handle client requests
    global failedAttempts

    action = data.get("action")
    macAddress = data.get("mac")
    password = data.get("password")

    if action == "logout" and macAddress:  # Handle client logout
        with threadLock:
            if macAddress in failedAttempts:
                del failedAttempts[macAddress]  # Clear client’s failed attempts
        logging.info(f"Client {macAddress} logged out.")
        return {"status": "success", "message": "Logged out"}

    if macAddress in whitelist:
        unlockSharedFolder()
        logging.info(f"Whitelisted MAC {macAddress} granted access.")
        return {"status": "success", "message": "Access granted (whitelisted)"}

    if isLocked:
        logging.warning(f"Access attempt by {macAddress} while server locked.")
        return {"status": "locked", "message": "Server is Locked. Contact IT/Admin."}

    if action == "unlock":
        credentials = loadCredentials()
        if macAddress in credentials and credentials[macAddress] == password:
            unlockSharedFolder()
            failedAttempts[macAddress] = 0
            logging.info(f"Access granted to {macAddress}.")
            return {"status": "success", "message": "Access granted"}
        else:
            with threadLock:
                failedAttempts[macAddress] = failedAttempts.get(macAddress, 0) + 1
                attempts = failedAttempts[macAddress]
                logging.warning(f"Failed attempt {attempts} by {macAddress}.")
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
        return {"status": "success", "message": "Server unlocked by admin"}

    return {"status": "error", "message": "Invalid request"}

# Main execution
serverIp = getServerIp()
logging.info(f"Server starting with IP: {serverIp}")

generateSelfSignedCert()

broadcastThread = Thread(target=broadcastServerIp, daemon=True)  # Start IP broadcast
broadcastThread.start()

# Set up SSL TCP server
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
sslContext.load_cert_chain(certfile=paths.SERVER_CERT_FILE, keyfile=paths.SERVER_KEY_FILE)
serverSocket = sslContext.wrap_socket(serverSocket, server_side=True)
serverSocket.bind(('0.0.0.0', 9999))
serverSocket.listen(5)
logging.info("Server running on port 9999 with SSL...")

while True:
    try:
        clientSocket, addr = serverSocket.accept()  # Accept connection
        data = clientSocket.recv(1024).decode()  # Receive data
        request = json.loads(data)
        response = handleRequest(request)  # Process request
        clientSocket.send(json.dumps(response).encode())  # Send response
        clientSocket.close()  # Close connection
    except Exception as e:
        logging.error(f"Server error: {str(e)}")