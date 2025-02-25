import tkinter as tk              # GUI library
from tkinter import ttk, messagebox  # Modern widgets and pop-up messages
import uuid                       # For MAC address retrieval
import socket                     # Network communication
import json                       # JSON encoding/decoding
import ssl                        # SSL/TLS security
import os                         # OS interactions (unused here but included)
import threading                  # Background tasks (used by Tkinter)
import time                       # Timing for socket timeout

def getMacAddress():
    # Get client’s MAC address
    mac = uuid.getnode()
    return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))  # Format as XX:XX:XX:XX:XX:XX

def discoverServerIp(timeout=10):
    # Discover server IP via UDP broadcast
    udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udpSocket.bind(('', 8888))  # Bind to port 8888
    udpSocket.settimeout(timeout)  # Set timeout

    try:
        while True:
            data, addr = udpSocket.recvfrom(1024)  # Receive broadcast
            message = json.loads(data.decode())  # Decode JSON
            if message.get("serverName") == "WaterBoy LS":
                return addr[0]  # Return server IP
    except socket.timeout:
        return None  # Return None if timeout occurs
    finally:
        udpSocket.close()  # Close socket

def sendToServer(data, serverIp):
    # Send secure request to server
    sslContext = ssl.create_default_context()
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket = sslContext.wrap_socket(clientSocket, server_hostname=serverIp)
    try:
        clientSocket.connect((serverIp, 9999))  # Connect to server port 9999
        clientSocket.send(json.dumps(data).encode())  # Send JSON data
        response = clientSocket.recv(1024).decode()  # Receive response
        return json.loads(response)  # Return decoded response
    except Exception as e:
        return {"status": "error", "message": f"Server connection failed: {str(e)}"}
    finally:
        clientSocket.close()  # Close socket

def submitPassword():
    # Handle submit button click
    password = passwordEntry.get().strip()  # Get password input
    macAddress = getMacAddress()  # Get MAC address

    if not password:
        messagebox.showerror("Error", "Password field cannot be empty!")
        statusLabel.config(text="Status: Error - Empty Password")
        return

    serverIp = discoverServerIp()  # Find server IP
    if not serverIp:
        messagebox.showerror("Error", "Could not find WaterBoy LS server!")
        statusLabel.config(text="Status: Server Not Found")
        return

    data = {"action": "unlock", "mac": macAddress, "password": password}  # Prepare request
    response = sendToServer(data, serverIp)  # Send request

    # Handle server response
    if response["status"] == "success":
        messagebox.showinfo("Success", "Shared folder unlocked!")
        statusLabel.config(text="Status: Unlocked")
    elif response["status"] == "warning":
        messagebox.showwarning("Warning", response["message"])
        statusLabel.config(text="Status: Warning - Check Attempts")
    elif response["status"] == "locked":
        messagebox.showerror("Locked", "Server is locked! Contact IT/Admin.")
        statusLabel.config(text="Status: Locked")
    else:
        messagebox.showerror("Error", response["message"])
        statusLabel.config(text="Status: Failed")

def closeGui():
    # Close the GUI window
    root.destroy()

# Set up main GUI window
root = tk.Tk()
root.title("Client Security GUI - WaterBoy LS")
root.geometry("300x250")  # Set dimensions to 300x250 pixels
root.resizable(False, False)  # Disable resizing

root.attributes('-toolwindow', False)  # Enable standard window controls
root.protocol("WM_DELETE_WINDOW", closeGui)  # Link "X" to close function

# MAC address display
macLabel = ttk.Label(root, text="MAC Address:")
macLabel.pack(pady=10)  # Add with 10px vertical padding

macValue = getMacAddress()
macEntry = ttk.Entry(root, width=25)
macEntry.insert(0, macValue)  # Insert MAC address
macEntry.config(state='disabled')  # Make read-only
macEntry.pack()

# Password input
passwordLabel = ttk.Label(root, text="Enter Password:")
passwordLabel.pack(pady=10)

passwordEntry = ttk.Entry(root, width=25, show="*")  # Mask input with asterisks
passwordEntry.pack()

# Submit button
submitButton = ttk.Button(root, text="Submit", command=submitPassword)
submitButton.pack(pady=10)

# Close button
closeButton = ttk.Button(root, text="Close", command=closeGui)
closeButton.pack(pady=10)

# Status display
statusLabel = ttk.Label(root, text="Status: Waiting")
statusLabel.pack(pady=5)

root.mainloop()  # Start GUI event loop