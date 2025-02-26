import tkinter as tk              # GUI library
from tkinter import ttk, messagebox  # Modern widgets and pop-ups
import uuid                       # MAC address retrieval
import socket                     # Network communication
import json                       # JSON encoding/decoding
import ssl                        # SSL/TLS security
import os                         # OS interactions (unused here)
import threading                  # Background tasks (used by Tkinter)
import time                       # Timing for CAPTCHA
import random                     # Random number for CAPTCHA

def getMacAddress():
    # Get MAC Address
    mac = uuid.getnode()
    return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))

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
        clientSocket.connect((serverIp, 9999)) # Connect to server port 9999
        clientSocket.send(json.dumps(data).encode()) # Send JSON data
        response = clientSocket.recv(1024).decode() # Recieve response
        return json.loads(response) # Return decoded response
    except Exception as e:
        return {"status": "error", "message": f"Server connection failed: {str(e)}"}
    finally:
        clientSocket.close() # Close socket

def verifyCaptcha():
    # Verify CAPTCHA answer
    userAnswer = captchaEntry.get().strip()
    if userAnswer == str(captchaAnswer):
        captchaFrame.pack_forget()  # Hide CAPTCHA screen
        loginFrame.pack() # Show login screen
    else:
        messagebox.showerror("Error", "Incorrect CAPTCHA answer.")
        generateCaptcha() # Reset Captcha

def generateCaptcha():
    # Generate new CAPTCHA
    global captchaAnswer
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    captchaAnswer = num1 + num2
    captchaLabel.config(text=f"What is {num1} + {num2}?")

def submitPassword():
    # Handle submit button click
    password = passwordEntry.get().strip()
    macAddress = getMacAddress()

    if not password:
        messagebox.showerror("Error", "Password field cannot be empty.")
        statusLabel.config(text="Status: Error - Empty Password")
        return
    
    serverIp = discoverServerIp()
    if not serverIp:
        messagebox.showerror("Error", "Could not find WaterBoy LS")
        statusLabel.config(text="Status: Server not found")
        return
    
    data = {"action": "unlock", "mac": macAddress, "password": password} # Prepare request
    response = sendToServer(data, serverIp) # Send request

    # Handle server response
    if response["status"] == "success":
        messagebox.showinfo("Success", "Shared folder unlocked.")
        statusLabel.config(text="Success: Unlocked")
    elif response["status"] == "warning":
        messagebox.showwarning("Warning", response["message"])
        statusLabel.config(text="Status: Warning - Check Attempt")
    elif response["status"] == "locked":
        messagebox.showerror("Locked", "Server is locked. Contact IT/Admin.")
        statusLabel.config(text="Status: Locked")
    else:
        messagebox.showerror("Error", response["message"])
        statusLabel.config(text="Status: Failed")

def logoutAndClose():
    # Send logout request and close GUI
    serverIp = discoverServerIp(timeout=2) # Quick check for server
    if serverIp:
        macAddress = getMacAddress()
        data = {"action": "logout", "mac": macAddress}
        sendToServer(data, serverIp) # Notify server of logout
    root.destroy() # Close GUI

# Set up main GUI window
root = tk.Tk()
root.title("Client Security GUI - WaterBoy LS")
root.geometry("300x250") # Set dimensions
root.resizable(False, False) # Disable resizing

root.attributes('-toolwindow', False) # Enable standard controls
root.protocol("WM_DELETE_WINDOW", logoutAndClose) # Link "X" and shutdown to logout

# CAPTCHA frame (initial screen)
captchaFrame = ttk.Frame(root)
captchaLabel = ttk.Label(captchaFrame, text='')
captchaEntry = ttk.Entry(captchaFrame, width=25)
captchaButton = ttk.Button(captchaFrame, text="Verify", command=verifyCaptcha)
captchaLabel.pack(pady=10)
captchaEntry.pack(pady=10)
captchaFrame.pack() # Show CAPTCHA first
generateCaptcha() # Initialize CAPTCHA

# Login frame (hidden until CAPTCHA solved)
loginFrame = ttk.Frame(root)
macLabel = ttk.Label(loginFrame, text="MAC Address:")
macLabel.pack(pady=10)
macValue = getMacAddress()
macEntry = ttk.Entry(loginFrame, width=25)
macEntry.insert(0, macValue)
macEntry.config(state='disabled') # Read-only MAC
macEntry.pack()
passwordLabel = ttk.Label(loginFrame, text="Enter Password:")
passwordLabel.pack(pady=10)
passwordEntry = ttk.Entry(loginFrame, width=25, show="*") # Masked input
passwordEntry.pack()
submitButton = ttk.Button(loginFrame, text="Submit", command=submitPassword)
submitButton.pack(pady=10)
closeButton = ttk.Button(loginFrame, text="Close", command=logoutAndClose) # Updated to logout
closeButton.pack(pady=10)
statusLabel = ttk.Label(loginFrame, text="Status: Waiting")
statusLabel.pack(pady=5)

root.mainloop() # Start GUI event loop