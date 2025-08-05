import socket
import os

# Need to check the file path and size
import struct

# Connect to the server on localhost:5001
client = socket.socket()
client.connect(("127.0.0.1", 5001))

# Ask user whether to upload or download
action = input("Enter 'upload' or 'download': ").strip().lower()
filename = input("Enter file name: ").strip()

if action == "upload":
    if not os.path.exists(filename):
        print("File not found on your computer.")
    else:
        filesize = os.path.getsize(filename)

        # Send the UPLOAD command with the file name
        client.send(f"UPLOAD {filename}".encode())

        # Send the file size as 4 bytes
        client.send(struct.pack("!I", filesize))

        # Send the file content
        with open(filename, "rb") as f:
            client.sendfile(f)

        print("File uploaded successfully.")

elif action == "download":
    # Send the DOWNLOAD command with the file name
    client.send(f"DOWNLOAD {filename}".encode())

    # Read the server response
    response = client.recv(2)
    if response == b"OK":
        # Receive the file size
        filesize = struct.unpack("!I", client.recv(4))[0]

        # Receive and write the file
        with open("new_" + filename, "wb") as f:
            received = 0
            while received < filesize:
                data = client.recv(min(1024, filesize - received))
                if not data:
                    break
                f.write(data)
                received += len(data)
        print("File downloaded and saved as new_" + filename)
    else:
        print("File not found on server.")

# Close the connection
client.close()
