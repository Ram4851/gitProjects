import socket
import os

# Need to check the file path and size
import struct

# Create a directory to store uploaded files if it doesn't exist
if not os.path.exists("files"):
    os.mkdir("files")

# Set up the server socket
server = socket.socket()
server.bind(("127.0.0.1", 5001))  # Bind to localhost on port 5001
server.listen(1)
print("Server is ready and listening...")

while True:
    # Accept a connection from a client
    client, _ = server.accept()

    # Receive the initial command (UPLOAD or DOWNLOAD)
    command = client.recv(1024).decode()

    if command.startswith("UPLOAD"):
        # Extract the file name
        filename = command.split()[1]

        # Receive the file size (4 bytes, unsigned int)
        filesize = struct.unpack("!I", client.recv(4))[0]

        # Receive the file content and save it
        with open("files/" + filename, "wb") as f:
            received = 0
            while received < filesize:
                data = client.recv(min(1024, filesize - received))
                if not data:
                    break
                f.write(data)
                received += len(data)
        print("Received file:", filename)

    elif command.startswith("DOWNLOAD"):
        filename = command.split()[1]
        filepath = "files/" + filename

        if os.path.exists(filepath):
            filesize = os.path.getsize(filepath)
            client.send(b"OK")  # Let the client know the file exists
            client.send(struct.pack("!I", filesize))  # Send the file size
            with open(filepath, "rb") as f:
                client.sendfile(f)  # Send the actual file
            print("Sent file:", filename)
        else:
            client.send(b"NOTFOUND")  # Let the client know the file was not found

    # Close the connection after the command is handled
    client.close()
