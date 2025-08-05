import os
import requests
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# The folder to monitor for new files. Change this path as needed.
FOLDER_TO_WATCH = "C:\\Users\\elara\\Downloads"

# --- API Configuration ---
API_KEY = "ced633a1466e43fb91f5fde8e1990b0c51c2db59c89c815397a54d462049afce"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- File Event Handler ---
class MyHandler(FileSystemEventHandler):
    """
    Handles file system events.
    """
    def on_created(self, event):
        """
        Triggered when a new file or directory is created.
        We only want to process new files, not directories.
        """
        if not event.is_directory:
            path = event.src_path
            print(f"New file detected: {path}")
            # Most importantly, we wait a bit to ensure the file is fully written before analyzing. either way, it would result in an error.
            time.sleep(3)  # Wait a bit to ensure the file is fully written
            analyze_path(path)

# --- VirusTotal API Functions ---
def upload_file_to_virustotal(filepath):
    """
    Sends the file to VirusTotal and returns an analysis ID to check results later.
    """
    url = f"{VT_BASE_URL}/files"
    headers = {"x-apikey": API_KEY}
    
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            response = requests.post(url, headers=headers, files=files)
    except Exception as e:
        output_box.insert(tk.END, f"Failed to open {filepath}: {e}\n")
        output_box.see(tk.END)
        return None

    if response.status_code == 200:
        data = response.json()
        analysis_id = data["data"]["id"]
        output_box.insert(tk.END, f"Uploaded: {filepath}\n")
        output_box.see(tk.END)
        return analysis_id
    else:
        output_box.insert(tk.END, f"Upload failed for {filepath}: {response.status_code}\n")
        output_box.see(tk.END)
        return None

def get_analysis_report(analysis_id):
    """
    Keeps checking the report status until it's ready, then shows the result.
    """
    url = f"{VT_BASE_URL}/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                output_box.insert(tk.END, f"  Malicious:   {stats['malicious']}\n")
                output_box.insert(tk.END, f"  Suspicious: {stats['suspicious']}\n")
                output_box.insert(tk.END, f"  Harmless:    {stats['harmless']}\n\n")
                output_box.see(tk.END)
                break
            else:
                # Still waiting — scan isn't finished yet
                output_box.insert(tk.END, "  Analysis in progress... waiting 10s\n")
                output_box.see(tk.END)
                root.update()
                time.sleep(10)
        else:
            output_box.insert(tk.END, f"Error getting analysis: {response.status_code}\n")
            output_box.see(tk.END)
            break

# --- Analyze Path (File or Folder) ---
def analyze_path(path):
    """
    Checks if path is a file or folder and analyzes accordingly.
    """
    if os.path.isfile(path):
        analyze_single_file(path)
    elif os.path.isdir(path):
        analyze_folder(path)
    else:
        output_box.insert(tk.END, "Path doesn't exist.\n")
        output_box.see(tk.END)

def analyze_single_file(filepath):
    """
    Uploads one file and shows the result.
    """
    output_box.insert(tk.END, f"\nAnalyzing file: {filepath}\n")
    output_box.see(tk.END)
    analysis_id = upload_file_to_virustotal(filepath)
    if analysis_id:
        get_analysis_report(analysis_id)

def analyze_folder(folderpath):
    """
    Walks through the folder and scans all files inside.
    """
    output_box.insert(tk.END, f"\nScanning folder: {folderpath}\n")
    output_box.see(tk.END)
    # os.walk() iterates through all subdirectories and files
    for root_dir, _, files in os.walk(folderpath):
        for file in files:
            file_path = os.path.join(root_dir, file)
            analyze_single_file(file_path)

# --- File/Folder Selection ---
def select_file():
    """
    Opens file picker and analyzes selected file.
    """
    filepath = filedialog.askopenfilename()
    if filepath:
        analyze_path(filepath)

def select_folder():
    """
    Opens folder picker and analyzes everything inside.
    """
    folderpath = filedialog.askdirectory()
    if folderpath:
        analyze_path(folderpath)

# --- Build the GUI ---
def setup_gui():
    """
    Creates the app window, buttons, and output display.
    """
    global root, output_box

    root = tk.Tk()
    root.title("VirusTotal Scanner")
    root.geometry("600x400")

    # Button to scan one file
    tk.Button(root, text="Scan File", command=select_file).pack(pady=5)

    # Button to scan all files in a folder
    tk.Button(root, text="Scan Folder", command=select_folder).pack(pady=5)

    # Output box for showing results
    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
    output_box.pack(pady=10)

# --- Run the App ---
def main():
    """
    Main function to set up the GUI and start the file system observer.
    """
    setup_gui()

    observer = Observer()
    event_handler = MyHandler()
    observer.schedule(event_handler, FOLDER_TO_WATCH, recursive=False)
    observer.start()

    # Log to the GUI instead of the console
    output_box.insert(tk.END, f"Watching folder: {FOLDER_TO_WATCH}...\n")
    output_box.see(tk.END)

    try:
        # Start the GUI's main loop, which also keeps the program running.
        # This replaces the need for a manual 'while True' loop.
        root.mainloop()
    finally:
        # Stop the observer gracefully when the program exits.
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main()
