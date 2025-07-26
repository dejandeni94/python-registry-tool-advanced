# === Standard & Windows-specific imports ===
import platform        # To get OS and architecture info
import getpass         # For getting the current user
import ctypes          # For checking admin rights and calling Windows API
import subprocess      # To execute system commands (like reg export)
import winreg          # For accessing the Windows registry
import threading       # For running tasks in the background
import json            # For saving registry data to JSON
import os
import sys
import tkinter as tk   # GUI toolkit
from tkinter import ttk, filedialog, messagebox  # GUI widgets & dialogs

# === Constants for Registry Root Keys and Value Types ===

# Mapping of registry root key names to their handles
ROOT_KEYS = {
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
}

# Mapping registry data types to string names
REG_TYPE_MAP = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"
}

# === Utility Functions ===

def is_admin():
    """Check if the script is running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch the script with admin rights if not already running as admin."""
    if is_admin():
        messagebox.showinfo("Already Admin", "The app is already running with administrator privileges.")
        return
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Elevation Failed", str(e))

# === Core Registry Export Logic ===

def export_registry_tree(root_key, sub_key='', progress_callback=None):
    """
    Recursively exports a registry tree as a dictionary.
    Supports a callback to update progress during traversal.
    """
    result = {}
    try:
        with winreg.OpenKey(root_key, sub_key or "", 0, winreg.KEY_READ) as key:
            # Export values at the current key
            values = {}
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    reg_type_str = REG_TYPE_MAP.get(reg_type, f"UNKNOWN_{reg_type}")
                    if isinstance(value, bytes):
                        value = value.hex()
                    values[name] = {"value": value, "type": reg_type_str}
                    i += 1
                except OSError:
                    break
            if values:
                result['__values__'] = values

            # Recurse into subkeys
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    full_subkey_path = f"{sub_key}\\{subkey_name}" if sub_key else subkey_name
                    if progress_callback:
                        progress_callback(full_subkey_path)
                    result[subkey_name] = export_registry_tree(root_key, full_subkey_path, progress_callback)
                    i += 1
                except OSError:
                    break
    except PermissionError:
        result['__error__'] = 'Permission denied'
    except FileNotFoundError:
        result['__error__'] = 'Not found'
    return result

def monitor_registry(root_key, sub_key, callback):
    """
    Monitor a registry key for changes using Windows API.
    Calls `callback` when a change is detected.
    """
    try:
        key = winreg.OpenKey(root_key, sub_key or "", 0, winreg.KEY_READ)
        reg_notify = ctypes.windll.advapi32.RegNotifyChangeKeyValue
        while True:
            reg_notify(
                key.handle,
                True,
                0x1 | 0x2 | 0x4 | 0x8,  # Notify on name, attributes, last set, and security
                None,
                False
            )
            callback()
    except Exception as e:
        callback(f"Monitoring error: {e}")

# === GUI Setup ===

# Create main window
root = tk.Tk()
username = getpass.getuser()
admin_label = " (Admin)" if is_admin() else " (Standard User)"
root.title(f"Advanced Windows Registry Tool - {username}{admin_label}")
root.geometry("1200x800")

# === Layout Panels ===
left = ttk.Frame(root, padding=10)
left.pack(side=tk.LEFT, fill=tk.Y)
right = ttk.Frame(root, padding=10)
right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# === Controls ===

# Root key dropdown
ttk.Label(left, text="Registry Root:").pack()
root_var = tk.StringVar()
root_combo = ttk.Combobox(left, textvariable=root_var, values=list(ROOT_KEYS.keys()), state="readonly")
root_combo.pack(fill=tk.X)

# Subkey dropdown
ttk.Label(left, text="Registry Subkey (optional):").pack(pady=(10, 0))
subkey_var = tk.StringVar()
subkey_combo = ttk.Combobox(left, textvariable=subkey_var, state="readonly")
subkey_combo.pack(fill=tk.X)

# Log display (text area)
log = tk.Text(left, height=10, state="disabled", wrap="word")
log.pack(fill=tk.X, pady=(10, 0))

def append_log(msg):
    """Helper to write messages to the log area."""
    log.config(state="normal")
    log.insert("end", msg + "\n")
    log.see("end")
    log.config(state="disabled")

# Populate subkeys dynamically when root changes
def update_subkeys(event=None):
    root_name = root_var.get()
    if not root_name:
        subkey_combo['values'] = ['-']
        subkey_var.set('-')
        return
    try:
        with winreg.OpenKey(ROOT_KEYS[root_name], "", 0, winreg.KEY_READ) as key:
            subkeys = []
            i = 0
            while True:
                try:
                    sk = winreg.EnumKey(key, i)
                    subkeys.append(sk)
                    i += 1
                except OSError:
                    break
            subkey_combo['values'] = ['-'] + subkeys
            subkey_var.set('-')
    except Exception as e:
        messagebox.showerror("Subkey Error", str(e))

root_combo.bind("<<ComboboxSelected>>", update_subkeys)

def get_subkey():
    return '' if subkey_var.get() == '-' else subkey_var.get()

# Export selected registry key to JSON
def do_export():
    r = root_var.get()
    if not r:
        messagebox.showwarning("Missing Root", "Please select a registry root.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
    if not path:
        return
    subkey = get_subkey()
    export_btn.config(state="disabled")

    def threaded_export():
        append_log(f"🔄 Exporting {r}\\{subkey or ''}")
        data = export_registry_tree(ROOT_KEYS[r], subkey, progress_callback=lambda p: append_log(f"Reading: {p}"))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        append_log(f"✅ Export complete: {path}")
        export_btn.config(state="normal")
        current_json_file[0] = path
        show_json(path)

    threading.Thread(target=threaded_export, daemon=True).start()

# Start monitoring a key for changes
def start_monitor():
    r = root_var.get()
    if not r:
        messagebox.showwarning("Missing Root", "Please select a registry root.")
        return
    subkey = get_subkey()

    def notify_change(_=None):
        append_log(f"🔔 Change detected in {r}\\{subkey or ''}")

    append_log(f"👀 Monitoring {r}\\{subkey or ''} for changes...")
    threading.Thread(target=monitor_registry, args=(ROOT_KEYS[r], subkey, notify_change), daemon=True).start()

# Track current JSON file for refresh
current_json_file = [None]

# Treeview for displaying exported JSON
tree = ttk.Treeview(right, columns=("value",), show="tree headings")
tree.heading("#0", text="Key/Subkey")
tree.heading("value", text="Value")
tree.pack(fill=tk.BOTH, expand=True)

# Load and show JSON file into treeview
def show_json(filepath):
    tree.delete(*tree.get_children())
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        messagebox.showerror("Invalid JSON", str(e))
        return

    def _recurse(node, blob):
        if isinstance(blob, dict):
            for k, v in blob.items():
                if isinstance(v, dict) and '__values__' not in v and '__error__' not in v:
                    nd = tree.insert(node, "end", text=k, values=("",))
                    _recurse(nd, v)
                elif isinstance(v, dict):
                    if '__values__' in v:
                        val_str = ", ".join(f"{name}: {info['value']}" for name, info in v['__values__'].items())
                        tree.insert(node, "end", text=k, values=(val_str,))
                    elif '__error__' in v:
                        tree.insert(node, "end", text=k, values=(f"Error: {v['__error__']}",))
                    else:
                        tree.insert(node, "end", text=k, values=("",))
                else:
                    tree.insert(node, "end", text=k, values=(str(v),))
        else:
            tree.insert(node, "end", text="Value", values=(str(blob),))

    _recurse("", data)

# Load a saved JSON file
def load_json():
    file = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
    if not file:
        return
    current_json_file[0] = file
    show_json(file)

# Reload the current JSON file
def refresh_json():
    if current_json_file[0]:
        show_json(current_json_file[0])
        append_log(f"🔄 Refreshed {os.path.basename(current_json_file[0])}")
    else:
        messagebox.showinfo("No JSON Loaded", "Load a JSON file first.")

# Full registry backup using .reg export
def full_backup():
    save_dir = filedialog.askdirectory(title="Select Folder to Save Registry Backup")
    if not save_dir:
        return

    export_btn.config(state="disabled")
    append_log("🧪 Starting full registry backup...")

    def threaded_backup():
        for name, hive in ROOT_KEYS.items():
            filename = os.path.join(save_dir, f"{name}.reg")
            try:
                subprocess.run(
                    ["reg", "export", name, filename, "/y"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                append_log(f"✅ Exported {name} to {filename}")
            except subprocess.CalledProcessError as e:
                append_log(f"❌ Failed to export {name}: {e.stderr.strip()}")

        export_btn.config(state="normal")
        append_log("🎉 Full backup complete.")

    threading.Thread(target=threaded_backup, daemon=True).start()

# === Button Controls ===
export_btn = ttk.Button(left, text="Export Registry to JSON", command=do_export)
export_btn.pack(fill=tk.X, pady=5)

monitor_btn = ttk.Button(left, text="Start Monitoring", command=start_monitor)
monitor_btn.pack(fill=tk.X, pady=5)

load_btn = ttk.Button(left, text="Load JSON File", command=load_json)
load_btn.pack(fill=tk.X, pady=5)

refresh_btn = ttk.Button(left, text="🔄 Refresh JSON Viewer", command=refresh_json)
refresh_btn.pack(fill=tk.X, pady=5)

full_backup_btn  = ttk.Button(left, text="🗂 Full Registry Backup (.reg)", command=full_backup)
full_backup_btn.pack(fill=tk.X, pady=5)

admin_btn = ttk.Button(left, text="🔐 Relaunch as Admin", command=run_as_admin)
admin_btn.pack(fill=tk.X, pady=5)

subkey_combo['values'] = ['-']
subkey_var.set('-')

# === System Info Display ===

def get_sid():
    """Retrieve the current user's SID."""
    try:
        username = getpass.getuser()
        output = subprocess.check_output(f"wmic useraccount where name='{username}' get sid", shell=True).decode()
        lines = output.strip().splitlines()
        return lines[1].strip() if len(lines) > 1 else "N/A"
    except:
        return "N/A"

def get_windows_info():
    """Collect basic system information."""
    return {
        "Username": getpass.getuser(),
        "Is Admin": "Yes" if is_admin() else "No",
        "SID": get_sid(),
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.architecture()[0],
        "Machine": platform.machine()
    }

# Display system info
info_frame = ttk.LabelFrame(left, text="System Info", padding=10)
info_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 5))

info_text = tk.Text(info_frame, height=8, wrap="word", state="normal")
info_text.pack(fill=tk.BOTH, expand=True)

def populate_info():
    """Fill the system info panel."""
    info = get_windows_info()
    info_text.config(state="normal")
    info_text.delete(1.0, tk.END)
    for k, v in info.items():
        if k == "Is Admin":
            v += " ✅" if v == "Yes" else " ❌"
        info_text.insert(tk.END, f"{k}: {v}\n")
    info_text.config(state="disabled")

populate_info()

# Start the main GUI loop
root.mainloop()
