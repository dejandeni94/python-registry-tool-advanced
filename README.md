# python-registry-tool-advanced
Advanced Windows Registry Tool Python

🧰 Advanced Windows Registry Tool
A full-featured Windows desktop application (built with Python and Tkinter) that allows you to view, export, monitor, and back up parts of the Windows Registry in a human-readable JSON format.

🚀 Features
🔍 Browse and Export Registry

Select any registry root and subkey

Export the full registry tree to a .json file

📊 Visual JSON Tree Viewer

Load and inspect any registry-exported .json file in a tree view

🔔 Registry Change Monitoring

Monitor a selected registry key for changes in real time

💾 Full Registry Backup (.reg)

Export all root hives (e.g., HKEY_LOCAL_MACHINE, HKEY_USERS, etc.) into native .reg files

🔐 Run as Administrator

Relaunch the tool with elevated privileges if needed

🖥 System Information Display

Shows current user info, admin status, SID, OS version, and architecture

📷 GUI Overview
Left Panel:

Select registry root and subkey

Buttons for export, monitor, load, refresh, and backup

Log output and system info

Right Panel:

Tree view for registry content (JSON)

🛠 Requirements
OS: Windows 10/11

Python: 3.8+

Dependencies:

pywin32

Install requirements with:

bash
Copy
Edit
pip install -r requirements.txt
▶️ How to Run
bash
Copy
Edit
python registry_tool.py
To run as administrator (from command line):

bash
Copy
Edit
powershell -Command "Start-Process python 'registry_tool.py' -Verb runAs"
Or click the 🔐 Relaunch as Admin button inside the app.

📂 File Types
.json: Exported registry data in human-readable form

.reg: Full native registry backup files (can be re-imported into Windows Registry Editor)

⚠️ Important Notes
Administrator rights are required to access certain registry hives (like HKEY_LOCAL_MACHINE).

Avoid editing the registry manually unless you know what you're doing—this tool is read/export-only.

📄 License
This project is released under the MIT License.


