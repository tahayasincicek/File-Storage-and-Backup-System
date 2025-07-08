import customtkinter as ctk
from tkinter import messagebox, simpledialog
from tkinter import filedialog
from hashlib import sha256
import os
import json
from datetime import datetime
import shutil
import threading
import time
import tkinter as tk
import log_analyzer


from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logger import log_event  # logger modülünü içe aktar
# File to store user data
data_file = "user_data.json"
files_directory = "uploaded_files"
backup_directory = "backup_files"
log_file = "system_logs.txt"
log_directory = "logs"

# Ensure necessary directories exist
os.makedirs(files_directory, exist_ok=True)
os.makedirs(backup_directory, exist_ok=True)

# Load existing data or initialize
if os.path.exists(data_file):
    with open(data_file, "r") as f:
        user_data = json.load(f)
else:
    user_data = {}

def save_data():
    with open(data_file, "w") as f:
        json.dump(user_data, f)

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def analyze_logs_in_project():
    anomalies = log_analyzer.analyze_all_logs()  # Logları analiz et
    log_analyzer.report_anomalies(anomalies, user_data)  # Anomalileri raporla
    log_analyzer.notify_anomaly(user_data, anomalies)  # Bildirimleri gönder

def start_log_analysis():
    while True:
        analyze_logs_in_project()
        time.sleep(1000)  # Her saat başı logları analiz et

# Proje başlangıcında başlatmak için:
threading.Thread(target=start_log_analysis, daemon=True).start()    


def backup_files():
    try:
        total_size = 0
        for root, _, files in os.walk(files_directory):
            for file in files:
                source_path = os.path.join(root, file)
                rel_path = os.path.relpath(source_path, files_directory)
                backup_path = os.path.join(backup_directory, rel_path)

                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                shutil.copy2(source_path, backup_path)
                total_size += os.path.getsize(source_path)

        log_event(
            category="Backup", 
            operation_code="AUTO_SYNC", 
            status_code="SUCCESS", 
            source_dir=files_directory, 
            backup_size=total_size
        )
        messagebox.showinfo("Backup", "Backup and synchronization completed successfully.")
    except Exception as e:
        log_event(
            category="Backup", 
            operation_code="AUTO_SYNC", 
            status_code=f"ERROR: {str(e)}"
        )
        messagebox.showerror("Backup", "An error occurred during backup.")

# Continuous backup using a separate thread
def start_continuous_backup():
    threading.Thread(target=continuous_backup, daemon=True).start()

def continuous_backup():
    while True:
        backup_files()
        time.sleep(1000)  # 1 saat aralıklarla yedekleme

# Directory change monitoring class
class DirectoryChangeHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return
        log_event(
            category="File Change", 
            operation_code="FILE_MODIFIED", 
            status_code=f"Path: {event.src_path}, Event: {event.event_type}"
        )
        backup_files()

def start_directory_monitoring():
    event_handler = DirectoryChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=files_directory, recursive=True)
    observer.start()
    threading.Thread(target=observer.join, daemon=True).start()

# Main application class
class UserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("User Management System")
        self.root.geometry("400x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.logged_in_user = None

        # Login frame
        self.login_frame = ctk.CTkFrame(root, corner_radius=10)
        self.login_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(self.login_frame, text="Username:", font=('Arial', 12)).grid(row=0, column=0, pady=10, sticky="w")
        self.username_entry = ctk.CTkEntry(self.login_frame)
        self.username_entry.grid(row=0, column=1, pady=10, sticky="ew")

        ctk.CTkLabel(self.login_frame, text="Password:", font=('Arial', 12)).grid(row=1, column=0, pady=10, sticky="w")
        self.password_entry = ctk.CTkEntry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=10, sticky="ew")

        login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login)
        login_button.grid(row=2, column=0, pady=10, padx=10, sticky="ew")
        register_button = ctk.CTkButton(self.login_frame, text="Register", command=self.register)
        register_button.grid(row=2, column=1, pady=10, padx=10, sticky="ew")

        # User actions frame
        self.user_frame = ctk.CTkFrame(root, corner_radius=10)

        # Progress bar for backup
        self.progress_frame = ctk.CTkFrame(root, corner_radius=10)
        self.progress_frame.pack(pady=20, padx=20, fill="none", expand=False)  # fill yerine "none" kullanıyoruz
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="Backup Progress", font=('Arial', 12))
        self.progress_label.pack(pady=5)
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(pady=5, padx=10, fill="x")
        self.progress_bar.set(0)  # Initialize progress bar

        self.start_backup_button = ctk.CTkButton(self.root, text="Start Backup", command=self.start_backup_thread)
        self.start_backup_button.pack(pady=10)

    def start_backup_thread(self):
        """Backup işlemini başlatmak için yeni bir thread oluşturur."""
        threading.Thread(target=self.backup_files, daemon=True).start()

    def backup_files(self):
        """Yedekleme işlemini gerçekleştirir."""
        try:
            files = []
            # Yedeklenecek dosyaları toplama
            for root, _, filenames in os.walk(files_directory):
                for filename in filenames:
                    files.append(os.path.join(root, filename))

            total_files = len(files)
            if total_files == 0:
                messagebox.showinfo("Backup", "No files to backup.")
                return

            # Yedekleme işlemi sırasında ilerleme çubuğunun güncellenmesi
            def update_progress(i):
                progress = i / total_files
                self.progress_bar.set(progress)  # İlerleme çubuğunu güncelle
                self.root.after(10, self.root.update_idletasks)  # GUI'nin güncellenmesini sağla

            # Yedekleme işlemi
            total_size = 0
            for i, file_path in enumerate(files, start=1):
                rel_path = os.path.relpath(file_path, files_directory)
                backup_path = os.path.join(backup_directory, rel_path)

                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                shutil.copy2(file_path, backup_path)

                # Dosya boyutunu toplam boyuta ekleyelim
                total_size += os.path.getsize(file_path)

                # İlerleme çubuğunu güncelle
                update_progress(i)

                # Her dosya kopyalandığında yavaşlatmak için gecikme ekle
                time.sleep(0.1)  # Bu değeri değiştirerek yavaşlatılabilir

            # Yedekleme başarılı olduğunda loglama yapılır
            log_event(
                category="Backup",
                operation_code="AUTO_SYNC",
                status_code="SUCCESS",
                source_dir=files_directory,
                backup_size=total_size
            )

            messagebox.showinfo("Backup", "Backup completed successfully.")
        except Exception as e:
            # Hata durumunda loglama yapılır
            log_event(
                category="Backup",
                operation_code="AUTO_SYNC",
                status_code=f"ERROR: {str(e)}"
            )
            messagebox.showerror("Backup", f"An error occurred during backup: {str(e)}")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        if username in user_data and user_data[username]["password"] == hash_password(password):
            self.logged_in_user = username
            role = user_data[username]["role"]

            if user_data[username].get("password_request"):
                new_password = simpledialog.askstring("New Password", "Please change your password:")
                if new_password and len(new_password) >= 6:
                    user_data[username]["password"] = hash_password(new_password)
                    user_data[username]["password_request"] = False
                    save_data()
                    messagebox.showinfo("Success", "Password changed successfully.")
                else:
                    messagebox.showerror("Error", "Password must be at least 6 characters long.")
                    return

            messagebox.showinfo("Login", f"Welcome, {username}! Role: {role}")
            self.show_user_actions()
        else:
            messagebox.showerror("Error", "Invalid username or password.")
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = simpledialog.askstring("Role Selection", "Enter role (individual/admin):").lower()

        if role not in ["individual", "admin"]:
            messagebox.showerror("Error", "Invalid role. Please choose 'individual' or 'admin'.")
            log_event(
                category="Profile Access",
                operation_code="REGISTER",
                status_code="FAILED: Invalid role",
                username=username
            )
            return

        if username in user_data:
            messagebox.showerror("Error", "Username already taken.")
            log_event(
                category="Profile Access",
                operation_code="REGISTER",
                status_code="FAILED: Username already taken",
                username=username
            )
        elif len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            log_event(
                category="Profile Access",
                operation_code="REGISTER",
                status_code="FAILED: Password too short",
                username=username
            )
        else:
            user_data[username] = {
                "password": hash_password(password),
                "role": role,
                "team_members": [],
                "notifications": [],
                "files": [],
                "shared_files": [],
                "storage_limit": 100,
                "password_request": False
            }
            save_data()
            messagebox.showinfo("Success", "Registration successful.")
            log_event(
                category="Profile Access",
                operation_code="REGISTER",
                status_code="SUCCESS",
                username=username
            )



    def show_user_actions(self):
        for widget in self.user_frame.winfo_children():
            widget.destroy()

        role = user_data[self.logged_in_user]["role"]
        ctk.CTkLabel(self.user_frame, text=f"Logged in as: {self.logged_in_user} ({role})", font=('Arial', 14)).pack(pady=10)

        actions_frame = ctk.CTkFrame(self.user_frame)
        actions_frame.pack(pady=20)

        if role == "individual":
            ctk.CTkButton(actions_frame, text="Change Username", command=self.change_username, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Request Password Change", command=self.request_password_change, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Add Team Member", command=self.add_team_member, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Upload File", command=self.upload_file, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="View Uploaded Files", command=self.view_uploaded_files, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Share File", command=self.share_file, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="View Notifications", command=self.view_notifications, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="View Shared Files", command=self.view_shared_files, width=200).pack(pady=5)
        elif role == "admin":
            ctk.CTkButton(actions_frame, text="Manage User Profiles", command=self.manage_profiles, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Set Storage Limits", command=self.set_storage_limits, width=200).pack(pady=5)
            ctk.CTkButton(actions_frame, text="Approve Password Change Requests", command=self.approve_password_requests, width=200).pack(pady=5)

        ctk.CTkButton(actions_frame, text="Logout", command=self.logout, width=200).pack(pady=5)

        self.login_frame.pack_forget()
        self.user_frame.pack(fill="both", expand=True)

    def change_username(self):
        new_username = simpledialog.askstring("Change Username", "Enter new username:")

        if new_username in user_data:
            messagebox.showerror("Error", "Username already taken.")
            log_event(
                category="User Action",
                operation_code="CHANGE_USERNAME",
                status_code="FAILED: Username already taken",
                username=self.logged_in_user
            )
        elif new_username:
            user_data[new_username] = user_data.pop(self.logged_in_user)
            self.logged_in_user = new_username
            save_data()
            messagebox.showinfo("Success", "Username changed successfully.")
            log_event(
                category="User Action",
                operation_code="CHANGE_USERNAME",
                status_code="SUCCESS",
                username=new_username
            )

    def request_password_change(self):
        user_data[self.logged_in_user]["password_request"] = True
        save_data()
        messagebox.showinfo("Request Sent", "Password change request sent to the system administrator.")
        log_event(
            category="User Action",
            operation_code="REQUEST_PASSWORD_CHANGE",
            status_code="SUCCESS",
            username=self.logged_in_user
        )

    def add_team_member(self):
        team_member = simpledialog.askstring("Add Team Member", "Enter team member's username:")

        if team_member in user_data and team_member != self.logged_in_user:
            user_data[self.logged_in_user]["team_members"].append(team_member)
            user_data[team_member]["team_members"].append(self.logged_in_user)
            user_data[team_member]["notifications"].append(f"{self.logged_in_user} added you as a team member.")
            save_data()
            messagebox.showinfo("Success", "Team member added successfully.")
            log_event(
                category="Team Management",
                operation_code="ADD_TEAM_MEMBER",
                status_code="SUCCESS",
                username=self.logged_in_user,
                details=f"Added team member: {team_member}"
            )
        else:
            messagebox.showerror("Error", "Invalid username.")
            log_event(
                category="Team Management",
                operation_code="ADD_TEAM_MEMBER",
                status_code="FAILED: Invalid username",
                username=self.logged_in_user
            )
    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(files_directory, file_name)

            if os.path.exists(dest_path):
                messagebox.showerror("Error", "File already exists.")
                log_event(
                    category="File Management",
                    operation_code="UPLOAD_FILE",
                    status_code="FAILED: File already exists",
                    username=self.logged_in_user
                )
                return

            file_size = os.path.getsize(file_path) / (1024 * 1024)
            total_size = sum(
                os.path.getsize(os.path.join(files_directory, f)) / (1024 * 1024)
                for f in user_data[self.logged_in_user]["files"]
                if os.path.exists(os.path.join(files_directory, f))
            )

            storage_limit = user_data[self.logged_in_user].get("storage_limit", 100)
            if total_size + file_size > storage_limit:
                messagebox.showerror(
                    "Storage Limit Exceeded",
                    f"Cannot upload file. Storage limit of {storage_limit}MB exceeded."
                )
                log_event(
                    category="File Management",
                    operation_code="UPLOAD_FILE",
                    status_code="FAILED: Storage limit exceeded",
                    username=self.logged_in_user,
                    #details=f"File size: {file_size}MB, Total used: {total_size}MB, Limit: {storage_limit}MB"
                )
                return

            with open(file_path, "rb") as src_file:
                with open(dest_path, "wb") as dest_file:
                    dest_file.write(src_file.read())

            user_data[self.logged_in_user]["files"].append(file_name)
            save_data()
            messagebox.showinfo("Success", "File uploaded successfully.")
            log_event(
                category="File Management",
                operation_code="UPLOAD_FILE",
                status_code="SUCCESS",
                username=self.logged_in_user,
                #details=f"Uploaded file: {file_name}, Size: {file_size}MB"
            )

    def view_uploaded_files(self):
        files = user_data[self.logged_in_user]["files"]
        if not files:
            messagebox.showinfo("Files", "No files uploaded.")
            return

        files_list = "\n".join(files)
        file_to_edit = simpledialog.askstring("Edit File", f"Your files:\n{files_list}\n\nEnter file name to edit:")

        if file_to_edit in files:
            action = simpledialog.askstring("Edit File", f"Choose an action for {file_to_edit} (edit/delete):")

            if action.lower() == "edit":
                new_name = simpledialog.askstring("Edit File Name", "Enter new file name:")
                if new_name:
                    # Rename the file
                    old_path = os.path.join(files_directory, file_to_edit)
                    new_path = os.path.join(files_directory, new_name)

                    if os.path.exists(new_path):
                        messagebox.showerror("Error", "File with that name already exists.")
                    else:
                        os.rename(old_path, new_path)
                        user_data[self.logged_in_user]["files"].remove(file_to_edit)
                        user_data[self.logged_in_user]["files"].append(new_name)
                        save_data()
                        messagebox.showinfo("Success", f"File '{file_to_edit}' renamed to '{new_name}'.")
            elif action.lower() == "delete":
                confirmation = messagebox.askyesno("Delete File", f"Are you sure you want to delete {file_to_edit}?")
                if confirmation:
                    file_path = os.path.join(files_directory, file_to_edit)
                    os.remove(file_path)
                    user_data[self.logged_in_user]["files"].remove(file_to_edit)
                    save_data()
                    messagebox.showinfo("Success", f"File '{file_to_edit}' deleted.")
        else:
            messagebox.showerror("Error", "File not found.")

    def share_file(self):
        if not user_data[self.logged_in_user]["files"]:
            messagebox.showerror("Error", "You have no files to share.")
            log_event(
                category="File Management",
                operation_code="SHARE_FILE",
                status_code="FAILED: No files to share",
                username=self.logged_in_user
            )
            return

        file_to_share = simpledialog.askstring(
            "Share File", "Enter the name of the file you want to share:"
        )

        if file_to_share not in user_data[self.logged_in_user]["files"]:
            messagebox.showerror("Error", "File not found in your uploads.")
            log_event(
                category="File Management",
                operation_code="SHARE_FILE",
                status_code="FAILED: File not found",
                username=self.logged_in_user,
            )
            return

        recipient = simpledialog.askstring(
            "Share File", "Enter the username of the recipient:"
        )

        if recipient not in user_data or recipient == self.logged_in_user:
            messagebox.showerror("Error", "Invalid recipient username.")
            log_event(
                category="File Management",
                operation_code="SHARE_FILE",
                status_code="FAILED: Invalid recipient",
                username=self.logged_in_user,
            )
            return

        # Check if the recipient is a team member
        if recipient not in user_data[self.logged_in_user]["team_members"]:
            messagebox.showerror(
                "Error", "You can only share files with your team members."
            )
            log_event(
                category="File Management",
                operation_code="SHARE_FILE",
                status_code="FAILED: Recipient not a team member",
                username=self.logged_in_user,
            )
            return

        # Check if the file has already been shared with the recipient
        shared_files = user_data[self.logged_in_user].get("shared_files_history", {})
        if file_to_share in shared_files and recipient in shared_files[file_to_share]:
            messagebox.showerror("Error", f"File '{file_to_share}' has already been shared with {recipient}.")
            log_event(
                category="File Management",
                operation_code="SHARE_FILE",
                status_code="FAILED: Duplicate share attempt",
                username=self.logged_in_user,
            )
            return

        # Update shared files history
        if file_to_share not in shared_files:
            shared_files[file_to_share] = []
        shared_files[file_to_share].append(recipient)
        user_data[self.logged_in_user]["shared_files_history"] = shared_files

        # Add file to recipient's shared files list
        if "shared_files" not in user_data[recipient]:
            user_data[recipient]["shared_files"] = []

        user_data[recipient]["shared_files"].append(
            {"file_name": file_to_share, "shared_by": self.logged_in_user}
        )

        # Ensure the recipient also gets the file in their own files list
        if file_to_share not in user_data[recipient]["files"]:
            user_data[recipient]["files"].append(file_to_share)

        user_data[recipient]["notifications"].append(
            f"{self.logged_in_user} shared a file with you: {file_to_share}"
        )

        # Send notification to the sender as well
        user_data[self.logged_in_user]["notifications"].append(
            f"You shared the file '{file_to_share}' with {recipient}."
        )

        save_data()
        messagebox.showinfo(
            "Success", f"File '{file_to_share}' shared with {recipient}."
        )
        log_event(
            category="File Management",
            operation_code="SHARE_FILE",
            status_code="SUCCESS",
            username=self.logged_in_user,
        )

    def view_notifications(self):
        notifications = user_data[self.logged_in_user]["notifications"]
        if notifications:
            messagebox.showinfo("Notifications", "\n".join(notifications))
            user_data[self.logged_in_user]["notifications"] = []
            save_data()
        else:
            messagebox.showinfo("Notifications", "No new notifications.")

    def view_shared_files(self):
        if not user_data[self.logged_in_user]["shared_files"]:
            messagebox.showinfo("Shared Files", "No files have been shared with you.")
            return

        shared_files = user_data[self.logged_in_user]["shared_files"]
        files_list = "\n".join(
            [f"{f['file_name']} (Shared by: {f['shared_by']})" for f in shared_files]
        )
        messagebox.showinfo("Shared Files", f"Files shared with you:\n\n{files_list}")

    def logout(self):
        if self.logged_in_user:
            log_event(
                category="Profile Access",
                operation_code="LOGOUT",
                status_code="SUCCESS",
                username=self.logged_in_user
            )
        else:
            log_event(
                category="Profile Access",
                operation_code="LOGOUT",
                status_code="FAILED: No user logged in"
            )
        
        self.logged_in_user = None
        self.user_frame.pack_forget()
        self.login_frame.pack()
        



    def manage_profiles(self):
        manage_window = tk.Toplevel(self.root)
        manage_window.title("Manage User Profiles")
        manage_window.geometry("500x400")

        tk.Label(manage_window, text="User Profiles", font=('Arial', 14)).pack(pady=10)

        user_list_frame = tk.Frame(manage_window)
        user_list_frame.pack(pady=10)

        user_listbox = tk.Listbox(user_list_frame, width=40, height=15)
        user_listbox.pack(side="left", fill="y")

        scrollbar = tk.Scrollbar(user_list_frame, orient="vertical")
        scrollbar.config(command=user_listbox.yview)
        scrollbar.pack(side="right", fill="y")

        user_listbox.config(yscrollcommand=scrollbar.set)

        for username in user_data.keys():
            user_listbox.insert(tk.END, username)

        def view_profile():
            selected_user = user_listbox.get(tk.ACTIVE)
            if not selected_user:
                messagebox.showerror("Error", "No user selected.")
                # Log: Kullanıcı seçilmedi
                log_event(
                    category="User Management",
                    operation_code="VIEW_PROFILE",
                    status_code="FAILED: No user selected",
                    username=self.logged_in_user,  # Aktif kullanıcı
                )
                return

            user_profile = user_data[selected_user]
            profile_window = tk.Toplevel(self.root)
            profile_window.title(f"Profile: {selected_user}")
            profile_window.geometry("400x300")

            tk.Label(profile_window, text=f"Username: {selected_user}", font=('Arial', 12)).pack(pady=5)
            tk.Label(profile_window, text=f"Role: {user_profile['role']}", font=('Arial', 12)).pack(pady=5)
            tk.Label(profile_window, text=f"Team Members: {', '.join(user_profile['team_members'])}", font=('Arial', 12)).pack(pady=5)

            tk.Label(profile_window, text="Files:", font=('Arial', 12, 'bold')).pack(pady=5)
            files_frame = tk.Frame(profile_window)
            files_frame.pack(pady=5)

            files_listbox = tk.Listbox(files_frame, width=40, height=5)
            files_listbox.pack(side="left", fill="y")

            for file_name in user_profile.get("files", []):
                files_listbox.insert(tk.END, file_name)

            scrollbar_files = tk.Scrollbar(files_frame, orient="vertical")
            scrollbar_files.config(command=files_listbox.yview)
            scrollbar_files.pack(side="right", fill="y")

            files_listbox.config(yscrollcommand=scrollbar_files.set)

            # Log: Kullanıcı profili görüntülendi
            log_event(
                category="User Management",
                operation_code="VIEW_PROFILE",
                status_code="SUCCESS",
                username=self.logged_in_user,  # Aktif kullanıcı
                #details=f"Viewed profile of {selected_user}",
            )

        def delete_user():
            selected_user = user_listbox.get(tk.ACTIVE)
            if not selected_user:
                messagebox.showerror("Error", "No user selected.")
                # Log: Kullanıcı seçilmedi
                log_event(
                    category="User Management",
                    operation_code="DELETE_USER",
                    status_code="FAILED: No user selected",
                    username=self.logged_in_user,  # Aktif kullanıcı
                )
                return

            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {selected_user}?")
            if confirm:
                user_data.pop(selected_user, None)
                save_data()
                user_listbox.delete(tk.ACTIVE)
                messagebox.showinfo("Success", "User deleted successfully.")
                # Log: Kullanıcı başarıyla silindi
                log_event(
                    category="User Management",
                    operation_code="DELETE_USER",
                    status_code="SUCCESS",
                    username=self.logged_in_user,  # Aktif kullanıcı
                    #details=f"Deleted user: {selected_user}",
                )
            else:
                # Eğer silme işlemi iptal edilirse, log kaydı yap
                log_event(
                    category="User Management",
                    operation_code="DELETE_USER",
                    status_code="CANCELLED: User deletion cancelled",
                    username=self.logged_in_user,  # Aktif kullanıcı
                    #details=f"Attempted to delete user: {selected_user}",
                )

        tk.Button(manage_window, text="View Profile", command=view_profile, font=('Arial', 12)).pack(pady=5)
        tk.Button(manage_window, text="Delete User", command=delete_user, font=('Arial', 12)).pack(pady=5)


    def set_storage_limits(self):
        storage_window = tk.Toplevel(self.root)
        storage_window.title("Set Storage Limits")
        storage_window.geometry("400x300")

        tk.Label(storage_window, text="Set Storage Limits", font=('Arial', 14)).pack(pady=10)

        user_list_frame = tk.Frame(storage_window)
        user_list_frame.pack(pady=10)

        user_listbox = tk.Listbox(user_list_frame, width=40, height=10)
        user_listbox.pack(side="left", fill="y")

        scrollbar = tk.Scrollbar(user_list_frame, orient="vertical")
        scrollbar.config(command=user_listbox.yview)
        scrollbar.pack(side="right", fill="y")

        user_listbox.config(yscrollcommand=scrollbar.set)

        for username in user_data.keys():
            user_listbox.insert(tk.END, username)

        def set_limit():
            selected_user = user_listbox.get(tk.ACTIVE)
            if not selected_user:
                messagebox.showerror("Error", "No user selected.")
                # Log: Kullanıcı seçilmedi
                log_event(
                    category="User Management",
                    operation_code="SET_STORAGE_LIMIT",
                    status_code="FAILED: No user selected",
                    username=self.logged_in_user,  # Aktif kullanıcı
                )
                return

            limit = simpledialog.askinteger("Set Limit", f"Enter storage limit for {selected_user} (MB):")
            if limit is not None and limit > 0:
                user_data[selected_user]["storage_limit"] = limit
                save_data()
                messagebox.showinfo("Success", "Storage limit updated successfully.")
                # Log: Storage limit başarıyla güncellendi
                log_event(
                    category="User Management",
                    operation_code="SET_STORAGE_LIMIT",
                    status_code="SUCCESS",
                    username=self.logged_in_user,  # Aktif kullanıcı
                    #details=f"Set storage limit for {selected_user} to {limit} MB",
                )
            else:
                # Log: Geçersiz limit veya iptal edilen işlem
                log_event(
                    category="User Management",
                    operation_code="SET_STORAGE_LIMIT",
                    status_code="FAILED: Invalid or cancelled limit",
                    username=self.logged_in_user,  # Aktif kullanıcı
                    #details=f"Failed to set limit for {selected_user}",
                )

        tk.Button(storage_window, text="Set Limit", command=set_limit, font=('Arial', 12)).pack(pady=10)

    def approve_password_requests(self):
     requests_window = tk.Toplevel(self.root)
     requests_window.title("Approve Password Requests")
     requests_window.geometry("400x300")

     tk.Label(requests_window, text="Password Change Requests", font=('Arial', 14)).pack(pady=10)

     requests_list_frame = tk.Frame(requests_window)
     requests_list_frame.pack(pady=10)

     requests_listbox = tk.Listbox(requests_list_frame, width=40, height=10)
     requests_listbox.pack(side="left", fill="y")

     scrollbar = tk.Scrollbar(requests_list_frame, orient="vertical")
     scrollbar.config(command=requests_listbox.yview)
     scrollbar.pack(side="right", fill="y")

     requests_listbox.config(yscrollcommand=scrollbar.set)

     for username, data in user_data.items():
          if data.get("password_request"):
             requests_listbox.insert(tk.END, username)

     def approve_request():
        selected_user = requests_listbox.get(tk.ACTIVE)
        if not selected_user:
            messagebox.showerror("Error", "No user selected.")
            return

        

        

     tk.Button(requests_window, text="Approve Request", command=approve_request, font=('Arial', 12)).pack(pady=10)
if __name__ == "__main__":
    root = ctk.CTk()
        # Start continuous backup
    start_continuous_backup()
    # Start directory monitoring
    start_directory_monitoring()

    app = UserApp(root)
    root.mainloop()


