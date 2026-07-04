import sqlite3
import json
import os
import threading

db_lock = threading.Lock()

class DatabaseManager:
    def __init__(self, db_path="app_data.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password TEXT,
                            role TEXT,
                            storage_limit INTEGER,
                            password_request INTEGER
                        )''')
            c.execute('''CREATE TABLE IF NOT EXISTS team_members (
                            username TEXT,
                            team_member TEXT,
                            UNIQUE(username, team_member)
                        )''')
            c.execute('''CREATE TABLE IF NOT EXISTS files (
                            username TEXT,
                            file_name TEXT,
                            UNIQUE(username, file_name)
                        )''')
            c.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                            shared_by TEXT,
                            shared_with TEXT,
                            file_name TEXT,
                            UNIQUE(shared_by, shared_with, file_name)
                        )''')
            c.execute('''CREATE TABLE IF NOT EXISTS notifications (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT,
                            message TEXT
                        )''')
            conn.commit()

    def migrate_from_json(self, json_path="user_data.json"):
        if not os.path.exists(json_path):
            return
        
        try:
            with open(json_path, "r") as f:
                user_data = json.load(f)
        except Exception:
            return

        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            for username, data in user_data.items():
                try:
                    c.execute('''INSERT OR IGNORE INTO users 
                                 (username, password, role, storage_limit, password_request) 
                                 VALUES (?, ?, ?, ?, ?)''',
                              (username, data.get("password"), data.get("role", "individual"), 
                               data.get("storage_limit", 100), int(data.get("password_request", False))))
                    
                    for tm in data.get("team_members", []):
                        c.execute('INSERT OR IGNORE INTO team_members (username, team_member) VALUES (?, ?)', (username, tm))
                    
                    for f in data.get("files", []):
                        c.execute('INSERT OR IGNORE INTO files (username, file_name) VALUES (?, ?)', (username, f))
                    
                    for sf in data.get("shared_files", []):
                        c.execute('INSERT OR IGNORE INTO shared_files (shared_by, shared_with, file_name) VALUES (?, ?, ?)',
                                  (sf.get("shared_by"), username, sf.get("file_name")))
                        
                    for notif in data.get("notifications", []):
                        c.execute('INSERT INTO notifications (username, message) VALUES (?, ?)', (username, notif))
                except Exception as e:
                    print(f"Error migrating {username}: {e}")
            conn.commit()
        
        # Rename json file so it won't be migrated again
        try:
            os.rename(json_path, json_path + ".bak")
        except Exception as e:
            print(f"Could not rename json file: {e}")

    # --- User Operations ---
    def get_user(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT username, password, role, storage_limit, password_request FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            if row:
                return {
                    "username": row[0],
                    "password": row[1],
                    "role": row[2],
                    "storage_limit": row[3],
                    "password_request": bool(row[4])
                }
            return None

    def get_all_usernames(self):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM users')
            return [row[0] for row in c.fetchall()]

    def add_user(self, username, password, role="individual", storage_limit=100):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, role, storage_limit, password_request) VALUES (?, ?, ?, ?, 0)',
                      (username, password, role, storage_limit))
            conn.commit()

    def update_username(self, old_username, new_username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET username = ? WHERE username = ?', (new_username, old_username))
            c.execute('UPDATE team_members SET username = ? WHERE username = ?', (new_username, old_username))
            c.execute('UPDATE team_members SET team_member = ? WHERE team_member = ?', (new_username, old_username))
            c.execute('UPDATE files SET username = ? WHERE username = ?', (new_username, old_username))
            c.execute('UPDATE shared_files SET shared_by = ? WHERE shared_by = ?', (new_username, old_username))
            c.execute('UPDATE shared_files SET shared_with = ? WHERE shared_with = ?', (new_username, old_username))
            c.execute('UPDATE notifications SET username = ? WHERE username = ?', (new_username, old_username))
            conn.commit()

    def delete_user(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM users WHERE username = ?', (username,))
            c.execute('DELETE FROM team_members WHERE username = ? OR team_member = ?', (username, username))
            c.execute('DELETE FROM files WHERE username = ?', (username,))
            c.execute('DELETE FROM shared_files WHERE shared_by = ? OR shared_with = ?', (username, username))
            c.execute('DELETE FROM notifications WHERE username = ?', (username,))
            conn.commit()

    def set_password_request(self, username, request_status):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET password_request = ? WHERE username = ?', (int(request_status), username))
            conn.commit()
            
    def get_users_with_password_requests(self):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE password_request = 1')
            return [row[0] for row in c.fetchall()]

    def set_storage_limit(self, username, limit):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET storage_limit = ? WHERE username = ?', (limit, username))
            conn.commit()

    # --- Team Operations ---
    def get_team_members(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT team_member FROM team_members WHERE username = ?', (username,))
            return [row[0] for row in c.fetchall()]

    def add_team_member(self, user1, user2):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT OR IGNORE INTO team_members (username, team_member) VALUES (?, ?)', (user1, user2))
            c.execute('INSERT OR IGNORE INTO team_members (username, team_member) VALUES (?, ?)', (user2, user1))
            conn.commit()

    # --- File Operations ---
    def get_files(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT file_name FROM files WHERE username = ?', (username,))
            return [row[0] for row in c.fetchall()]

    def add_file(self, username, file_name):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT OR IGNORE INTO files (username, file_name) VALUES (?, ?)', (username, file_name))
            conn.commit()

    def remove_file(self, username, file_name):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM files WHERE username = ? AND file_name = ?', (username, file_name))
            conn.commit()

    def rename_file(self, username, old_name, new_name):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('UPDATE files SET file_name = ? WHERE username = ? AND file_name = ?', (new_name, username, old_name))
            c.execute('UPDATE shared_files SET file_name = ? WHERE file_name = ?', (new_name, old_name))
            conn.commit()

    # --- Shared Files Operations ---
    def share_file(self, shared_by, shared_with, file_name):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT OR IGNORE INTO shared_files (shared_by, shared_with, file_name) VALUES (?, ?, ?)',
                      (shared_by, shared_with, file_name))
            c.execute('INSERT OR IGNORE INTO files (username, file_name) VALUES (?, ?)', (shared_with, file_name))
            conn.commit()

    def get_shared_files_received(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT file_name, shared_by FROM shared_files WHERE shared_with = ?', (username,))
            return [{"file_name": row[0], "shared_by": row[1]} for row in c.fetchall()]
            
    def get_shared_files_history(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT file_name, shared_with FROM shared_files WHERE shared_by = ?', (username,))
            history = {}
            for row in c.fetchall():
                file_name, shared_with = row[0], row[1]
                if file_name not in history:
                    history[file_name] = []
                history[file_name].append(shared_with)
            return history

    # --- Notification Operations ---
    def get_notifications(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('SELECT message FROM notifications WHERE username = ? ORDER BY id ASC', (username,))
            return [row[0] for row in c.fetchall()]

    def add_notification(self, username, message):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO notifications (username, message) VALUES (?, ?)', (username, message))
            conn.commit()
            
    def clear_notifications(self, username):
        with db_lock, self._get_conn() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM notifications WHERE username = ?', (username,))
            conn.commit()

    # --- Utility for whole export (useful for log analyzer) ---
    def export_to_dict(self):
        data = {}
        usernames = self.get_all_usernames()
        for u in usernames:
            user_data = self.get_user(u)
            data[u] = {
                "password": user_data["password"],
                "role": user_data["role"],
                "storage_limit": user_data["storage_limit"],
                "password_request": user_data["password_request"],
                "team_members": self.get_team_members(u),
                "files": self.get_files(u),
                "shared_files": self.get_shared_files_received(u),
                "shared_files_history": self.get_shared_files_history(u),
                "notifications": self.get_notifications(u)
            }
        return data

db = DatabaseManager()
db.migrate_from_json()
