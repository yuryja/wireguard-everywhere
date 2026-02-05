import sqlite3
import time
from datetime import datetime

class Database:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_connection(self):
        """Create a database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        ''')
        
        # Activity Logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        conn.commit()
        conn.close()

    # User methods
    def get_user_by_username(self, username):
        conn = self.get_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        return user

    def get_user_by_id(self, user_id):
        conn = self.get_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return user

    def create_user(self, username, password_hash):
        conn = self.get_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                         (username, password_hash))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def update_user_password(self, user_id, password_hash):
        conn = self.get_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                     (password_hash, user_id))
        conn.commit()
        conn.close()

    # Client methods
    def add_client(self, name, public_key, ip_address, created_by):
        conn = self.get_connection()
        try:
            conn.execute('''
                INSERT INTO clients (name, public_key, ip_address, created_by)
                VALUES (?, ?, ?, ?)
            ''', (name, public_key, ip_address, created_by))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def get_all_clients(self):
        conn = self.get_connection()
        clients = conn.execute('SELECT * FROM clients ORDER BY created_at DESC').fetchall()
        conn.close()
        return clients

    def get_client_by_name(self, name):
        conn = self.get_connection()
        client = conn.execute('SELECT * FROM clients WHERE name = ?', (name,)).fetchone()
        conn.close()
        return client

    def update_client_status(self, name, enabled):
        conn = self.get_connection()
        conn.execute('UPDATE clients SET enabled = ? WHERE name = ?', (enabled, name))
        conn.commit()
        conn.close()

    def delete_client(self, name):
        conn = self.get_connection()
        conn.execute('DELETE FROM clients WHERE name = ?', (name,))
        conn.commit()
        conn.close()

    # Activity Log methods
    def log_activity(self, user_id, action, details=None, ip_address=None):
        conn = self.get_connection()
        conn.execute('''
            INSERT INTO activity_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, details, ip_address))
        conn.commit()
        conn.close()

    def get_activity_logs(self, limit=50):
        conn = self.get_connection()
        logs = conn.execute('''
            SELECT l.*, u.username 
            FROM activity_logs l 
            LEFT JOIN users u ON l.user_id = u.id 
            ORDER BY l.created_at DESC 
            LIMIT ?
        ''', (limit,)).fetchall()
        conn.close()
        return logs
