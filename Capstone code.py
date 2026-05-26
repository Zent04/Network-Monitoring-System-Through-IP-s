import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import time
import sqlite3
from cryptography.fernet import Fernet
import win10toast
import psutil
import platform
import datetime
from collections import defaultdict

key = Fernet.generate_key()
cipher_suite = Fernet(key)

BUILTIN_USER = "admin"
BUILTIN_PASSWORD = cipher_suite.encrypt(b"admin!23").decode()

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitoring System")
        self.root.geometry("1200x800")
        self.root.state('zoomed') 
        self.root.configure(bg='#f0f0f0') 
        
        self.init_db()
        
        self.setup_ui()
        
        self.monitoring_active = False
        self.suspicious_ips = set()
        self.last_notification = {}
        self.load_suspicious_ips()
        
        self.notifier = win10toast.ToastNotifier()
        
        self.start_monitoring()
    
    def init_db(self):
        self.conn = sqlite3.connect("network_monitor.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                description TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                ip TEXT,
                status TEXT,
                last_seen DATETIME
            )
        ''')
        
        self.conn.commit()
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0', foreground='#333333', font=('Helvetica', 10))
        style.configure('TButton', background='#4CAF50', foreground='white', font=('Helvetica', 10, 'bold'), relief='flat', borderwidth=0)
        style.map('TButton', background=[('active', '#45a049')])
        style.configure('TEntry', fieldbackground='#ffffff', foreground='#333333', font=('Helvetica', 10))
        style.configure('TCombobox', fieldbackground='#ffffff', foreground='#333333', font=('Helvetica', 10))
        style.configure('Treeview', background='#ffffff', foreground='#333333', fieldbackground='#ffffff', font=('Helvetica', 9))
        style.configure('Treeview.Heading', background='#e0e0e0', foreground='#333333', font=('Helvetica', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#cce7ff')])
        style.configure('TLabelframe', background='#f0f0f0', foreground='#333333', font=('Helvetica', 12, 'bold'))
        style.configure('TLabelframe.Label', background='#f0f0f0', foreground='#333333', font=('Helvetica', 12, 'bold'))
        
        self.login_frame = ttk.Frame(self.root)
        self.main_frame = ttk.Frame(self.root)
        
        self.setup_login_ui()
        
        self.setup_main_ui()
        
        self.login_frame.pack(fill=tk.BOTH, expand=True)
    
    def setup_login_ui(self):
        ttk.Label(self.login_frame, text="Network Monitoring System", font=('Helvetica', 18, 'bold')).pack(pady=30)
        
        login_form = ttk.Frame(self.login_frame, relief='ridge', borderwidth=2)
        login_form.pack(pady=30, padx=50)
        
        ttk.Label(login_form, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
        self.username_entry = ttk.Entry(login_form, width=25)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(login_form, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
        self.password_entry = ttk.Entry(login_form, show="*", width=25)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        login_btn = ttk.Button(login_form, text="Login", command=self.authenticate)
        login_btn.grid(row=2, columnspan=2, pady=20)
        
        self.login_status = ttk.Label(self.login_frame, text="", foreground="red", font=('Helvetica', 10))
        self.login_status.pack(pady=10)
    
    def setup_main_ui(self):
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        self.monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_tab, text="Network Monitor")
        
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Activity Logs")
        
        self.setup_dashboard()
        self.setup_monitor_tab()
        self.setup_logs_tab()
        
        self.status_bar = ttk.Label(self.main_frame, text="Ready", relief=tk.SUNKEN, font=('Helvetica', 9))
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        logout_btn = ttk.Button(self.main_frame, text="Logout", command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=10, pady=10)
    
    def setup_dashboard(self):
        self.sys_info_frame = ttk.LabelFrame(self.dashboard_tab, text="System Information")
        self.sys_info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.hostname_label = ttk.Label(self.sys_info_frame, text="")
        self.hostname_label.pack(anchor='w', padx=10, pady=5)
        self.os_label = ttk.Label(self.sys_info_frame, text="")
        self.os_label.pack(anchor='w', padx=10, pady=5)
        self.cpu_label = ttk.Label(self.sys_info_frame, text="")
        self.cpu_label.pack(anchor='w', padx=10, pady=5)
        self.memory_label = ttk.Label(self.sys_info_frame, text="")
        self.memory_label.pack(anchor='w', padx=10, pady=5)
        
        self.update_system_info()
        
        net_status_frame = ttk.LabelFrame(self.dashboard_tab, text="Network Status")
        net_status_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.network_status_tree = ttk.Treeview(net_status_frame, columns=('interface', 'ip', 'status'), show='headings', height=10)
        self.network_status_tree.heading('interface', text='Interface')
        self.network_status_tree.heading('ip', text='IP Address')
        self.network_status_tree.heading('status', text='Status')
        self.network_status_tree.column('interface', width=150)
        self.network_status_tree.column('ip', width=150)
        self.network_status_tree.column('status', width=100)
        self.network_status_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.update_network_status()
    
    def update_system_info(self):
        self.hostname_label.config(text=f"Hostname: {socket.gethostname()}")
        self.os_label.config(text=f"OS: {platform.platform()}")
        self.cpu_label.config(text=f"CPU Usage: {psutil.cpu_percent()}%")
        self.memory_label.config(text=f"Memory Usage: {psutil.virtual_memory().percent}%")
        
        self.root.after(1000, self.update_system_info)
    
    def setup_monitor_tab(self):
        controls_frame = ttk.Frame(self.monitor_tab)
        controls_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(controls_frame, text="Block IP", command=self.block_ip_dialog).pack(side=tk.LEFT, padx=10)
        
        conn_frame = ttk.LabelFrame(self.monitor_tab, text="Active Connections")
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.connections_tree = ttk.Treeview(conn_frame, columns=('proto', 'local', 'remote', 'status', 'pid', 'process', 'direction'), show='headings', height=15)
        self.connections_tree.heading('proto', text='Protocol')
        self.connections_tree.heading('local', text='Local Address')
        self.connections_tree.heading('remote', text='Remote Address')
        self.connections_tree.heading('status', text='Status')
        self.connections_tree.heading('pid', text='PID')
        self.connections_tree.heading('process', text='Process')
        self.connections_tree.heading('direction', text='Direction')
        self.connections_tree.column('proto', width=80)
        self.connections_tree.column('local', width=150)
        self.connections_tree.column('remote', width=150)
        self.connections_tree.column('status', width=100)
        self.connections_tree.column('pid', width=60)
        self.connections_tree.column('process', width=120)
        self.connections_tree.column('direction', width=100)
        self.connections_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        suspicious_frame = ttk.LabelFrame(self.monitor_tab, text="Suspicious IPs")
        suspicious_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.suspicious_tree = ttk.Treeview(suspicious_frame, columns=('ip', 'count', 'last_seen'), show='headings', height=10)
        self.suspicious_tree.heading('ip', text='IP Address')
        self.suspicious_tree.heading('count', text='Count')
        self.suspicious_tree.heading('last_seen', text='Last Seen')
        self.suspicious_tree.column('ip', width=150)
        self.suspicious_tree.column('count', width=100)
        self.suspicious_tree.column('last_seen', width=200)
        self.suspicious_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.update_connections()
    
    def setup_logs_tab(self):
        logs_frame = ttk.LabelFrame(self.logs_tab, text="Activity Logs")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.logs_tree = ttk.Treeview(logs_frame, columns=('timestamp', 'event', 'description', 'ip'), show='headings', height=20)
        self.logs_tree.heading('timestamp', text='Timestamp')
        self.logs_tree.heading('event', text='Event')
        self.logs_tree.heading('description', text='Description')
        self.logs_tree.heading('ip', text='IP Address')
        self.logs_tree.column('timestamp', width=200)
        self.logs_tree.column('event', width=100)
        self.logs_tree.column('description', width=300)
        self.logs_tree.column('ip', width=150)
        self.logs_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.update_logs()
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.login_status.config(text="Username and password are required")
            return
        
        if username == BUILTIN_USER and cipher_suite.decrypt(BUILTIN_PASSWORD.encode()).decode() == password:
            self.login_frame.pack_forget()
            self.main_frame.pack(fill=tk.BOTH, expand=True)
            self.monitoring_active = True
            self.status_bar.config(text="Monitoring active")
            self.log_activity("login", f"User {username} logged in")
            self.log_activity("monitoring", "Started network monitoring")
        else:
            self.login_status.config(text="Invalid credentials")
    
    def logout(self):
        self.monitoring_active = False
        self.suspicious_ips.clear()
        self.last_notification.clear()
        
        self.cursor.execute("DELETE FROM blocked_ips")
        self.cursor.execute("DELETE FROM activity_logs")
        self.cursor.execute("DELETE FROM server_nodes")
        self.conn.commit()
        
        self.connections_tree.delete(*self.connections_tree.get_children())
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        self.logs_tree.delete(*self.logs_tree.get_children())
        self.network_status_tree.delete(*self.network_status_tree.get_children())
        
        self.hostname_label.config(text="")
        self.os_label.config(text="")
        self.cpu_label.config(text="")
        self.memory_label.config(text="")
        
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.login_status.config(text="")
        self.status_bar.config(text="Ready")
    
    def start_monitoring(self):
        def monitor_network():
            ip_counter = defaultdict(int)
            
            while True:
                if self.monitoring_active:
                    connections = self.get_active_connections()
                    current_ips = set()
                    
                    for conn in connections:
                        remote_ip = conn[2].split(':')[0]
                        if remote_ip not in ['0.0.0.0', '127.0.0.1']:
                            current_ips.add(remote_ip)
                            ip_counter[remote_ip] += 1
                            
                            if ip_counter[remote_ip] > 10 and remote_ip not in self.suspicious_ips:
                                self.suspicious_ips.add(remote_ip)
                                now = time.time()
                                if remote_ip not in self.last_notification or now - self.last_notification[remote_ip] > 30: 
                                    self.show_notification("Suspicious Activity", 
                                                         f"High connection count from {remote_ip}")
                                    self.last_notification[remote_ip] = now
                    
                    self.update_suspicious_list()
                    
                    if len(current_ips) > 50: 
                        self.log_activity("security", "Possible DDoS attack detected")
                        now = time.time()
                        if 'ddos' not in self.last_notification or now - self.last_notification['ddos'] > 30:  
                            self.show_notification("Security Alert", "Possible DDoS attack detected")
                            self.last_notification['ddos'] = now
                
                time.sleep(1)  
        
        monitor_thread = threading.Thread(target=monitor_network, daemon=True)
        monitor_thread.start()
    
    def update_network_status(self):
        self.network_status_tree.delete(*self.network_status_tree.get_children())
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    self.network_status_tree.insert('', 'end', values=(interface, addr.address, "Active"))
    
    def update_connections(self):
        self.connections_tree.delete(*self.connections_tree.get_children())
        
        connections = self.get_active_connections()
        for conn in connections:
            self.connections_tree.insert('', 'end', values=conn)
        
        self.root.after(500, self.update_connections)
    
    def get_active_connections(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        subnet = '.'.join(local_ip.split('.')[:3]) + '.'
        
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                continue
                
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            remote_ip = remote_addr.split(':')[0] if remote_addr else ""
            
            if remote_ip and not remote_ip.startswith(subnet):
                continue
            
            process_name = self.get_process_name(conn.pid) if conn.pid else "N/A"
            direction = "Inbound" if remote_addr else "Outbound"
            
            connections.append((
                conn.type.name,
                local_addr,
                remote_addr,
                conn.status,
                conn.pid,
                process_name,
                direction
            ))
        
        return connections
    
    def get_process_name(self, pid):
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "N/A"
    
    def update_suspicious_list(self):
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        
        connections = self.get_active_connections()
        ip_counts = defaultdict(int)
        
        for conn in connections:
            remote_ip = conn[2].split(':')[0]
            if remote_ip not in ['0.0.0.0', '127.0.0.1']:
                ip_counts[remote_ip] += 1
        
        for ip in self.suspicious_ips:
            self.suspicious_tree.insert('', 'end', values=(ip, ip_counts.get(ip, 0), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    
    def load_suspicious_ips(self):
        self.cursor.execute("SELECT ip FROM blocked_ips")
        for row in self.cursor.fetchall():
            self.suspicious_ips.add(row[0])
    
    def update_logs(self):
        self.logs_tree.delete(*self.logs_tree.get_children())
        
        self.cursor.execute("SELECT timestamp, event_type, description, ip_address FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
        for row in self.cursor.fetchall():
            self.logs_tree.insert('', 'end', values=row)
    
    def block_ip_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Block IP Address")
        dialog.geometry("450x250")
        dialog.configure(bg='#f0f0f0')
        
        ttk.Label(dialog, text="Select IP from Suspicious IPs Table:").pack(pady=10)
        
        self.cursor.execute("SELECT ip FROM blocked_ips")
        suspicious_ips_list = [row[0] for row in self.cursor.fetchall()]
        
        ip_combo = ttk.Combobox(dialog, values=suspicious_ips_list, state='readonly')
        ip_combo.pack(pady=5)
        
        ttk.Label(dialog, text="Reason:").pack(pady=5)
        reason_entry = ttk.Entry(dialog)
        reason_entry.pack(pady=5)
        
        def block_ip():
            ip = ip_combo.get()
            reason = reason_entry.get()
            
            if not ip:
                messagebox.showerror("Error", "Please select an IP address")
                return
            
            self.log_activity("block", f"IP {ip} blocked", ip)
           
            messagebox.showinfo("Success", f"IP {ip} is already blocked in the suspicious IPs table")
            dialog.destroy()
        
        ttk.Button(dialog, text="Block", command=block_ip).pack(pady=15)
    
    def show_notification(self, title, message):
        try:
            self.notifier.show_toast(title, message, duration=10)
        except:
            pass
    
    def log_activity(self, event_type, description, ip_address=None):
        self.cursor.execute(
            "INSERT INTO activity_logs (event_type, description, ip_address) VALUES (?, ?, ?)",
            (event_type, description, ip_address)
        )
        self.conn.commit()
        self.update_logs()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()