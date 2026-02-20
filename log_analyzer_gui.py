import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re
from collections import defaultdict
import datetime
import matplotlib.pyplot as plt
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SOCDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("SOC Threat Intelligence Dashboard")
        self.root.geometry("1050x680")
        self.root.configure(bg="#121212")

        self.file_path = None
        self.low = 0
        self.medium = 0
        self.high = 0

        self.create_ui()

    # ---------------- UI ---------------- #
    def create_ui(self):
        title = tk.Label(self.root,
                         text="SOC Threat Dashboard",
                         font=("Arial", 20, "bold"),
                         bg="#121212",
                         fg="cyan")
        title.pack(pady=10)

        btn_frame = tk.Frame(self.root, bg="#121212")
        btn_frame.pack()

        tk.Button(btn_frame,
                  text="Upload Log File",
                  command=self.load_file,
                  bg="#1f1f1f",
                  fg="white",
                  width=20).grid(row=0, column=0, padx=5)

        tk.Button(btn_frame,
                  text="Enable Real-Time Monitoring",
                  command=self.enable_monitoring,
                  bg="#1f1f1f",
                  fg="white",
                  width=25).grid(row=0, column=1, padx=5)

        tk.Button(btn_frame,
                  text="Show Threat Pie Chart",
                  command=self.show_chart,
                  bg="#1f1f1f",
                  fg="white",
                  width=20).grid(row=0, column=2, padx=5)

        self.result_area = scrolledtext.ScrolledText(self.root,
                                                     width=130,
                                                     height=30,
                                                     bg="#1e1e1e",
                                                     fg="lime",
                                                     insertbackground="white")
        self.result_area.pack(pady=15)

    # ---------------- Log Loading ---------------- #
    def load_file(self):
        self.file_path = filedialog.askopenfilename()
        if not self.file_path:
            return
        self.analyze_logs()

    # ---------------- Analysis Engine ---------------- #
    def analyze_logs(self):
        self.result_area.delete("1.0", tk.END)

        try:
            with open(self.file_path, "r", errors="ignore") as file:
                logs = file.readlines()
        except:
            messagebox.showerror("Error", "Could not read log file.")
            return

        brute_force_ips = defaultdict(int)
        sql_injection_ips = defaultdict(int)

        sql_patterns = ["' OR", "UNION SELECT", "--", "DROP TABLE"]
        blacklist = ["192.168.1.10", "10.0.0.5"]

        self.low = 0
        self.medium = 0
        self.high = 0

        for line in logs:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue

            ip = ip_match.group(1)

            # Blacklist Check
            if ip in blacklist:
                self.high += 1
                self.result_area.insert(tk.END, f"[CRITICAL - BLACKLISTED] {ip}\n")

            # Brute Force Detection
            if "401" in line or "Failed password" in line:
                brute_force_ips[ip] += 1

            # SQL Injection Detection
            for pattern in sql_patterns:
                if pattern.lower() in line.lower():
                    sql_injection_ips[ip] += 1

        # Brute Force Scoring
        for ip, count in brute_force_ips.items():
            if count > 5:
                self.high += 1
                self.result_area.insert(tk.END,
                                        f"[HIGH] Brute Force Attack from {ip} ({count} attempts)\n")
                self.geo_lookup(ip)

        # SQL Injection Scoring
        for ip, count in sql_injection_ips.items():
            self.medium += count
            self.result_area.insert(tk.END,
                                    f"[MEDIUM] SQL Injection detected from {ip} ({count} hits)\n")
            self.geo_lookup(ip)

        total_threats = self.low + self.medium + self.high

        if total_threats == 0:
            self.result_area.insert(tk.END, "\nNo threats detected.\n")
        else:
            self.result_area.insert(tk.END, "\nAnalysis Completed.\n")

    # ---------------- GeoIP Lookup ---------------- #
    def geo_lookup(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = response.json()
            country = data.get("country", "Unknown")
            self.result_area.insert(tk.END, f"   ↳ Location: {country}\n")
        except:
            self.result_area.insert(tk.END, "   ↳ Location: Lookup Failed\n")

    # ---------------- Pie Chart ---------------- #
    def show_chart(self):
        labels = []
        sizes = []

        if self.low > 0:
            labels.append("Low")
            sizes.append(self.low)

        if self.medium > 0:
            labels.append("Medium")
            sizes.append(self.medium)

        if self.high > 0:
            labels.append("High")
            sizes.append(self.high)

        if sum(sizes) == 0:
            messagebox.showinfo("No Data", "No threats detected to visualize.")
            return

        plt.figure()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%')
        plt.title("Threat Distribution")
        plt.show()

    # ---------------- Real-Time Monitoring ---------------- #
    def enable_monitoring(self):
        if not self.file_path:
            messagebox.showerror("Error", "Upload a log file first.")
            return

        class Handler(FileSystemEventHandler):
            def on_modified(inner_self, event):
                if event.src_path == self.file_path:
                    self.analyze_logs()

        observer = Observer()
        observer.schedule(Handler(), path=self.file_path, recursive=False)
        observer.start()

        messagebox.showinfo("Monitoring Enabled",
                            "Real-time monitoring activated.")

# ---------------- Run App ---------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = SOCDashboard(root)
    root.mainloop()
