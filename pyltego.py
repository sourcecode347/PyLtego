# Author : SourceCode347
# Website : sourcecode347.com
# pyltego.py - Domain OSINT Graph Tool
# Required libraries: pip install networkx matplotlib pillow requests beautifulsoup4 lxml

import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pickle
import threading
import requests
from bs4 import BeautifulSoup
import re
import socket

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

class Entity:
    def __init__(self, entity_type, value):
        self.type = entity_type   # domain, ip, email, url
        self.value = value.strip().lower()
    
    def __hash__(self):
        return hash((self.type, self.value))
    
    def __eq__(self, other):
        return isinstance(other, Entity) and self.type == other.type and self.value == other.value
    
    def __repr__(self):
        return f"{self.type.upper()}: {self.value}"


class Pyltego:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.root = None
    
    def add_entity(self, entity, parent=None):
        if entity not in self.graph:
            self.graph.add_node(entity)
        if parent and not self.graph.has_edge(parent, entity):
            self.graph.add_edge(parent, entity)
        if not self.root:
            self.root = entity
    
    def is_live(self, domain):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            for proto in ['https://', 'http://']:
                try:
                    r = requests.head(proto + domain, timeout=6, headers=headers, allow_redirects=True)
                    if r.status_code in (200, 301, 302, 403, 405):
                        return True
                except:
                    continue
            return False
        except:
            return False
    
    def get_page_data(self, domain):
        emails = set()
        urls = set()
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            for proto in ['https://', 'http://']:
                try:
                    r = requests.get(proto + domain, timeout=10, headers=headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        
                        # Emails
                        found = EMAIL_REGEX.findall(r.text)
                        for email in found:
                            if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js')):
                                emails.add(email.lower())
                        
                        # External Links
                        for a in soup.find_all('a', href=True):
                            href = a['href'].strip()
                            if href.startswith(('http://', 'https://')):
                                urls.add(href)
                        break
                except:
                    continue
        except:
            pass
        return list(emails), list(urls)
    
    def expand_domain(self, domain):
        results = []
        parts = domain.split('.')
        base = parts[-2] + '.' + parts[-1] if len(parts) >= 2 else domain
        
        subs = ["www", "mail", "admin", "vpn", "api", "login", "portal", "shop", "blog", "dev", "staging"]
        
        # Subdomains + their data
        for sub in subs:
            candidate = f"{sub}.{base}"
            if self.is_live(candidate):
                results.append(Entity("domain", candidate))
                try:
                    ip = socket.gethostbyname(candidate)
                    results.append(Entity("ip", ip))
                except:
                    pass
                
                # Emails & Links από subdomain
                emails, urls = self.get_page_data(candidate)
                for email in emails[:6]:
                    results.append(Entity("email", email))
                for url in urls[:5]:
                    results.append(Entity("url", url[:80] + "..." if len(url) > 80 else url))
        
        # Main domain
        if self.is_live(base) and base not in [d.value for d in results if d.type == "domain"]:
            results.append(Entity("domain", base))
            try:
                ip = socket.gethostbyname(base)
                results.append(Entity("ip", ip))
            except:
                pass
            
            emails, urls = self.get_page_data(base)
            for email in emails[:8]:
                results.append(Entity("email", email))
            for url in urls[:6]:
                results.append(Entity("url", url[:80] + "..." if len(url) > 80 else url))
        
        # Remove duplicates
        seen = set()
        unique = []
        for item in results:
            key = (item.type, item.value)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique
    
    def expand_node(self, entity):
        if entity.type == "domain":
            return self.expand_domain(entity.value)
        return []


class PyltegoGUI:
    def __init__(self):
        self.app = Pyltego()
        self.root = tk.Tk()
        self.root.title("PyLtego - Domain Osint Graph Tool")
        self.root.geometry("1480x940")
        
        sidebar = ttk.Frame(self.root, width=280)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        ttk.Label(sidebar, text="Domain Investigation", font=("Arial", 14, "bold")).pack(anchor="w", pady=10)
        
        ttk.Label(sidebar, text="Enter Domain:").pack(anchor="w")
        self.search_entry = ttk.Entry(sidebar, width=38)
        self.search_entry.pack(pady=8)
        self.search_entry.bind("<Return>", lambda e: self.start_search())
        
        self.scan_button = ttk.Button(sidebar, text="🔍 Start Investigation", command=self.start_search)
        self.scan_button.pack(pady=12, fill="x")
        
        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", pady=15)
        
        ttk.Button(sidebar, text="💾 Save Graph", command=self.save_graph).pack(pady=5, fill="x")
        ttk.Button(sidebar, text="📂 Load Graph", command=self.load_graph).pack(pady=5, fill="x")
        ttk.Button(sidebar, text="🗑 Clear Graph", command=self.clear_graph).pack(pady=5, fill="x")
        
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(0,10), pady=10)
        
        self.fig, self.ax = plt.subplots(figsize=(12.5, 8.5))
        self.canvas = FigureCanvasTkAgg(self.fig, self.main_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.toolbar = NavigationToolbar2Tk(self.canvas, self.main_frame)
        self.toolbar.update()
        
        self.status = ttk.Label(self.root, text="Ready", relief="sunken", anchor="w")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.canvas.mpl_connect('button_press_event', self.on_click)
        self.update_graph()
    
    def start_search(self):
        domain = self.search_entry.get().strip().lower()
        if not domain or "." not in domain:
            messagebox.showwarning("Error", "Enter a valid domain")
            return
        
        self.scan_button.config(state="disabled")
        self.status.config(text=f"Scanning {domain} and subdomains... (please wait)")
        
        entity = Entity("domain", domain)
        self.app.add_entity(entity)
        
        threading.Thread(target=self.expand_thread, args=(entity,), daemon=True).start()
    
    def expand_thread(self, entity):
        transforms = self.app.expand_node(entity)
        for t in transforms:
            self.app.add_entity(t, entity)
        
        self.root.after(0, self.update_graph)
        self.root.after(0, lambda: self.status.config(text=f"Scan completed for {entity.value}"))
        self.root.after(0, lambda: self.scan_button.config(state="normal"))
    
    def update_graph(self):
        self.ax.clear()
        if len(self.app.graph.nodes) == 0:
            self.ax.text(0.5, 0.5, "Enter a domain to start", ha='center', va='center', fontsize=14)
            self.canvas.draw()
            return
        
        pos = nx.spring_layout(self.app.graph, k=0.75, iterations=150, seed=42)
        self.app.pos = pos
        
        color_map = {
            "domain": "#FF9F1C",
            "ip": "#4ADE80",
            "email": "#A78BFA",
            "url": "#F472B6"
        }
        colors = [color_map.get(n.type, "gray") for n in self.app.graph.nodes]
        
        nx.draw_networkx_nodes(self.app.graph, pos, ax=self.ax, node_color=colors, node_size=2600)
        nx.draw_networkx_edges(self.app.graph, pos, ax=self.ax, edge_color="#555", arrows=True)
        nx.draw_networkx_labels(self.app.graph, pos, ax=self.ax, font_size=8.5, font_weight="bold")
        
        self.ax.set_title("PyLtego - Investigation Graph", fontsize=16)
        self.ax.axis("off")
        self.canvas.draw()
    
    def on_click(self, event):
        if event.inaxes != self.ax or not hasattr(self.app, 'pos'):
            return
        closest = min(self.app.pos.keys(), key=lambda n: (self.app.pos[n][0]-event.xdata)**2 + (self.app.pos[n][1]-event.ydata)**2)
        dist = (self.app.pos[closest][0]-event.xdata)**2 + (self.app.pos[closest][1]-event.ydata)**2
        if dist < 0.15 and closest.type == "domain":
            threading.Thread(target=self.expand_thread, args=(closest,), daemon=True).start()
    
    def save_graph(self):
        fn = filedialog.asksaveasfilename(defaultextension=".pyl")
        if fn:
            with open(fn, "wb") as f: pickle.dump(self.app.graph, f)
            messagebox.showinfo("Saved", "Graph saved!")
    
    def load_graph(self):
        fn = filedialog.askopenfilename(filetypes=[("PyLtego", "*.pyl")])
        if fn:
            with open(fn, "rb") as f: self.app.graph = pickle.load(f)
            self.update_graph()
    
    def clear_graph(self):
        if messagebox.askyesno("Clear", "Clear graph?"):
            self.app.graph.clear()
            self.update_graph()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    print("PyLtego - Domain Osint Graph Tool")
    app = PyltegoGUI()
    app.run()