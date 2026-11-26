#!/usr/bin/env python3
"""Desktop interface for offline PCAP summaries."""

import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk


BG = "#0b1220"
PANEL = "#121d2e"
TEXT = "#edf4ff"
MUTED = "#9bacbf"
ACCENT = "#45d6c5"


class AnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Traffic Analyzer")
        self.geometry("900x660")
        self.minsize(720, 540)
        self.configure(bg=BG)
        self.path = tk.StringVar()
        self.top = tk.StringVar(value="10")
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Arial", 10))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
        style.configure("TEntry", fieldbackground="#0f1928", foreground=TEXT,
                        insertcolor=TEXT, bordercolor="#31445b")
        style.configure("TButton", padding=(12, 8), background="#24364b",
                        foreground=TEXT, borderwidth=0)
        style.configure("Accent.TButton", background=ACCENT, foreground="#07131b",
                        font=("Arial", 10, "bold"))

    def _build(self):
        shell = ttk.Frame(self, padding=24)
        shell.pack(fill="both", expand=True)
        ttk.Label(shell, text="TRAFFIC REVIEW  /  OFFLINE FILES", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(shell, text="PCAP Traffic Analyzer", font=("Arial", 25, "bold")).pack(anchor="w", pady=(6, 4))
        ttk.Label(shell, text="Reads a saved capture and summarises protocols, endpoints and DNS queries.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 18))
        card = ttk.Frame(shell, style="Card.TFrame", padding=16)
        card.pack(fill="x")
        ttk.Label(card, text="Capture file", style="Card.TLabel").pack(anchor="w", pady=(0, 7))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.path).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Button(row, text="Choose file…", command=self.choose).pack(side="left")
        opts = ttk.Frame(card, style="Card.TFrame")
        opts.pack(fill="x", pady=(12, 0))
        ttk.Label(opts, text="Top entries", style="Card.TLabel").pack(side="left", padx=(0, 8))
        ttk.Entry(opts, textvariable=self.top, width=8).pack(side="left")
        self.run_button = ttk.Button(opts, text="Analyze capture", style="Accent.TButton", command=self.analyze)
        self.run_button.pack(side="right")
        self.status = tk.StringVar(value="Choose a capture you created or are authorised to inspect.")
        ttk.Label(shell, textvariable=self.status, style="Muted.TLabel").pack(anchor="w", pady=(16, 8))
        self.output = tk.Text(shell, bg="#070d16", fg=TEXT, insertbackground=TEXT,
                              relief="flat", padx=16, pady=14, font=("Menlo", 11), wrap="none")
        self.output.pack(fill="both", expand=True)
        self.output.insert("end", "Analysis results will appear here.\n")
        self.output.configure(state="disabled")

    def choose(self):
        path = filedialog.askopenfilename(
            title="Choose an authorised capture",
            filetypes=[("Packet captures", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if path:
            self.path.set(path)

    def analyze(self):
        if not self.path.get():
            self.status.set("Choose a capture file first.")
            return
        try:
            top = int(self.top.get())
            if top < 1:
                raise ValueError
        except ValueError:
            self.status.set("Top entries must be a positive number.")
            return
        self.run_button.configure(state="disabled")
        self.status.set("Reading capture offline…")
        threading.Thread(target=self._run, args=(self.path.get(), top), daemon=True).start()

    def _run(self, path, top):
        result = subprocess.run(
            [sys.executable, "pcap_summary.py", path, "--top", str(top)],
            capture_output=True, text=True, timeout=180
        )
        self.after(0, self._finish, result)

    def _finish(self, result):
        self.run_button.configure(state="normal")
        self.status.set("Summary ready." if result.returncode == 0 else "Could not read this capture.")
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", result.stdout if result.returncode == 0 else result.stderr)
        self.output.configure(state="disabled")


if __name__ == "__main__":
    AnalyzerApp().mainloop()
