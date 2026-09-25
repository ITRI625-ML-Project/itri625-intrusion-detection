"""
ITRI625 Project - Intrusion Detection Desktop App
==================================================

A basic Tkinter desktop application that lets an analyst enter a session's
raw features, sends them to the FastAPI service in ``../api/api.py``, and
displays the model's Normal / Attack prediction (rubric 2.5).

Run the API first:
    cd api
    uvicorn api:app --reload --port 8000

Then run this app:
    cd desktop_app
    python desktop_app.py
"""

import json
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import requests

DEFAULT_API_URL = "http://127.0.0.1:8000"

PROTOCOL_OPTIONS = ["TCP", "UDP", "ICMP"]
ENCRYPTION_OPTIONS = ["AES", "DES", "None"]
BROWSER_OPTIONS = ["Chrome", "Edge", "Firefox", "Safari", "Unknown"]

# A couple of ready-made examples so markers/users can try the app without
# having to invent realistic values by hand.
SAMPLE_SESSIONS = {
    "Typical normal session": {
        "network_packet_size": 350,
        "protocol_type": "TCP",
        "login_attempts": 1,
        "session_duration": 620.0,
        "encryption_used": "AES",
        "ip_reputation_score": 0.12,
        "failed_logins": 0,
        "browser_type": "Chrome",
        "unusual_time_access": 0,
    },
    "Suspicious / likely attack": {
        "network_packet_size": 1450,
        "protocol_type": "UDP",
        "login_attempts": 9,
        "session_duration": 45.0,
        "encryption_used": "None",
        "ip_reputation_score": 0.91,
        "failed_logins": 6,
        "browser_type": "Unknown",
        "unusual_time_access": 1,
    },
}


class IDSDesktopApp(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title("ITRI625 - Intrusion Detection (Desktop Client)")
        self.geometry("560x680")
        self.resizable(False, False)

        self.api_url = tk.StringVar(value=DEFAULT_API_URL)
        self.status_text = tk.StringVar(value="Checking API connection...")

        self._build_layout()
        self._check_health_async()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_layout(self):
        pad = {"padx": 10, "pady": 6}

        # --- API connection row -----------------------------------------
        conn_frame = ttk.LabelFrame(self, text="API connection")
        conn_frame.pack(fill="x", **pad)

        ttk.Entry(conn_frame, textvariable=self.api_url, width=40).grid(
            row=0, column=0, padx=8, pady=8, sticky="w"
        )
        ttk.Button(conn_frame, text="Test connection", command=self._check_health_async).grid(
            row=0, column=1, padx=8, pady=8
        )
        self.status_label = ttk.Label(conn_frame, textvariable=self.status_text)
        self.status_label.grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 8), sticky="w")

        # --- Sample loader -------------------------------------------------
        sample_frame = ttk.LabelFrame(self, text="Load a sample session (optional)")
        sample_frame.pack(fill="x", **pad)
        self.sample_choice = tk.StringVar()
        sample_combo = ttk.Combobox(
            sample_frame,
            textvariable=self.sample_choice,
            values=list(SAMPLE_SESSIONS.keys()),
            state="readonly",
            width=30,
        )
        sample_combo.grid(row=0, column=0, padx=8, pady=8)
        ttk.Button(sample_frame, text="Load", command=self._load_sample).grid(
            row=0, column=1, padx=8, pady=8
        )

        # --- Session feature form ------------------------------------------
        form_frame = ttk.LabelFrame(self, text="Session features")
        form_frame.pack(fill="x", **pad)

        self.fields = {}
        self._add_entry(form_frame, "network_packet_size", "Network packet size (bytes)", 0)
        self._add_combo(form_frame, "protocol_type", "Protocol type", PROTOCOL_OPTIONS, 1)
        self._add_entry(form_frame, "login_attempts", "Login attempts", 2)
        self._add_entry(form_frame, "session_duration", "Session duration (seconds)", 3)
        self._add_combo(form_frame, "encryption_used", "Encryption used", ENCRYPTION_OPTIONS, 4)
        self._add_entry(form_frame, "ip_reputation_score", "IP reputation score (0-1)", 5)
        self._add_entry(form_frame, "failed_logins", "Failed logins", 6)
        self._add_combo(form_frame, "browser_type", "Browser type", BROWSER_OPTIONS, 7)

        self.unusual_time_access = tk.BooleanVar(value=False)
        ttk.Label(form_frame, text="Unusual time access?").grid(
            row=8, column=0, padx=8, pady=6, sticky="w"
        )
        ttk.Checkbutton(form_frame, variable=self.unusual_time_access).grid(
            row=8, column=1, padx=8, pady=6, sticky="w"
        )

        # --- Actions ---------------------------------------------------
        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", **pad)
        ttk.Button(action_frame, text="Classify session", command=self._predict_async).pack(
            side="left", padx=8
        )
        ttk.Button(action_frame, text="View model performance", command=self._show_metrics_async).pack(
            side="left", padx=8
        )

        # --- Result panel -----------------------------------------------
        result_frame = ttk.LabelFrame(self, text="Prediction result")
        result_frame.pack(fill="both", expand=True, **pad)

        self.result_label = tk.Label(
            result_frame, text="No prediction yet", font=("Segoe UI", 20, "bold")
        )
        self.result_label.pack(pady=(16, 4))

        self.probability_label = ttk.Label(result_frame, text="")
        self.probability_label.pack()

    def _add_entry(self, parent, key, label, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, padx=8, pady=6, sticky="w")
        var = tk.StringVar()
        ttk.Entry(parent, textvariable=var, width=22).grid(row=row, column=1, padx=8, pady=6, sticky="w")
        self.fields[key] = var

    def _add_combo(self, parent, key, label, options, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, padx=8, pady=6, sticky="w")
        var = tk.StringVar(value=options[0])
        ttk.Combobox(parent, textvariable=var, values=options, state="readonly", width=20).grid(
            row=row, column=1, padx=8, pady=6, sticky="w"
        )
        self.fields[key] = var

    # ------------------------------------------------------------------
    # Sample data
    # ------------------------------------------------------------------
    def _load_sample(self):
        name = self.sample_choice.get()
        if not name:
            return
        sample = SAMPLE_SESSIONS[name]
        for key, value in sample.items():
            if key == "unusual_time_access":
                self.unusual_time_access.set(bool(value))
            elif key in self.fields:
                self.fields[key].set(str(value))

    # ------------------------------------------------------------------
    # Networking (run off the GUI thread so the window never freezes)
    # ------------------------------------------------------------------
    def _check_health_async(self):
        threading.Thread(target=self._check_health, daemon=True).start()

    def _check_health(self):
        try:
            resp = requests.get(f"{self.api_url.get().rstrip('/')}/health", timeout=4)
            resp.raise_for_status()
            data = resp.json()
            if data.get("model_ready"):
                self._set_status("Connected. Model is loaded and ready.", ok=True)
            else:
                self._set_status(
                    "Connected, but model artefacts are missing - run the notebook first.",
                    ok=False,
                )
        except requests.exceptions.RequestException as exc:
            self._set_status(f"Cannot reach API at {self.api_url.get()} ({exc.__class__.__name__})", ok=False)

    def _set_status(self, text, ok):
        self.status_text.set(text)
        self.status_label.configure(foreground="#1a7f37" if ok else "#c0392b")

    def _collect_payload(self):
        """Read and validate the form into the JSON payload the API expects."""
        try:
            payload = {
                "network_packet_size": float(self.fields["network_packet_size"].get()),
                "protocol_type": self.fields["protocol_type"].get(),
                "login_attempts": int(self.fields["login_attempts"].get()),
                "session_duration": float(self.fields["session_duration"].get()),
                "encryption_used": self.fields["encryption_used"].get(),
                "ip_reputation_score": float(self.fields["ip_reputation_score"].get()),
                "failed_logins": int(self.fields["failed_logins"].get()),
                "browser_type": self.fields["browser_type"].get(),
                "unusual_time_access": 1 if self.unusual_time_access.get() else 0,
            }
        except ValueError:
            raise ValueError(
                "Please check the numeric fields (packet size, login attempts, "
                "session duration, IP reputation score, failed logins) - "
                "they must all be numbers."
            )
        if not (0.0 <= payload["ip_reputation_score"] <= 1.0):
            raise ValueError("IP reputation score must be between 0 and 1.")
        return payload

    def _predict_async(self):
        try:
            payload = self._collect_payload()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        self.result_label.configure(text="Classifying...", foreground="black")
        self.probability_label.configure(text="")
        threading.Thread(target=self._predict, args=(payload,), daemon=True).start()

    def _predict(self, payload):
        url = f"{self.api_url.get().rstrip('/')}/predict"
        try:
            resp = requests.post(url, json=payload, timeout=8)
            if resp.status_code != 200:
                detail = resp.json().get("detail", resp.text)
                self.after(0, lambda: messagebox.showerror("API error", str(detail)))
                self.after(0, lambda: self.result_label.configure(text="No prediction yet", foreground="black"))
                return
            data = resp.json()
            self.after(0, lambda: self._render_result(data))
        except requests.exceptions.RequestException as exc:
            self.after(0, lambda: messagebox.showerror("Connection error", str(exc)))
            self.after(0, lambda: self.result_label.configure(text="No prediction yet", foreground="black"))

    def _render_result(self, data):
        label = data["label"]
        prob = data["attack_probability"]
        color = "#c0392b" if label == "Attack" else "#1a7f37"
        self.result_label.configure(text=label.upper(), foreground=color)
        self.probability_label.configure(
            text=f"Predicted attack probability: {prob:.1%}  (decision threshold: {data['threshold']:.0%})"
        )

    # ------------------------------------------------------------------
    # Model performance popup (surfaces rubric 2.3 metrics to the user)
    # ------------------------------------------------------------------
    def _show_metrics_async(self):
        threading.Thread(target=self._show_metrics, daemon=True).start()

    def _show_metrics(self):
        url = f"{self.api_url.get().rstrip('/')}/metrics"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                detail = resp.json().get("detail", resp.text)
                self.after(0, lambda: messagebox.showerror("API error", str(detail)))
                return
            metrics = resp.json()
            text = "\n".join(f"{k:>12s}: {v:.4f}" for k, v in metrics.items())
            self.after(0, lambda: messagebox.showinfo("Model performance (test set)", text))
        except requests.exceptions.RequestException as exc:
            self.after(0, lambda: messagebox.showerror("Connection error", str(exc)))


if __name__ == "__main__":
    app = IDSDesktopApp()
    app.mainloop()
