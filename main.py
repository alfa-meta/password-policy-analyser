# password_analyzer_ctk.py
import customtkinter as ctk
import math
import re
from tkinter import messagebox

ctk.set_appearance_mode("dark")  # "light" or "dark"
ctk.set_default_color_theme("blue")


class PasswordAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Policy & Strength Analyzer")
        self.geometry("1300x800")

        # Policy variables
        self.policy = {
            "min_length": ctk.IntVar(value=8),
            "upper": ctk.BooleanVar(value=True),
            "lower": ctk.BooleanVar(value=True),
            "numbers": ctk.BooleanVar(value=True),
            "special": ctk.BooleanVar(value=False),
            "expire_days": ctk.IntVar(value=90),
            "history": ctk.IntVar(value=5),
            "max_attempts": ctk.IntVar(value=5),
            "lockout_min": ctk.IntVar(value=30),
        }

        self.password_var = ctk.StringVar()
        self.analysis_result = None
        self.strength_result = None
        self.dict_result = None

        self.create_ui()

    def create_ui(self):
        title = ctk.CTkLabel(self, text="Password Policy Analyzer",
                             font=ctk.CTkFont(size=28, weight="bold"))
        title.pack(pady=20)

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Left panel
        left = ctk.CTkFrame(main_frame, width=400)
        left.pack(side="left", fill="both", padx=(0, 10))
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="Policy Configuration",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        sliders = [
            ("Minimum Length", "min_length", 4, 20),
            ("Password Expires (days)", "expire_days", 0, 365),
            ("Password History (last N)", "history", 0, 24),
            ("Max Failed Attempts", "max_attempts", 3, 15),
            ("Lockout Duration (min)", "lockout_min", 5, 120),
        ]

        for label, key, minv, maxv in sliders:
            frame = ctk.CTkFrame(left)
            frame.pack(fill="x", padx=20, pady=8)
            ctk.CTkLabel(frame, text=label, width=180, anchor="w").pack(side="left")
            slider = ctk.CTkSlider(frame, from_=minv, to=maxv, variable=self.policy[key])
            slider.pack(side="right", padx=10)
            ctk.CTkLabel(frame, textvariable=self.policy[key], width=40).pack(side="right")

        ctk.CTkLabel(left, text="Complexity Requirements",
                     font=ctk.CTkFont(weight="bold")).pack(pady=(20, 10), anchor="w", padx=20)

        for text, key in [
            ("Uppercase letters", "upper"),
            ("Lowercase letters", "lower"),
            ("Numbers", "numbers"),
            ("Special characters", "special"),
        ]:
            ctk.CTkCheckBox(left, text=text, variable=self.policy[key]).pack(anchor="w", padx=40, pady=4)

        ctk.CTkButton(left, text="Analyze Policy",
                      command=self.analyze_policy, height=40,
                      font=ctk.CTkFont(weight="bold")).pack(pady=25, padx=50)

        # Right Panel
        right = ctk.CTkFrame(main_frame)
        right.pack(side="right", fill="both", expand=True)

        tester = ctk.CTkFrame(right)
        tester.pack(fill="x", pady=(0, 15), padx=20)

        ctk.CTkLabel(tester, text="Test a Password",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)

        entry = ctk.CTkEntry(tester, textvariable=self.password_var,
                             width=400, height=40, font=ctk.CTkFont(size=14))
        entry.pack(pady=10)

        ctk.CTkButton(tester, text="Test Password Strength",
                      command=self.test_password, width=200, height=40).pack(pady=10)

        ctk.CTkLabel(tester, text="Never enter real passwords!",
                     text_color="orange").pack()

        self.tabview = ctk.CTkTabview(right)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)

        self.tabview.add("Policy Analysis")
        self.tabview.add("Strength Details")
        self.tabview.add("Dictionary Attack")

    def analyze_policy(self):
        p = {k: v.get() for k, v in self.policy.items()}
        score = 0
        details = []

        # Length scoring
        if p["min_length"] >= 12:
            score += 20
            details.append(("Excellent", "Length ≥ 12 characters"))
        elif p["min_length"] >= 8:
            score += 15
            details.append(("Good", "Length ≥ 8 characters"))
        else:
            score += 5
            details.append(("Poor", "Length < 8"))

        # Complexity
        types = sum([p["upper"], p["lower"], p["numbers"], p["special"]])
        score += types * 5 + (10 if p["special"] else 0)
        details.append(("Complexity", f"{types}/4 character classes required"))

        # Expiry
        if 1 <= p["expire_days"] <= 90:
            score += 15
            details.append(("Strong", "Expires ≤ 90 days"))
        else:
            score += 5
            details.append(("Weak", "No/too long expiration"))

        # History
        if p["history"] >= 10:
            score += 15
            details.append(("Excellent", "History ≥ 10"))
        else:
            score += 8
            details.append(("Good", "History ≥ 5"))

        # Lockout
        if p["max_attempts"] <= 5 and p["lockout_min"] >= 15:
            score += 20
            details.append(("Excellent", "Strong lockout policy"))
        else:
            score += 10
            details.append(("Moderate", "Lockout could be stronger"))

        score += 10
        total = min(100, round((score / 138) * 100))

        risk = "LOW" if total >= 80 else "MEDIUM" if total >= 60 else "HIGH" if total >= 40 else "CRITICAL"
        color = "#00ff00" if total >= 80 else "#ffaa00" if total >= 60 else "#ff4444"

        self.analysis_result = {"score": total, "risk": risk, "color": color, "details": details}
        self.show_policy_results()

    def show_policy_results(self):
        tab = self.tabview.tab("Policy Analysis")
        for widget in tab.winfo_children():
            widget.destroy()

        ctk.CTkLabel(tab, text=f"{self.analysis_result['score']}%",
                     font=ctk.CTkFont(size=60, weight="bold"),
                     text_color=self.analysis_result["color"]).pack(pady=30)

        ctk.CTkLabel(tab, text=self.analysis_result["risk"],
                     font=ctk.CTkFont(size=36, weight="bold"),
                     text_color=self.analysis_result["color"]).pack(pady=10)

        for status, text in self.analysis_result["details"]:
            color = "#00ff00" if status in ["Excellent", "Strong"] else \
                    "#ffaa00" if status in ["Good", "Moderate"] else "#ff6666"

            ctk.CTkLabel(tab, text=f"• {text}", text_color=color,
                         font=ctk.CTkFont(size=14)).pack(anchor="w", padx=80, pady=4)

    def test_password(self):
        pwd = self.password_var.get().strip()
        if not pwd:
            messagebox.showwarning("Empty", "Enter a password first")
            return

        length = len(pwd)
        has_upper = bool(re.search(r"[A-Z]", pwd))
        has_lower = bool(re.search(r"[a-z]", pwd))
        has_num = bool(re.search(r"\d", pwd))
        has_spec = bool(re.search(r"[^A-Za-z0-9]", pwd))

        charset = (26 if has_lower else 0) + \
                  (26 if has_upper else 0) + \
                  (10 if has_num else 0) + \
                  (32 if has_spec else 0)

        entropy = length * math.log2(charset) if charset else 0
        combos = charset ** length if charset else 0

        rates = {
            "Online attack (10/sec)": 10,
            "Fast online (10k/sec)": 10_000,
            "Offline fast (100B/sec)": 100_000_000_000,
            "Supercomputer": 1_000_000_000_000,
        }

        times = {k: self.format_time(combos / (2 * v)) for k, v in rates.items()}

        score = 0
        if length >= 16:
            score += 35
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15

        score += (15 if has_upper else 0) + \
                 (15 if has_lower else 0) + \
                 (15 if has_num else 0) + \
                 (25 if has_spec else 0)

        score = min(100, score)

        level = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(4, score // 20)]
        color = ["#ff4444", "#ff8800", "#ffaa00", "#4488ff", "#00ff00"][min(4, score // 20)]

        self.strength_result = {
            "level": level,
            "score": score,
            "color": color,
            "entropy": entropy,
            "combos": f"{combos:.2e}",
            "times": times
        }

        self.dict_result = self.dictionary_attack(pwd)

        self.show_strength_results()
        self.show_dict_results()

    def format_time(self, seconds):
        if seconds < 1:
            return "instantly"

        units = [
            ("year", 31536000),
            ("day", 86400),
            ("hour", 3600),
            ("minute", 60),
        ]

        parts = []
        for unit, secs in units:
            val = int(seconds // secs)
            if val:
                parts.append(f"{val} {unit}{'s' if val > 1 else ''}")
                seconds %= secs

        return " ".join(parts[:2]) + (" and more" if len(parts) > 2 else "")

    def dictionary_attack(self, pwd):
        lower = pwd.lower()
        issues = []

        common_passwords = ["password", "123456", "qwerty", "admin", "letmein", "welcome", "password123"]
        if lower in common_passwords:
            issues.append("In top 10 most common passwords")

        patterns = [
            (r"^[a-z]+$", "All lowercase"),
            (r"^\d+$", "Only numbers"),
            (r"^(.)\1+$", "Repeated character"),
            (r"qwerty|asdf|zxcvb", "Keyboard walking pattern"),
            (r"password|admin|root|123", "Contains forbidden word"),
        ]

        for pat, desc in patterns:
            if re.search(pat, pwd, re.I):
                issues.append(desc)

        if len(pwd) < 8:
            issues.append("Too short (<8 characters)")

        return {"vulnerable": len(issues) > 0,
                "issues": issues or ["No common patterns detected"]}

    def show_strength_results(self):
        tab = self.tabview.tab("Strength Details")
        for w in tab.winfo_children():
            w.destroy()

        s = self.strength_result

        ctk.CTkLabel(tab, text=s["level"], font=ctk.CTkFont(size=36, weight="bold"),
                     text_color=s["color"]).pack(pady=30)

        ctk.CTkLabel(tab, text=f"Score: {s['score']}/100 | Entropy: {s['entropy']:.1f} bits"
                     ).pack(pady=10)

        ctk.CTkLabel(tab, text=f"Total combinations: {s['combos']}").pack(pady=10)

        ctk.CTkLabel(tab, text="Estimated crack time:",
                     font=ctk.CTkFont(weight="bold")).pack(pady=(20, 10), anchor="w", padx=50)

        for scenario, t in s["times"].items():
            ctk.CTkLabel(tab, text=f"• {scenario}: {t}", anchor="w").pack(anchor="w", padx=70)

    def show_dict_results(self):
        tab = self.tabview.tab("Dictionary Attack")
        for w in tab.winfo_children():
            w.destroy()

        d = self.dict_result
        status = "VULNERABLE" if d["vulnerable"] else "RESISTANT"
        color = "#ff4444" if d["vulnerable"] else "#00ff88"

        ctk.CTkLabel(tab, text=status,
                     font=ctk.CTkFont(size=32, weight="bold"),
                     text_color=color).pack(pady=40)

        for issue in d["issues"]:
            c = "#ff6666" if d["vulnerable"] else "#00ff88"
            ctk.CTkLabel(tab, text="• " + issue,
                         text_color=c, font=ctk.CTkFont(size=14)).pack(pady=5)


if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()
