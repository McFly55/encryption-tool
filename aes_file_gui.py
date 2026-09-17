#!/usr/bin/env python3
"""Grafische Oberflaeche (Tkinter) fuer das AES-256-Dateiverschluesselungs-Tool.

Basiert auf den Funktionen in aes_file_crypto.py. Es werden keine
zusaetzlichen Abhaengigkeiten benoetigt (Tkinter ist Teil von Python).
Auf Arch Linux einmalig installieren:  sudo pacman -S tk
"""

import os
import sys
import threading
from pathlib import Path
from tkinter import (
    BOTH,
    LEFT,
    RIGHT,
    StringVar,
    Tk,
    filedialog,
    messagebox,
    ttk,
)

try:
    from aes_file_crypto import CryptoError, decrypt_file, encrypt_file
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from aes_file_crypto import CryptoError, decrypt_file, encrypt_file

APP_TITLE = "AES-256 Dateiverschluesselung"
PAD = 12


def human_size(num: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} {unit}"
        num /= 1024.0
    return f"{num:.1f} PiB"


class CryptoApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("620x580")
        self.root.minsize(560, 560)

        self.mode = StringVar(value="encrypt")
        self.file_path = StringVar()
        self.password = StringVar()
        self.password2 = StringVar()
        self.status = StringVar(value="Bereit.")
        self.running = False
        self._worker = None
        self._prog_done = 0
        self._prog_total = 0

        self._build_ui()
        self._apply_mode_change()
        self._fit_window_to_content()

    def _build_ui(self) -> None:
        self.main_frame = ttk.Frame(self.root, padding=PAD)
        self.main_frame.pack(fill=BOTH, expand=True)
        main = self.main_frame

        # ---- Modusauswahl ----
        mode_frame = ttk.LabelFrame(main, text="Was moechtest du tun?", padding=PAD)
        mode_frame.pack(fill="x", pady=(0, PAD))
        ttk.Radiobutton(
            mode_frame, text="Datei verschluesseln",
            variable=self.mode, value="encrypt",
            command=self._apply_mode_change,
        ).pack(side=LEFT, padx=(0, 20))
        ttk.Radiobutton(
            mode_frame, text="Datei entschluesseln",
            variable=self.mode, value="decrypt",
            command=self._apply_mode_change,
        ).pack(side=LEFT)

        # ---- Dateiauswahl ----
        file_frame = ttk.LabelFrame(main, text="Datei", padding=PAD)
        file_frame.pack(fill="x", pady=(0, PAD))

        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path)
        self.file_entry.pack(side=LEFT, fill="x", expand=True, padx=(0, PAD))
        self.browse_btn = ttk.Button(file_frame, text="Durchsuchen ...", command=self.browse)
        self.browse_btn.pack(side=RIGHT)

        self.file_info = ttk.Label(main, text="", foreground="#555")
        self.file_info.pack(anchor="w", pady=(0, PAD))

        # ---- Passwort ----
        pw_frame = ttk.LabelFrame(main, text="Passwort", padding=PAD)
        pw_frame.pack(fill="x", pady=(0, PAD))

        ttk.Label(pw_frame, text="Passwort:").grid(row=0, column=0, sticky="w", pady=4)
        self.pw_entry = ttk.Entry(pw_frame, textvariable=self.password, show="*")
        self.pw_entry.grid(row=0, column=1, sticky="we", padx=(8, 0), pady=4)

        self.pw2_label = ttk.Label(pw_frame, text="Wiederholen:")
        self.pw2_label.grid(row=1, column=0, sticky="w", pady=4)
        self.pw2_entry = ttk.Entry(pw_frame, textvariable=self.password2, show="*")
        self.pw2_entry.grid(row=1, column=1, sticky="we", padx=(8, 0), pady=4)

        self.show_var = StringVar(value="no")
        ttk.Checkbutton(
            pw_frame, text="Passwort anzeigen", variable=self.show_var,
            onvalue="yes", offvalue="no", command=self._toggle_pw_visibility,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        pw_frame.columnconfigure(1, weight=1)

        # ---- Fortschritt ----
        prog_frame = ttk.LabelFrame(main, text="Fortschritt", padding=PAD)
        prog_frame.pack(fill="x", pady=(0, PAD))
        self.progress = ttk.Progressbar(prog_frame, mode="determinate", maximum=100)
        self.progress.pack(fill="x")
        self.prog_label = ttk.Label(prog_frame, text="")
        self.prog_label.pack(anchor="w", pady=(4, 0))

        # ---- Status + Aktion ----
        action_frame = ttk.Frame(main)
        action_frame.pack(fill="x", pady=(PAD, 0))
        self.status_label = ttk.Label(action_frame, textvariable=self.status)
        self.status_label.pack(side=LEFT)
        self.run_btn = ttk.Button(action_frame, text="Verschluesseln", command=self.run)
        self.run_btn.pack(side=RIGHT)

    # ---- Hilfsfunktionen ----
    def _fit_window_to_content(self) -> None:
        """Passt die Fensterhoehe an den tatsaechlich benoetigten Inhalt an,
        sodass alle Elemente (inkl. Status und Button) sofort sichtbar sind."""
        self.root.update_idletasks()
        needed_w = self.main_frame.winfo_reqwidth()
        needed_h = self.main_frame.winfo_reqheight()
        # Fensterrahmen/-titel beruecksichtigen (kleine Pauschale)
        extra = 40
        width = max(needed_w + 2 * PAD, 620)
        height = max(needed_h + extra, 560)
        self.root.geometry(f"{int(width)}x{int(height)}")

    def _toggle_pw_visibility(self) -> None:
        show = "" if self.show_var.get() == "yes" else "*"
        self.pw_entry.configure(show=show)
        self.pw2_entry.configure(show=show)

    def _apply_mode_change(self) -> None:
        is_encrypt = self.mode.get() == "encrypt"
        self.run_btn.configure(text="Verschluesseln" if is_encrypt else "Entschluesseln")
        # Bestaetigungsfeld nur beim Verschluesseln anzeigen
        state = "normal" if is_encrypt else "disabled"
        self.pw2_label.configure(state=state)
        self.pw2_entry.configure(state=state)
        self.password2.set("")

    def browse(self) -> None:
        if self.mode.get() == "decrypt":
            path = filedialog.askopenfilename(
                title="Zu entschluesselnde Datei waehlen",
                filetypes=[("Verschluesselte Dateien", "*.enc"), ("Alle Dateien", "*.*")],
            )
        else:
            path = filedialog.askopenfilename(
                title="Zu verschluesselnde Datei waehlen",
                filetypes=[("Alle Dateien", "*.*")],
            )
        if path:
            self.file_path.set(path)
            self._update_file_info()

    def _update_file_info(self) -> None:
        p = Path(self.file_path.get())
        try:
            if p.is_file():
                size = p.stat().st_size
                self.file_info.configure(text=f"{p.name}  -  {human_size(size)}")
            else:
                self.file_info.configure(text="")
        except OSError:
            self.file_info.configure(text="")

    def _set_status(self, text: str, color: str = "#333") -> None:
        self.status.set(text)
        self.status_label.configure(foreground=color)

    def _set_running(self, running: bool) -> None:
        self.running = running
        state = "disabled" if running else "normal"
        self.run_btn.configure(state=state)
        self.browse_btn.configure(state=state)
        self.file_entry.configure(state=state)
        self.pw_entry.configure(state=state)
        self.pw2_entry.configure(state=state)

    def _on_progress(self, done: int, total: int) -> None:
        # Laeuft im Hintergrund-Thread: nur Werte speichern, die Widgets
        # werden im Main-Thread via _poll_worker aktualisiert (thread-sicher).
        self._prog_done = done
        self._prog_total = total

    # ---- Eingabepruefung ----
    def _validate(self) -> Path | None:
        path_str = self.file_path.get().strip()
        if not path_str:
            self._set_status("Bitte eine Datei auswaehlen.", "#b00")
            return None
        p = Path(path_str).expanduser()
        if not p.is_file():
            self._set_status("Die gewaehlte Datei existiert nicht.", "#b00")
            return None
        if not self.password.get():
            self._set_status("Bitte ein Passwort eingeben.", "#b00")
            return None
        if self.mode.get() == "encrypt" and self.password.get() != self.password2.get():
            self._set_status("Die Passwoerter stimmen nicht ueberein.", "#b00")
            return None
        return p

    def _target_path(self, src: Path) -> Path:
        if self.mode.get() == "encrypt":
            return src.with_suffix(src.suffix + ".enc")
        return src.with_suffix("") if src.suffix == ".enc" else src.with_suffix(".dec")

    # ---- Ausfuehrung (im Hintergrund-Thread) ----
    def run(self) -> None:
        if self.running:
            return
        src = self._validate()
        if src is None:
            return

        dst = self._target_path(src)
        if dst.exists():
            if not messagebox.askyesno(
                "Datei existiert bereits",
                f"Die Zieldatei existiert bereits:\n\n{dst}\n\nUeberschreiben?",
            ):
                self._set_status("Abgebrochen.", "#555")
                return

        self._set_running(True)
        self.progress["value"] = 0
        self.prog_label.configure(text="")
        self._set_status("Arbeite ...")

        mode = self.mode.get()
        password = self.password.get()
        self._worker = threading.Thread(
            target=self._worker_run,
            args=(mode, src, dst, password),
            daemon=True,
        )
        self._worker.start()
        self.root.after(100, self._poll_worker)

    def _worker_run(self, mode: str, src: Path, dst: Path, password: str) -> None:
        self._error: str | None = None
        try:
            if dst.exists():
                dst.unlink()
            if mode == "encrypt":
                encrypt_file(src, dst, password, on_progress=self._on_progress)
            else:
                decrypt_file(src, dst, password, on_progress=self._on_progress)
            self._result = dst
        except CryptoError as exc:
            self._error = str(exc)
            self._result = None
        except Exception as exc:  # noqa: BLE001 - GUI soll nie abstuerzen
            self._error = f"Unerwarteter Fehler: {exc}"
            self._result = None

    def _poll_worker(self) -> None:
        # Fortschrittsanzeige aus den vom Thread gespeicherten Werten updaten
        total = self._prog_total
        done = self._prog_done
        pct = 100 if total <= 0 else min(done * 100 // total, 100)
        self.progress["value"] = pct
        self.prog_label.configure(
            text=f"{human_size(done)} / {human_size(total)}  ({pct}%)"
        )

        if self._worker is not None and self._worker.is_alive():
            self.root.after(100, self._poll_worker)
            return
        self._set_running(False)
        if getattr(self, "_error", None):
            self.progress["value"] = 0
            self._set_status("Fehler: " + self._error, "#b00")
            messagebox.showerror("Fehler", self._error)
        else:
            self.progress["value"] = 100
            dst = getattr(self, "_result", None)
            self._set_status("Fertig.", "#070")
            if dst is not None:
                messagebox.showinfo(
                    "Fertig",
                    f"Die Datei wurde erfolgreich gespeichert:\n\n{dst}",
                )
        self._error = None
        self._result = None


def main() -> int:
    root = Tk()
    try:
        # Modernes Theme verwenden, wenn verfuegbar
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    CryptoApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
