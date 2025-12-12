# ui/settings_tabs.py
# Copyright (C) 2025 Frédéric Levi Mazloum
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

import base64
import datetime
import logging
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter import ttk
import ttkbootstrap
from ttkbootstrap.constants import *
from opn_czami import OpnCzamiLogic
from models.utils import show_error, show_info
from models.config import FEATURE_WATERMARK, FEATURE_AUDIT, FEATURE_MASKED_IDS

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except Exception:
    PYZIPPER_AVAILABLE = False


class SettingsTabs:
    """
    Manages the application's configuration tabs: 'Settings' and 'Backup'.
    """

    def _update_wraplength(self, event, label_widget):
        """Helper to dynamically adjust the wraplength of a label."""
        label_widget.config(wraplength=event.width - 20)

    def __init__(self, notebook: ttk.Notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic

        # Tk variables kept with identical names so external code can reference them
        self.check_for_updates_var = tk.BooleanVar()
        self.show_pass_var = tk.BooleanVar(value=False)
        self.backup_show_pass_var = tk.BooleanVar(value=False)

        # frames
        self.settings_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.security_tab_frame = ttk.Frame(self.notebook, padding=10)

        # Build UI
        self._create_settings_and_uploads_tab(self.settings_tab_frame)
        self._create_backup_and_security_tab(self.security_tab_frame)

    def add_backup_and_settings_tabs(self):
        """Insert backup and settings tabs at correct positions (called after pro tabs)."""
        self.notebook.add(self.security_tab_frame, text=" 6. Backup ")
        self.notebook.add(self.settings_tab_frame, text=" 7. Settings ")

    # --- UI HELPER METHODS ---

    def _reset_button_to_normal(self, button, text):
        """
        Reset a button to normal state with default text.
        Safely handles missing widgets.
        """
        try:
            button.config(state=NORMAL, text=text)
        except (tk.TclError, AttributeError, RuntimeError) as e:
            # If widget not yet created or destroyed, log and ignore
            logging.debug(f"Could not reset button state (UI widget issue): {e}")
            pass

    def _show_operation_result(self, success: bool, message: str, title: str = None):
        """
        Show operation result to user and reload UI.
        """
        if success:
            dialog_title = title or "Operation Successful"
            show_info(dialog_title, message)
        else:
            dialog_title = title or "Operation Failed"
            show_error(dialog_title, message)

        # Reload the UI to reflect new state
        self.logic.reload_data_and_update_ui()

    # --- UI CREATION ---

    def _create_settings_and_uploads_tab(self, parent_frame):
        """Builds the full settings tab with 3-column layout."""
        parent_frame.grid_columnconfigure(0, weight=1)
        top_columns_container = ttk.Frame(parent_frame)
        top_columns_container.grid(row=0, column=0, sticky="new")
        # 2-column layout: Connection & Uploads (narrow) | Signing & Saving & Watermark & Audit & Document
        top_columns_container.grid_columnconfigure(0, weight=2)      # Column 1: Connection & Uploads (narrow)
        top_columns_container.grid_columnconfigure(1, weight=3)      # Column 2: Signing, Watermark, Audit, Document (wider)

        #  COLUMN 1: CONNECTION & UPLOADS 
        col1 = ttk.Frame(top_columns_container)
        col1.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Connection frame
        connection_frame = ttk.LabelFrame(col1, text="🚀 Connection & Uploads", padding=15)
        connection_frame.pack(fill="x", pady=(0, 10), anchor='n')
        connection_frame.grid_columnconfigure(1, weight=1)

        row = 0
        ttk.Label(connection_frame, text="Step 1: Enter FTP Server Credentials", font="-weight bold").grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 10))
        row += 1

        ttk.Label(connection_frame, text="Username:").grid(row=row, column=0, sticky="w", padx=(0, 5), pady=4)
        self.ftp_user_entry = ttk.Entry(connection_frame)
        self.ftp_user_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        row += 1

        ttk.Label(connection_frame, text="Password:").grid(row=row, column=0, sticky="w", padx=(0, 5), pady=4)
        self.ftp_pass_entry = ttk.Entry(connection_frame, show="*")
        self.ftp_pass_entry.grid(row=row, column=1, sticky="ew", pady=4, ipady=2)
        self.show_pass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(connection_frame, text="Show", variable=self.show_pass_var, command=self.toggle_password_visibility, bootstyle="toolbutton").grid(row=row, column=2, sticky="w", padx=5)
        row += 1

        ttk.Separator(connection_frame).grid(row=row, column=0, columnspan=3, sticky="ew", pady=15)
        row += 1

        ttk.Label(connection_frame, text="Step 2: Set FTP Address & Path", font="-weight bold").grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 10))
        row += 1

        ttk.Label(connection_frame, text="FTP Host:").grid(row=row, column=0, sticky="w", padx=(0, 5), pady=4)
        self.ftp_host_entry = ttk.Entry(connection_frame)
        self.ftp_host_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        row += 1

        ttk.Label(connection_frame, text="Root Path:").grid(row=row, column=0, sticky="w", padx=(0, 5), pady=(10, 4))
        path_entry_frame = ttk.Frame(connection_frame)
        path_entry_frame.grid(row=row, column=1, columnspan=2, sticky="ew", pady=(10, 4))
        self.ftp_path_entry = ttk.Entry(path_entry_frame, width=15)
        self.ftp_path_entry.pack(side="left", fill="x", expand=True, ipady=2, padx=(0, 5))
        self.sense_button = ttk.Button(path_entry_frame, text="🔎 Auto-Sense", command=self.handle_auto_sense_threaded, bootstyle="outline-info")
        self.sense_button.pack(side="left", expand=False)
        row += 1

        self.save_and_upload_button = ttk.Button(connection_frame, text="✔️ Save Settings & Upload Public Files", command=self.handle_save_settings_and_upload_threaded, bootstyle=PRIMARY, state=DISABLED)
        self.save_and_upload_button.grid(row=row, column=0, columnspan=3, sticky="ew", ipady=5, pady=(20, 0))
        row += 1

        ttk.Separator(connection_frame).grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)
        row += 1

        self.enable_insights_logging_var = tk.BooleanVar()
        self.enable_insights_logging_checkbox = ttk.Checkbutton(
            connection_frame,
            text="Enable Anonymized Server Logging",
            variable=self.enable_insights_logging_var,
            bootstyle="info-round-toggle",
            command=self.handle_insights_logging_toggle
        )
        self.enable_insights_logging_checkbox.grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 5))
        row += 1

        desc_label = ttk.Label(connection_frame, text="Required for Insight generation (Pro feature)",
                  font="-size 8", bootstyle="secondary", wraplength=400, justify="left")
        desc_label.grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 0))

        ttk.Separator(connection_frame).grid(row=row+1, column=0, columnspan=3, sticky="ew", pady=15)

        # Security Status (moved from Backup tab)
        security_status_frame = ttk.LabelFrame(connection_frame, text="🔒 Security Status", padding=10)
        security_status_frame.grid(row=row+2, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        # Check if keystore is available and show status
        keystore_available = self.logic.crypto_manager.is_keystore_available()

        if keystore_available:
            ttk.Label(security_status_frame, text="✅ Hardened Security ENABLED", bootstyle="success", font="-weight bold").pack(anchor="w")
            ttk.Label(security_status_frame, text="Your private key and FTP password are secured in your OS's keychain.", wraplength=350, bootstyle="secondary", font="-size 8").pack(anchor="w")
        else:
            ttk.Label(security_status_frame, text="⚠️ Hardened Security NOT AVAILABLE", bootstyle="warning", font="-weight bold").pack(anchor="w")
            ttk.Label(security_status_frame, text="Your OS doesn't support secure keychain. Keys are stored in encrypted database.", wraplength=350, bootstyle="secondary", font="-size 8").pack(anchor="w")

        # ========== COLUMN 2: SIGNING & SAVING + WATERMARK + AUDIT + DOCUMENT ==========
        col2 = ttk.Frame(top_columns_container)
        col2.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        # Signing & Saving options
        lkey_qr_frame = ttk.LabelFrame(col2, text="📝 Signing & Saving", padding=15)
        lkey_qr_frame.pack(fill="x", pady=(0, 10))

        # Auto update check (moved from Column 2)
        self.check_for_updates_checkbox = ttk.Checkbutton(
            lkey_qr_frame,
            text="Check for update at start up",
            variable=self.check_for_updates_var,
            bootstyle="round-toggle",
            command=self._save_settings
        )
        self.check_for_updates_checkbox.pack(fill="x", anchor="w", pady=(0, 10))

        ttk.Separator(lkey_qr_frame).pack(fill="x", pady=(0, 10))

        self.ftp_auto_upload_var = tk.BooleanVar()
        self.auto_upload_check = ttk.Checkbutton(lkey_qr_frame, text="Automatically Upload LKeys After Signing", variable=self.ftp_auto_upload_var, bootstyle="success-round-toggle", command=self.handle_auto_upload_toggle, state=DISABLED)
        self.auto_upload_check.pack(anchor="w", pady=(5, 10))

        self.randomize_lkey_name_var = tk.BooleanVar()
        self.randomize_lkey_name_checkbox = ttk.Checkbutton(lkey_qr_frame, text="Salt LKey File Name", variable=self.randomize_lkey_name_var, bootstyle="round-toggle", command=self._save_settings)
        self.randomize_lkey_name_checkbox.pack(anchor="w", pady=(5, 10))

        ttk.Label(lkey_qr_frame, text="Local Save Location for Signed Files (auto-organized by date):").pack(anchor="w", pady=(10, 2))
        lkey_path_frame = ttk.Frame(lkey_qr_frame)
        lkey_path_frame.pack(fill="x")
        self.legato_files_save_path_entry = ttk.Entry(lkey_path_frame, state="readonly")
        self.legato_files_save_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(lkey_path_frame, text="...", width=3, command=self.browse_for_legato_files_save_path).pack(side="left")

        # Watermark options
        watermark_frame = ttk.LabelFrame(col2, text="💎 Watermark Options (Pro Feature)", padding=15)
        watermark_frame.pack(fill="x", pady=(0, 10))
        text_watermark_frame = ttk.Frame(watermark_frame)
        text_watermark_frame.pack(fill="x", pady=(5, 10))
        self.apply_watermark_var = tk.BooleanVar()
        self.apply_watermark_checkbox = ttk.Checkbutton(text_watermark_frame, text="Apply Text Watermark:", variable=self.apply_watermark_var, bootstyle="round-toggle", command=lambda: (self.toggle_watermark_state(), self._save_settings()), state=DISABLED)
        self.apply_watermark_checkbox.pack(side="left", padx=(0, 10))
        self.watermark_entry = ttk.Entry(text_watermark_frame, state=DISABLED)
        self.watermark_entry.pack(side="left", fill="x", expand=True)
        self.watermark_entry.insert(0, "SIGNED")
        self.watermark_entry.bind("<FocusOut>", lambda e: self._save_settings())
        self.apply_logo_watermark_var = tk.BooleanVar()
        self.apply_logo_watermark_checkbox = ttk.Checkbutton(watermark_frame, text="Apply Your Logo as Watermark", variable=self.apply_logo_watermark_var, bootstyle="round-toggle", command=self._save_settings, state=DISABLED)
        self.apply_logo_watermark_checkbox.pack(anchor="w", pady=5)

        # Audit Frame
        audit_frame = ttk.LabelFrame(col2, text="💎 Secured Audit Trail (Pro Feature)", padding=15)
        audit_frame.pack(fill="x", pady=(0, 10))
        self.enable_audit_trail_var = tk.BooleanVar()
        self.enable_audit_trail_checkbox = ttk.Checkbutton(audit_frame, text="Tracks signing and upload events in a cryptosealed audit trail.", variable=self.enable_audit_trail_var, bootstyle="info-round-toggle", command=self._save_settings, state=DISABLED)
        self.enable_audit_trail_checkbox.pack(anchor="w", fill="x", pady=(5, 5))

        # Document mask settings
        doc_num_settings_frame = ttk.LabelFrame(col2, text="💎 Document Number Mask (Pro Feature)", padding=15)
        doc_num_settings_frame.pack(fill="x")
        self.mask_entry_settings = ttk.Entry(doc_num_settings_frame, state=DISABLED)
        self.mask_entry_settings.insert(0, "####-MM/YYYY")
        self.mask_entry_settings.pack(fill="x", pady=(5, 2))
        self.mask_entry_settings.bind("<FocusOut>", lambda e: self._save_settings())

        ttk.Label(doc_num_settings_frame, text="Format: YYYY (year), YY,MM, DD, #### (auto-incrementing number)", bootstyle="secondary").pack(anchor="w", pady=(0, 2))
        self.mask_sample_label = ttk.Label(doc_num_settings_frame, text="Sample: ####-MM/YYYY", bootstyle="secondary")
        self.mask_sample_label.pack(anchor="w")

        # Bind ftp entries to change handler
        for entry in [getattr(self, name) for name in ("ftp_host_entry", "ftp_user_entry", "ftp_pass_entry", "ftp_path_entry")]:
            entry.bind("<KeyRelease>", self.on_ftp_settings_change)

    def _create_backup_and_security_tab(self, parent_frame):
        """Builds the Backup tab layout. Behavior preserved."""
        parent_frame.grid_columnconfigure(0, weight=1)
        main_container = ttk.Frame(parent_frame)
        main_container.grid(row=0, column=0, sticky="new")
        main_container.grid_columnconfigure((0, 1), weight=1, uniform="backup_cols")

        # LEFT COLUMN
        left_column = ttk.Frame(main_container)
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        practices_frame = ttk.LabelFrame(left_column, text="🔐 Security Best Practices", padding=15)
        practices_frame.pack(fill="x", pady=(0, 15), anchor="n")
        ttk.Label(practices_frame, text="⚠️ IMPORTANT BACKUP NOTICE", bootstyle="warning", font="-weight bold").pack(anchor="w")
        notice_label = ttk.Label(practices_frame, text="Your private key file (abracadabra...key) and your settings file (opn_czami_settings.json) are your digital identity. If you lose them, you lose the ability to create new LegatoKeys. You MUST create a secure, offline backup.", justify="left")
        notice_label.pack(fill="x", anchor="w", pady=(2, 10))
        ttk.Label(practices_frame, text="Essential Security Rules", font="-weight bold").pack(anchor="w", pady=(5, 2))
        ttk.Label(practices_frame, text="• Guard Your Private Key: Treat it like a master password.\n• Never Share Key Files: Do not email or upload your private key file.\n• Regular Backups: You are responsible for maintaining secure backups.\n• Use Strong Passwords: Protect backup files with strong, unique passwords.", justify="left").pack(anchor="w", pady=2)
        practices_frame.bind("<Configure>", lambda e, w=notice_label: self._update_wraplength(e, w))

        backup_frame = ttk.LabelFrame(practices_frame, text="Create Secure Encrypted Backup", padding=15)
        backup_frame.pack(fill="x", pady=(10, 20), anchor="n")
        backup_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(backup_frame, text="Backup Password:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=1)
        self.backup_pass_entry = ttk.Entry(backup_frame, show="*")
        self.backup_pass_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ttk.Checkbutton(backup_frame, text="Show", variable=self.backup_show_pass_var, bootstyle="toolbutton", command=lambda: self.backup_pass_entry.config(show="" if self.backup_show_pass_var.get() else "*")).grid(row=0, column=2, padx=5)

        self.create_backup_button = ttk.Button(backup_frame, text="📦 Create Secure Backup...", command=self.handle_create_backup)
        self.create_backup_button.grid(row=1, column=0, columnspan=3, sticky="ew", pady=1)

        if not PYZIPPER_AVAILABLE:
            self.backup_pass_entry.config(state=DISABLED)
            self.create_backup_button.config(state=DISABLED)
            ttk.Label(backup_frame, text="Requires 'pyzipper'", bootstyle="danger", font="-size 8").grid(row=2, column=0, columnspan=3)

        # RIGHT COLUMN
        right_column = ttk.Frame(main_container)
        right_column.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        tech_security_frame = ttk.LabelFrame(right_column, text="✨ Built-in Security Features", padding=15)
        tech_security_frame.pack(fill="x", expand=False, anchor="n")

        security_features = [
            ("Industry-Standard Encryption", "All server communications use robust Transport Layer Security (TLS 1.2+) to protect data in transit."),
            ("Modern Cryptography", "Utilizes NIST-approved algorithms, including Ed25519 for digital signatures and SHA-256 for data integrity."),
            ("Local Key Processing", "Your private key never leaves your computer. All signing operations happen locally."),
            ("Tamper Detection", "Each LegatoKey includes a cryptographic signature that detects any unauthorized changes to its content and source image."),
            ("Audit Trail (Pro)", "When enabled, a blockchain-like audit file is created, logging each key creation. Any attempt to tamper with this evidence is detected and reported."),
        ]

        for i, (title, description) in enumerate(security_features):
            padding_top = 15 if i > 0 else 0
            item_frame = ttk.Frame(tech_security_frame)
            item_frame.pack(fill="x", anchor="w", pady=(padding_top, 0))
            ttk.Label(item_frame, text=title, font="-weight bold").pack(anchor="w", pady=(0, 2))
            desc_label = ttk.Label(item_frame, text=description, justify="left")
            desc_label.pack(fill="x", anchor="w", padx=(10, 0))
            item_frame.bind("<Configure>", lambda e, w=desc_label: self._update_wraplength(e, w))

    # --- HANDLERS / UTILITIES  ---

    def toggle_password_visibility(self):
        """Toggles the visibility of the FTP password entry field."""
        self.ftp_pass_entry.config(show="" if self.show_pass_var.get() else "*")

    def sync_ui_from_config(self, config, priv_key_pem: str):
        # FTP host/user/path
        self.ftp_host_entry.delete(0, END)
        self.ftp_host_entry.insert(0, config.ftp_host)
        self.ftp_user_entry.delete(0, END)
        self.ftp_user_entry.insert(0, config.ftp_user)
        self.ftp_path_entry.delete(0, END)
        self.ftp_path_entry.insert(0, config.ftp_path)

        # FTP password
        password = self.logic.get_ftp_password_for_display()
        self.ftp_pass_entry.delete(0, END)
        self.ftp_pass_entry.insert(0, password)

        # Watermark text
        current_state = self.watermark_entry.cget("state")
        self.watermark_entry.config(state=NORMAL)
        self.watermark_entry.delete(0, END)
        self.watermark_entry.insert(0, config.watermark_text or "SIGNED")
        self.watermark_entry.config(state=current_state)

        # Save path
        self.legato_files_save_path_entry.config(state=NORMAL)
        self.legato_files_save_path_entry.delete(0, END)
        self.legato_files_save_path_entry.insert(0, config.legato_files_save_path)
        self.legato_files_save_path_entry.config(state="readonly")

        # Boolean vars
        # REFACTOR FOR BUG #3: hardened_security is now automatic - no user toggle needed
        self.enable_audit_trail_var.set(config.enable_audit_trail)
        self.ftp_auto_upload_var.set(config.ftp_auto_upload)
        self.apply_watermark_var.set(config.apply_watermark)
        self.apply_logo_watermark_var.set(config.apply_logo_watermark)
        self.randomize_lkey_name_var.set(config.randomize_lkey_name)
        self.check_for_updates_var.set(config.check_for_updates)
        # Insights logging (default to False - disabled until user explicitly enables it)
        self.enable_insights_logging_var.set(getattr(config, 'enable_insights_logging', False))

        # Document mask
        current_mask_state = self.mask_entry_settings.cget("state")
        self.mask_entry_settings.config(state=NORMAL)
        self.mask_entry_settings.delete(0, END)
        self.mask_entry_settings.insert(0, config.doc_num_mask or "####-MM/YYYY")
        self.mask_entry_settings.config(state=current_mask_state)
        self._update_mask_sample_label()

        self.on_ftp_settings_change(pristine=True)
        logging.info("Settings tabs synced from configuration.")

    def get_ui_config_data(self) -> dict:
        """
        Gathers the current configuration data from all UI 
        """
        return {
            "ftp_host": self.ftp_host_entry.get(),
            "ftp_user": self.ftp_user_entry.get(),
            "ftp_path": self.ftp_path_entry.get(),
            "ftp_password": self.ftp_pass_entry.get(),
            "watermark_text": self.watermark_entry.get(),
            "legato_files_save_path": self.legato_files_save_path_entry.get(),
            # REFACTOR FOR BUG: hardened_security no longer a config field - determined by actual key location
            "enable_audit_trail": self.enable_audit_trail_var.get(),
            "ftp_auto_upload": self.ftp_auto_upload_var.get(),
            "apply_watermark": self.apply_watermark_var.get(),
            "apply_logo_watermark": self.apply_logo_watermark_var.get(),
            "randomize_lkey_name": self.randomize_lkey_name_var.get(),
            "doc_num_mask": self.mask_entry_settings.get(),
            "check_for_updates": self.check_for_updates_var.get(),
            "enable_insights_logging": self.enable_insights_logging_var.get(),
        }

    def handle_insights_logging_toggle(self):
        """
        Handler for insights logging toggle.
        Saves settings locally and uploads updated config to server.
        """
        # Fix delay to let Tkinter update the variable first
        root = self.notebook.winfo_toplevel()
        root.after(10, self._process_insights_logging_toggle)

    def _process_insights_logging_toggle(self):
        """Process the toggle after the variable has been updated"""
        # Now read the NEW state (updated by Tkinter)
        new_enabled_state = self.enable_insights_logging_var.get()

        # First save the settings locally
        self._save_settings()

        # Then upload the updated config to the server asynchronously
        threading.Thread(
            target=self._update_server_logging_config_threaded,
            args=(new_enabled_state,),
            daemon=True
        ).start()

    def _update_server_logging_config_threaded(self, enabled_state: bool):
        """
        Updates the .insights-config.json file on the server with new logging state.
        """
        try:
            success, message = self.logic.update_server_insights_config(enabled_state)

            if success:
                logging.info(f"Server logging config synced: {message}")
            else:
                logging.error(f"Server logging config failed: {message}")

                # IMPORTANT: Rollback the checkbox state since the server update failed
                root = self.notebook.winfo_toplevel()
                root.after(100, lambda: self.enable_insights_logging_var.set(not enabled_state))

        except Exception as e:
            error_msg = f"Unexpected error updating logging config: {str(e)}"
            logging.error(error_msg, exc_info=True)

            # Rollback checkbox state on exception
            root = self.notebook.winfo_toplevel()
            root.after(100, lambda: self.enable_insights_logging_var.set(not enabled_state))

    def _save_settings(self):
        ui_data = self.get_ui_config_data()
        ftp_password = ui_data.pop("ftp_password")
        self.logic.sync_and_save_settings(ui_data, ftp_password)

    def handle_save_settings_and_upload_threaded(self):
        self._save_settings()
        self.save_and_upload_button.config(state=DISABLED, text="Working...")
        threading.Thread(target=self._save_and_upload_worker, daemon=True).start()

    def _save_and_upload_worker(self):
        ftp_settings = self.logic.get_ftp_settings_for_connection()
        if not ftp_settings:
            self.settings_tab_frame.after(0, lambda: show_error("FTP Error", "FTP settings are incomplete or password is missing."))
            self.settings_tab_frame.after(0, self.save_and_upload_button.config, {'state': NORMAL, 'text': "✔️ Save Settings & Upload Public Files"})
            return

        # Extract only params test_connection needs (exclude ftp_root)
        is_success, message = self.logic.ftp_manager.test_connection(
            host=ftp_settings['host'],
            user=ftp_settings['user'],
            password=ftp_settings['password']
        )
        if not is_success:
            self.settings_tab_frame.after(0, lambda: show_error("Connection Failed", f"Could not connect to FTP.\n\nError: {message}"))
            self.settings_tab_frame.after(0, self.save_and_upload_button.config, {'state': NORMAL, 'text': "✔️ Save Settings & Upload Public Files"})
            return

        upload_success, upload_msg = self.logic.upload_public_files()

        def update_ui():
            if upload_success:
                self.save_and_upload_button.config(state=DISABLED, text="✔️ Saved & Uploaded!")
                self.logic.reload_data_and_update_ui() 
                self.logic.check_system_status_threaded()
            else:
                show_error("Upload Failed", upload_msg)
                self.save_and_upload_button.config(state=NORMAL, text="✔️ Save Settings & Upload Public Files")

        self.settings_tab_frame.after(0, update_ui)

    def on_ftp_settings_change(self, *args, pristine=False):
        state = DISABLED if pristine else NORMAL
        self.save_and_upload_button.config(state=state, text="✔️ Save Settings & Upload Public Files")
        self._update_ftp_dependent_widgets_state()

    def update_ui_state(self, has_identity: bool):
        """
        Updates UI widgets to reflect current application state.
        """
        # General UI state updates
        is_watermark = self.logic.license_manager.is_feature_enabled(FEATURE_WATERMARK)
        is_audit = self.logic.license_manager.is_feature_enabled(FEATURE_AUDIT)
        is_masking = self.logic.license_manager.is_feature_enabled(FEATURE_MASKED_IDS)
        state = NORMAL if has_identity else DISABLED

        self.randomize_lkey_name_checkbox.config(state=state)

        self.apply_watermark_checkbox.config(state=state if is_watermark else DISABLED)
        self.apply_logo_watermark_checkbox.config(state=state if is_watermark else DISABLED)
        self.enable_audit_trail_checkbox.config(state=state if is_audit else DISABLED)
        self.create_backup_button.config(state=state)
        self.mask_entry_settings.config(state=state if is_masking else DISABLED)

        if not (has_identity and is_masking):
            self.mask_entry_settings.delete(0, END)
            self.mask_sample_label.config(text="Sample: Pro feature")
        else:
            self._update_mask_sample_label()

        self.toggle_watermark_state()
        self._update_ftp_dependent_widgets_state()

    def handle_auto_upload_toggle(self):
        self._save_settings()

        try:
            self.logic.ui_callback.tabs["core"].update_auto_upload_indicator()
        except Exception as e:
            logging.debug(f"Could not update auto upload indicator: {e}")
            pass

    def _update_mask_sample_label(self, *args):
        try:
            sample = self.logic._apply_number_mask(self.mask_entry_settings.get())
            self.mask_sample_label.config(text=f"Sample: {sample}")
        except Exception:
            self.mask_sample_label.config(text="Sample: Invalid Mask")

    def handle_auto_sense_threaded(self):
        """
        Starts the background process to auto-sense FTP web root.
        """
        host, user, password = self.ftp_host_entry.get(), self.ftp_user_entry.get(), self.ftp_pass_entry.get()
        if not all([host, user, password]):
            return show_info("Missing Info", "Please fill in FTP Host, User, and Password.")
        self.sense_button.config(state=DISABLED, text="Sensing...")
        self.ftp_path_entry.config(state=DISABLED)
        threading.Thread(target=self._sense_ftp_root_worker, args=(host, user, password), daemon=True).start()

    def _sense_ftp_root_worker(self, host, user, password):
        try:
            success, result = self.logic.ftp_manager.find_web_root(host, user, password)
        except Exception as e:
            logging.error(f"Auto-sense failed with exception: {e}")
            success = False
            result = f"Error: {e}"

        def update_ui():
            if success:
                self.ftp_path_entry.delete(0, END)
                self.ftp_path_entry.insert(0, result)
                show_info("Path Found!", f"Found web root: {result}\nSaving settings and uploading files.")
                self.handle_save_settings_and_upload_threaded()
            else:
                show_error("Auto-Sense Failed", result)
                self.save_and_upload_button.config(state=NORMAL)
            self.sense_button.config(state=NORMAL, text="🔎 Auto-Sense")
            self.ftp_path_entry.config(state=NORMAL)

        self.settings_tab_frame.after(0, update_ui)

    def handle_create_backup(self):
        if not self.logic.active_issuer_id:
            return
        password = self.backup_pass_entry.get()
        if PYZIPPER_AVAILABLE and not password:
            return show_error("Password Required", "A password is required for backups.")

        default_filename = f"opn-czami-backup-{self.logic.active_issuer_id}-{datetime.date.today()}.zip"
        save_path_str = filedialog.asksaveasfilename(title="Save Secure Backup", defaultextension=".zip", initialfile=default_filename)
        if not save_path_str:
            return

        threading.Thread(target=self._backup_worker, args=(password, save_path_str), daemon=True).start()

    def _backup_worker(self, password: str, save_path_str: str):
        success, message, parent_path = self.logic.create_secure_backup(password, save_path_str)

        def update_ui():
            self.backup_pass_entry.delete(0, END)
            if success:
                show_info("Backup Successful", f"{message}\n\nLocation: {parent_path}")
                if parent_path:
                    try:
                        webbrowser.open(Path(parent_path).resolve().as_uri())
                    except Exception as e:
                        logging.warning(f"Could not open backup folder: {e}")
                        pass
            else:
                show_error("Backup Failed", message)

        self.security_tab_frame.after(0, update_ui)

    def _update_ftp_dependent_widgets_state(self, *args):
        """Enable/disable FTP-dependent widgets based on validity of FTP settings."""
        is_valid = all([self.ftp_host_entry.get(), self.ftp_user_entry.get(), self.ftp_pass_entry.get(), self.ftp_path_entry.get()])
        self.auto_upload_check.config(state=NORMAL if is_valid else DISABLED)
        if not is_valid:
            self.ftp_auto_upload_var.set(False)

    def toggle_watermark_state(self):
        """Togle watermark text entry based on license and checkbox state."""
        is_licensed = self.logic.license_manager.is_feature_enabled(FEATURE_WATERMARK)
        state = NORMAL if self.apply_watermark_var.get() and is_licensed else DISABLED
        self.watermark_entry.config(state=state)        

    def browse_for_legato_files_save_path(self):
        if new_path := filedialog.askdirectory(title="Select Folder"):
            self.legato_files_save_path_entry.config(state=NORMAL)
            self.legato_files_save_path_entry.delete(0, END)
            self.legato_files_save_path_entry.insert(0, new_path)
            self.legato_files_save_path_entry.config(state="readonly")
            self._save_settings()