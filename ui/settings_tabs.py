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


# --- Standard Library Imports ---
import base64
import datetime
import logging
import threading
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

# --- Third-Party Imports ---
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# --- Local Imports ---
from opn_czami_logic import OpnCzamiLogic
from models.utils import show_error, show_info
from models.config import FEATURE_WATERMARK, FEATURE_AUDIT, FEATURE_MASKED_IDS, FEATURE_WEB3

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except Exception:
    PYZIPPER_AVAILABLE = False


class SettingsTabs:
    """
    Manages the application's configuration tabs: 'Settings' and 'Backup & Security'.
    This refactor preserves all original public method names and widget attributes
    so existing UI callbacks and OpnCzamiLogic integrations continue to work.
    """

    def _update_wraplength(self, event, label_widget):
        """Helper to dynamically adjust the wraplength of a label."""
        label_widget.config(wraplength=event.width - 20)

    def __init__(self, notebook: ttk.Notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic

        # Tk variables kept with identical names so external code can reference them
        self.check_for_updates_var = ttk.BooleanVar()
        self.show_pass_var = ttk.BooleanVar(value=False)
        self.backup_show_pass_var = ttk.BooleanVar(value=False)

        # Create frames
        self.settings_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.security_tab_frame = ttk.Frame(self.notebook, padding=10)

        # Build UI
        self._create_settings_and_uploads_tab(self.settings_tab_frame)
        self._create_backup_and_security_tab(self.security_tab_frame)

        # Add tabs
        self.notebook.add(self.settings_tab_frame, text=" 3. Settings ")
        self.notebook.add(self.security_tab_frame, text=" 4. Backup & Security ")

    # --- CALLBACKS FROM LOGIC LAYER (preserve signatures) ---

    def on_managed_anchor_complete(self, success: bool, message: str):
        """Called by the logic layer after any managed anchor operation finishes."""
        # Reset all buttons to the unpressed state
        try:
            self.activate_anchor_button.config(state=NORMAL, text="Activate Managed Anchor")
            self.update_anchor_button.config(state=NORMAL, text="🔄 Update Anchor")
            self.deactivate_anchor_button.config(state=NORMAL, text="❌ Deactivate Anchor")
        except Exception:
            # defensive: if widgets not yet created, ignore
            pass

        if success:
            show_info("Operation Successful", message)
        else:
            show_error("Operation Failed", message)

        # Reload the UI to reflect the new state (Active, Not Activated, etc.)
        self.logic.reload_data_and_update_ui()

    def on_byok_complete(self, success: bool, message: str):
        """Callback for when the BYOK activation process finishes."""
        try:
            self.byok_publish_button.config(state=NORMAL, text="Publish to Custom Anchor")
        except Exception:
            pass

        if success:
            show_info("Success", message)
        else:
            show_error("Failed", message)

        self.logic.reload_data_and_update_ui()

    # --- WEB3 MANAGEMENT HANDLERS ---

    def handle_activate_anchor(self):
        """Initial Opt-In. Calls activate endpoint."""
        if not messagebox.askyesno("Confirm Activation", "This will register and create a permanent IPFS anchor for your current identity. Proceed?"):
            return
        self.activate_anchor_button.config(state=DISABLED, text="Activating...")
        self.logic.pro_handler.activate_managed_anchor_threaded()

    def handle_update_anchor(self):
        """Updating an existing anchor. Calls update endpoint."""
        if not messagebox.askyesno("Confirm Update", "This will publish your identity's latest public file to IPFS, updating your anchor. Proceed?"):
            return
        self.update_anchor_button.config(state=DISABLED, text="Updating...")
        self.deactivate_anchor_button.config(state=DISABLED)
        self.logic.pro_handler.update_managed_anchor_threaded()

    def handle_deactivate_anchor(self):
        """Opt-Out. Calls deactivate endpoint."""
        if not messagebox.askyesno("Confirm Deactivation", "WARNING: This will permanently de-list your IPFS anchor from the registry and generate a new license key. Are you sure?"):
            return
        self.deactivate_anchor_button.config(state=DISABLED, text="Deactivating...")
        self.update_anchor_button.config(state=DISABLED)
        self.logic.pro_handler.deactivate_managed_anchor_threaded()

    # --- BYOK / TOGGLE HANDLERS ---

    def _toggle_byok_fields_visibility(self):
        """Master logic for switching between Managed and Custom modes."""
        is_activating_byok = self.byok_var.get()

        # Toggle the visibility of the fields
        if is_activating_byok:
            self.byok_fields_frame.pack(fill="x", pady=(10, 0))
        else:
            self.byok_fields_frame.pack_forget()

        # Trigger the logic layer to revert the state if the user is opting out of BYOK
        if not is_activating_byok:
            # Check if the anchor source was 'custom' before reverting
            if self.logic.active_issuer_data.get("settings", {}).get("anchor_source") == "custom":
                # Preserve behavior: call the logic method that reverts
                self.logic.revert_to_managed_anchor_threaded()

        # Update UI state
        self.update_ui_state(has_identity=bool(self.logic.active_issuer_id))

    def handle_byok_publish(self):
        """Handler for the 'Publish to Custom Anchor' button."""
        if not self.logic.active_issuer_id:
            show_error("Action Blocked", "Please create or load an identity first.")
            return

        if not self.logic.system_is_verified:
            show_error("Action Blocked", "Please ensure your system status is 'Online & Verified' before publishing a custom anchor.")
            return

        # Gather the credentials from the UI
        creds = {
            "bucket": self.filebase_bucket_entry.get(),
            "key": self.filebase_key_entry.get(),
            "secret": self.filebase_secret_entry.get()
        }
        if not all(creds.values()):
            show_error("Missing Credentials", "Please fill in all Filebase credential fields.")
            return

        # Disable the button to prevent multiple clicks
        self.byok_publish_button.config(state=DISABLED, text="Publishing...")

        # Call the logic handler
        self.logic.handle_byok_publish_threaded(creds)

    # --- UI CREATION ---

    def _create_settings_and_uploads_tab(self, parent_frame):
        """Builds the full settings tab; layout preserved to avoid behavioral changes."""
        parent_frame.grid_columnconfigure(0, weight=1)
        top_columns_container = ttk.Frame(parent_frame)
        top_columns_container.grid(row=0, column=0, sticky="new")
        top_columns_container.grid_columnconfigure((0, 1), weight=1, uniform="settings_group")

        # LEFT COLUMN
        left_column = ttk.Frame(top_columns_container)
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Connection frame
        connection_frame = ttk.LabelFrame(left_column, text="🚀 Connection & Uploads", padding=15)
        connection_frame.pack(fill="x", pady=(0, 10), anchor='n')
        connection_frame.grid_columnconfigure(1, weight=1)

        row = 0
        ttk.Label(connection_frame, text="Step 1: Enter FTP Server Credentials", font="-weight bold").grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 10))
        row += 1

        ttk.Label(connection_frame, text="Username:").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_user_entry = ttk.Entry(connection_frame)
        self.ftp_user_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        row += 1

        ttk.Label(connection_frame, text="Password:").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_pass_entry = ttk.Entry(connection_frame, show="*")
        self.ftp_pass_entry.grid(row=row, column=1, sticky="ew", pady=4, ipady=2)
        self.show_pass_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(connection_frame, text="Show", variable=self.show_pass_var, command=self.toggle_password_visibility, bootstyle="toolbutton").grid(row=row, column=2, sticky="w", padx=5)
        row += 1

        ttk.Separator(connection_frame).grid(row=row, column=0, columnspan=3, sticky="ew", pady=15)
        row += 1

        ttk.Label(connection_frame, text="Step 2: Set FTP Address & Path", font="-weight bold").grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 10))
        row += 1

        ttk.Label(connection_frame, text="FTP Host:").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_host_entry = ttk.Entry(connection_frame)
        self.ftp_host_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        row += 1

        ttk.Label(connection_frame, text="Web Root Path:").grid(row=row, column=0, sticky="w", padx=(0, 10), pady=(10, 4))
        path_entry_frame = ttk.Frame(connection_frame)
        path_entry_frame.grid(row=row, column=1, columnspan=2, sticky="ew", pady=(10, 4))
        self.ftp_path_entry = ttk.Entry(path_entry_frame)
        self.ftp_path_entry.pack(side="left", fill="x", expand=True, ipady=2, padx=(0, 5))
        self.sense_button = ttk.Button(path_entry_frame, text="🔎 Auto-Sense", command=self.handle_auto_sense_threaded, bootstyle="outline-info")
        self.sense_button.pack(side="left")
        row += 1

        self.save_and_upload_button = ttk.Button(connection_frame, text="✔️ Save Settings & Upload Public Files", command=self.handle_save_settings_and_upload_threaded, bootstyle=PRIMARY, state=DISABLED)
        self.save_and_upload_button.grid(row=row, column=0, columnspan=3, sticky="ew", ipady=5, pady=(20, 0))
        row += 1

        # Update checker
        update_check_frame = ttk.Frame(left_column)
        update_check_frame.pack(fill="x", pady=(10, 0))

        self.check_for_updates_checkbox = ttk.Checkbutton(
            update_check_frame,
            text="Auto-check for updates at startup",
            variable=self.check_for_updates_var,
            bootstyle="round-toggle",
            command=self._save_settings
        )
        self.check_for_updates_checkbox.pack(fill="x", padx=5, pady=5)

        # Web3 Frame
        web3_frame = ttk.LabelFrame(left_column, text="🌐 IPFS Anchor Mode", padding=15)
        web3_frame.pack(fill="x", pady=(10, 0), anchor='n')

        self.enable_web3_var = ttk.BooleanVar()
        self.enable_web3_checkbox = ttk.Checkbutton(
            web3_frame,
            text="Enable Web3 / IPFS Anchor Features",
            variable=self.enable_web3_var,
            bootstyle="primary-round-toggle",
            command=self._on_toggle_web3_section
        )
        self.enable_web3_checkbox.pack(fill="x", pady=(0, 10))

        self.web3_controls_container = ttk.Frame(web3_frame)
        self.anchor_mode_var = ttk.StringVar(value="managed")

        mode_frame = ttk.Frame(self.web3_controls_container)
        mode_frame.pack(fill="x", pady=(0, 10))

        ttk.Radiobutton(
            mode_frame,
            text="Managed Anchor (Pro Feature)",
            variable=self.anchor_mode_var,
            value="managed",
            command=self._on_anchor_mode_change
        ).pack(side="left", padx=(0, 20))

        ttk.Radiobutton(
            mode_frame,
            text="Custom Anchor (Free - BYOK)",
            variable=self.anchor_mode_var,
            value="custom",
            command=self._on_anchor_mode_change
        ).pack(side="left")

        ttk.Separator(self.web3_controls_container).pack(fill="x", pady=(5, 15))

        # Managed controls
        self.managed_controls_frame = ttk.Frame(self.web3_controls_container)
        self.managed_controls_frame.pack(fill="x")

        self.managed_status_label = ttk.Label(self.managed_controls_frame, text="Status: Pro license required.", bootstyle="secondary")
        self.managed_status_label.pack(fill="x", pady=(0, 10))

        button_row_frame = ttk.Frame(self.managed_controls_frame)
        button_row_frame.pack(fill="x")
        self.activate_anchor_button = ttk.Button(button_row_frame, text="Activate Managed Anchor", command=self.handle_activate_anchor, bootstyle="success")
        self.update_anchor_button = ttk.Button(button_row_frame, text="🔄 Update Anchor", command=self.handle_update_anchor, bootstyle="info")
        self.deactivate_anchor_button = ttk.Button(button_row_frame, text="❌ Deactivate Anchor", command=self.handle_deactivate_anchor, bootstyle="danger")

        # Custom (BYOK) controls (hidden by default)
        self.custom_controls_frame = ttk.Frame(self.web3_controls_container)
        self.custom_controls_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(self.custom_controls_frame, text="Filebase Bucket:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=4)
        self.filebase_bucket_entry = ttk.Entry(self.custom_controls_frame)
        self.filebase_bucket_entry.grid(row=0, column=1, sticky="ew")

        ttk.Label(self.custom_controls_frame, text="Filebase Key:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=4)
        self.filebase_key_entry = ttk.Entry(self.custom_controls_frame)
        self.filebase_key_entry.grid(row=1, column=1, sticky="ew")

        ttk.Label(self.custom_controls_frame, text="Filebase Secret:").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=4)
        self.filebase_secret_entry = ttk.Entry(self.custom_controls_frame, show="*")
        self.filebase_secret_entry.grid(row=2, column=1, sticky="ew")

        self.byok_publish_button = ttk.Button(self.custom_controls_frame, text="Publish to Custom Anchor", command=self.handle_byok_publish, bootstyle="info-outline")
        self.byok_publish_button.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(15, 0))

        # RIGHT COLUMN
        right_container = ttk.Frame(top_columns_container)
        right_container.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        # Signing & Saving options
        lkey_qr_frame = ttk.LabelFrame(right_container, text="⚙️ Signing & Saving Options", padding=15)
        lkey_qr_frame.pack(fill="x", pady=(0, 10))

        self.ftp_auto_upload_var = ttk.BooleanVar()
        self.auto_upload_check = ttk.Checkbutton(lkey_qr_frame, text="Automatically Upload LKeys After Signing", variable=self.ftp_auto_upload_var, bootstyle="success-round-toggle", command=self.handle_auto_upload_toggle, state=DISABLED)
        self.auto_upload_check.pack(anchor="w", pady=(5, 10))

        self.randomize_lkey_name_var = ttk.BooleanVar()
        self.randomize_lkey_name_checkbox = ttk.Checkbutton(lkey_qr_frame, text="Salt LKey File Name", variable=self.randomize_lkey_name_var, bootstyle="round-toggle", command=self._save_settings)
        self.randomize_lkey_name_checkbox.pack(anchor="w", pady=(5, 10))

        ttk.Label(lkey_qr_frame, text="Local Save Location for Signed Files (auto-organized by date):").pack(anchor="w", pady=(10, 2))
        lkey_path_frame = ttk.Frame(lkey_qr_frame)
        lkey_path_frame.pack(fill="x")
        self.legato_files_save_path_entry = ttk.Entry(lkey_path_frame, state="readonly")
        self.legato_files_save_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(lkey_path_frame, text="...", width=3, command=self.browse_for_legato_files_save_path).pack(side="left")

        # Watermark options
        watermark_frame = ttk.LabelFrame(right_container, text="🖼️ Watermark Options (Pro Feature)", padding=15)
        watermark_frame.pack(fill="x", pady=(0, 10))
        text_watermark_frame = ttk.Frame(watermark_frame)
        text_watermark_frame.pack(fill="x", pady=(5, 10))

        self.apply_watermark_var = ttk.BooleanVar()
        self.apply_watermark_checkbox = ttk.Checkbutton(text_watermark_frame, text="Apply Text Watermark:", variable=self.apply_watermark_var, bootstyle="round-toggle", command=lambda: (self.toggle_watermark_state(), self._save_settings()), state=NORMAL)
        self.apply_watermark_checkbox.pack(side="left", padx=(0, 10))

        self.watermark_entry = ttk.Entry(text_watermark_frame)
        self.watermark_entry.pack(side="left", fill="x", expand=True)
        self.watermark_entry.insert(0, "SIGNED")
        self.watermark_entry.bind("<FocusOut>", lambda e: self._save_settings())

        self.apply_logo_watermark_var = ttk.BooleanVar()
        self.apply_logo_watermark_checkbox = ttk.Checkbutton(watermark_frame, text="Apply Your Logo as Watermark", variable=self.apply_logo_watermark_var, bootstyle="round-toggle", command=self._save_settings)
        self.apply_logo_watermark_checkbox.pack(anchor="w", pady=5)

        # Audit Frame
        audit_frame = ttk.LabelFrame(right_container, text="💎 Secured Audit Trail (Pro Feature)", padding=15)
        audit_frame.pack(fill="x", pady=(0, 10))
        self.enable_audit_trail_var = ttk.BooleanVar()
        self.enable_audit_trail_checkbox = ttk.Checkbutton(audit_frame, text="Tracks signing and upload events in a cryptosealed audit trail.", variable=self.enable_audit_trail_var, bootstyle="info-round-toggle", command=self._save_settings)
        self.enable_audit_trail_checkbox.pack(anchor="w", fill="x", pady=(5, 5))

        # Document mask settings
        doc_num_settings_frame = ttk.LabelFrame(right_container, text="💎 Document Number Mask (Pro Feature)", padding=15)
        doc_num_settings_frame.pack(fill="x")
        self.mask_entry_settings = ttk.Entry(doc_num_settings_frame)
        self.mask_entry_settings.insert(0, "####-MM/YYYY")
        self.mask_entry_settings.pack(fill="x", pady=(5, 2))
        self.mask_entry_settings.bind("<FocusOut>", lambda e: self._save_settings())

        ttk.Label(doc_num_settings_frame, text="Format: YYYY (year), YY,MM, DD, #### (auto-incrementing number)", bootstyle="secondary").pack(anchor="w", pady=(0, 2))
        self.mask_sample_label = ttk.Label(doc_num_settings_frame, text="Sample: ####-MM/YYYY", bootstyle="secondary")
        self.mask_sample_label.pack(anchor="w")

        # Bind ftp entries to change handler
        for entry in [getattr(self, name) for name in ("ftp_host_entry", "ftp_user_entry", "ftp_pass_entry", "ftp_path_entry")]:
            entry.bind("<KeyRelease>", self.on_ftp_settings_change)

    # --- Web3 toggle and state helpers ---

    def _on_toggle_web3_section(self):
        """Shows/hides the Web3 controls and triggers the initial status check."""
        # Save immediately
        self._save_settings()

        if self.enable_web3_var.get():
            self.web3_controls_container.pack(fill="x")

            if hasattr(self.logic, "handle_web3_status_check_on_demand"):
                self.logic.handle_web3_status_check_on_demand()
        else:
            self.web3_controls_container.pack_forget()

    def _create_backup_and_security_tab(self, parent_frame):
        """Builds the Backup & Security tab layout. Behavior preserved."""
        parent_frame.grid_columnconfigure(0, weight=1)
        main_container = ttk.Frame(parent_frame)
        main_container.grid(row=0, column=0, sticky="new")
        main_container.grid_columnconfigure((0, 1), weight=1, uniform="backup_cols")

        # LEFT COLUMN
        left_column = ttk.Frame(main_container)
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        hardened_security_frame = ttk.LabelFrame(left_column, text="🛡️ Hardened Security", padding=15)
        hardened_security_frame.pack(fill="x", pady=(0, 15), anchor="n")
        self.hardened_security_var = ttk.BooleanVar()
        self.pro_security_checkbox = ttk.Checkbutton(hardened_security_frame, text="Enable Hardened Security (OS Keychain)", variable=self.hardened_security_var, bootstyle="primary-round-toggle", state=DISABLED, command=self.handle_toggle_hardened_security)
        self.pro_security_checkbox.pack(anchor="w", fill="x", pady=(5, 5))
        ttk.Label(hardened_security_frame, text="RECOMMENDED. Moves private key and FTP password to your OS's secure keychain.", wraplength=400, bootstyle="secondary").pack(anchor="w")

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

        tech_security_frame = ttk.LabelFrame(right_column, text="🛡️ Built-in Security Features", padding=15)
        tech_security_frame.pack(fill="x", expand=False, anchor="n")

        security_features = [
            ("Industry-Standard Encryption", "All server communications use robust Transport Layer Security (TLS 1.2+) to protect data in transit."),
            ("Secure Credential Storage", "Your private key and passwords can be stored in the OS Keychain, never in plain text files, when Hardened Security is enabled."),
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
        self.watermark_entry.delete(0, END)
        self.watermark_entry.insert(0, config.watermark_text)

        # Save path
        self.legato_files_save_path_entry.config(state=NORMAL)
        self.legato_files_save_path_entry.delete(0, END)
        self.legato_files_save_path_entry.insert(0, config.legato_files_save_path)
        self.legato_files_save_path_entry.config(state="readonly")

        # Boolean vars
        self.hardened_security_var.set(config.hardened_security)
        self.enable_audit_trail_var.set(config.enable_audit_trail)
        self.ftp_auto_upload_var.set(config.ftp_auto_upload)
        self.apply_watermark_var.set(config.apply_watermark)
        self.apply_logo_watermark_var.set(config.apply_logo_watermark)
        self.randomize_lkey_name_var.set(config.randomize_lkey_name)
        self.check_for_updates_var.set(config.check_for_updates)

        # Document mask
        self.mask_entry_settings.delete(0, END)
        self.mask_entry_settings.insert(0, config.doc_num_mask)
        self._update_mask_sample_label()

        self.on_ftp_settings_change(pristine=True)
        logging.info("Settings tabs synced from configuration.")

        # Load and display Filebase credentials
        try:
            fb_key, fb_secret = self.logic.crypto_manager.load_filebase_credentials(self.logic.active_issuer_id)
        except Exception:
            fb_key, fb_secret = ("", "")
        fb_bucket = self.logic.active_issuer_data.get("settings", {}).get("filebase_bucket", "")

        self.filebase_bucket_entry.delete(0, END)
        self.filebase_bucket_entry.insert(0, fb_bucket or "")
        self.filebase_key_entry.delete(0, END)
        self.filebase_key_entry.insert(0, fb_key or "")
        self.filebase_secret_entry.delete(0, END)
        self.filebase_secret_entry.insert(0, fb_secret or "")

        logging.info("Settings tabs synced from configuration.")

    def get_ui_config_data(self) -> dict:
        """
        Gathers the current configuration data from all UI components in the settings tabs.
        """
        return {
            "ftp_host": self.ftp_host_entry.get(),
            "ftp_user": self.ftp_user_entry.get(),
            "ftp_path": self.ftp_path_entry.get(),
            "ftp_password": self.ftp_pass_entry.get(),
            "watermark_text": self.watermark_entry.get(),
            "legato_files_save_path": self.legato_files_save_path_entry.get(),
            "hardened_security": self.hardened_security_var.get(),
            "enable_audit_trail": self.enable_audit_trail_var.get(),
            "ftp_auto_upload": self.ftp_auto_upload_var.get(),
            "apply_watermark": self.apply_watermark_var.get(),
            "apply_logo_watermark": self.apply_logo_watermark_var.get(),
            "randomize_lkey_name": self.randomize_lkey_name_var.get(),
            "doc_num_mask": self.mask_entry_settings.get(),
            "check_for_updates": self.check_for_updates_var.get(),
        }

    def _save_settings(self):
        ui_data = self.get_ui_config_data()
        ftp_password = ui_data.pop("ftp_password")
        self.logic.sync_and_save_settings(ui_data, ftp_password)

    def handle_legacy_anchor_activation(self):
        """
        Handler for the 'Activate Your Included Web3 Anchor' button.
        """
        if not messagebox.askyesno(
            "Confirm Anchor Activation",
            "This will contact the Legato server to generate and register a permanent IPFS anchor for your identity.\n\n"
            "This is a one-time process. Do you want to proceed?"
        ):
            return

        # Disable the button to prevent multiple clicks
        self.legacy_anchor_button.config(state=DISABLED, text="Activating...")
        self.logic.handle_legacy_anchor_activation_threaded()

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

        is_success, message = self.logic.ftp_manager.test_connection(**ftp_settings)
        if not is_success:
            self.settings_tab_frame.after(0, lambda: show_error("Connection Failed", f"Could not connect to FTP.\n\nError: {message}"))
            self.settings_tab_frame.after(0, self.save_and_upload_button.config, {'state': NORMAL, 'text': "✔️ Save Settings & Upload Public Files"})
            return

        upload_success, upload_msg = self.logic.upload_public_files()

        def update_ui():
            if upload_success:
                show_info("Upload Complete", upload_msg)
                # preserve behavior: kick off status check
                self.logic.check_system_status_threaded()
                self.save_and_upload_button.config(state=DISABLED, text="✔️ Saved & Uploaded!")
            else:
                show_error("Upload Failed", upload_msg)
                self.save_and_upload_button.config(state=NORMAL, text="✔️ Save Settings & Upload Public Files")

        self.settings_tab_frame.after(0, update_ui)

    def on_ftp_settings_change(self, *args, pristine=False):
        state = DISABLED if pristine else NORMAL
        self.save_and_upload_button.config(state=state, text="✔️ Save Settings & Upload Public Files")
        self._update_ftp_dependent_widgets_state()

    def _on_anchor_mode_change(self):
        """Called when the user clicks a radio button. Hides/shows the correct UI sections."""
        if self.logic.active_issuer_id:
            if "settings" not in self.logic.all_issuer_data[self.logic.active_issuer_id]:
                self.logic.all_issuer_data[self.logic.active_issuer_id]["settings"] = {}
            self.logic.all_issuer_data[self.logic.active_issuer_id]["settings"]["anchor_source"] = self.anchor_mode_var.get()
            # preserve behavior: use settings_manager save directly
            self.logic.settings_manager.save_app_data(self.logic.all_issuer_data)

        # Trigger a full UI state update
        self.update_ui_state(bool(self.logic.active_issuer_id))

    def update_ui_state(self, has_identity: bool):
        """
        Updates UI widgets to reflect current application state.

        """
        if has_identity:
            saved_mode = self.logic.active_issuer_data.get("settings", {}).get("anchor_source", "managed")
            self.anchor_mode_var.set(saved_mode)

        # Hide all anchor related controls then re-show appropriate ones
        try:
            self.activate_anchor_button.pack_forget()
            self.update_anchor_button.pack_forget()
            self.deactivate_anchor_button.pack_forget()
            self.managed_controls_frame.pack_forget()
            self.custom_controls_frame.pack_forget()
        except Exception:
            pass 

        is_licensed_pro = self.logic.license_manager.is_licensed
        has_web3_feature = self.logic.license_manager.is_feature_enabled(FEATURE_WEB3)
        is_already_anchored = self.logic.active_issuer_data.get("ipfsCid") is not None

        selected_mode = self.anchor_mode_var.get()

        if selected_mode == 'custom':
            # Show custom UI
            self.custom_controls_frame.pack(fill="x", pady=(10, 0))
        else:
            # Show managed UI
            self.managed_controls_frame.pack(fill="x")

            if has_identity and is_licensed_pro and has_web3_feature:
                if is_already_anchored:
                    self.managed_status_label.config(text="Status: Active (Managed Service)", bootstyle="success")
                    self.update_anchor_button.pack(side="left", fill="x", expand=True, padx=(0, 5))
                    self.deactivate_anchor_button.pack(side="left", fill="x", expand=True)
                else:
                    self.managed_status_label.config(text="Status: Activation Required", bootstyle="info")
                    self.activate_anchor_button.pack(fill="x")
            elif has_identity and not is_licensed_pro:
                self.managed_status_label.config(text="Status: Pro license required.", bootstyle="secondary")
            else:
                self.managed_status_label.config(text="Status: Load an identity to see status.", bootstyle="secondary")

        # General UI state updates for other widgets
        is_watermark = self.logic.license_manager.is_feature_enabled(FEATURE_WATERMARK)
        is_audit = self.logic.license_manager.is_feature_enabled(FEATURE_AUDIT)
        is_masking = self.logic.license_manager.is_feature_enabled(FEATURE_MASKED_IDS)
        state = NORMAL if has_identity else DISABLED

        # Disable the radio buttons if no identity is loaded
        try:
            for radio in self.managed_controls_frame.master.winfo_children():
                if isinstance(radio, ttk.Radiobutton):
                    radio.config(state=state)
        except Exception:
            pass

        self.pro_security_checkbox.config(state=state)
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
        except Exception:
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
        Behavior preserved: calls ftp_manager.find_web_root and then save/upload.
        """
        host, user, password = self.ftp_host_entry.get(), self.ftp_user_entry.get(), self.ftp_pass_entry.get()
        if not all([host, user, password]):
            return show_info("Missing Info", "Please fill in FTP Host, User, and Password.")
        self.sense_button.config(state=DISABLED, text="Sensing...")
        self.ftp_path_entry.config(state=DISABLED)
        threading.Thread(target=self._sense_ftp_root_worker, args=(host, user, password), daemon=True).start()

    def _sense_ftp_root_worker(self, host, user, password):
        success, result = self.logic.ftp_manager.find_web_root(host, user, password)

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


    def handle_toggle_hardened_security(self, enable_security: bool, ftp_password: str):
        """Moves the private data between DB and OS on hardened security."""
        if not self.active_issuer_id:
            return show_error("Error", "No active identity to modify.")

        try:
            # 1. First, load the ACTUAL private key from wherever it is currently stored.
            key_location = self.active_issuer_data.get("priv_key_pem")
            key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
            real_private_key_pem = self.crypto_manager.get_private_key(key_location, self.active_issuer_id, key_path)

            if not real_private_key_pem:
                raise KeystoreError("Could not retrieve the current private key to perform the security toggle.")
            
            # 2. Now, call the identity manager with the REAL key.
            success, result = self.identity_manager.toggle_hardened_security(
                enable_security,
                self.active_issuer_id,
                real_private_key_pem,
                ftp_password
            )

            if success:
                new_key_location = result
                self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = new_key_location
                self.config.hardened_security = enable_security
                
                # Retrieve latest UI data (excluding the password which is handled here)
                ui_config_data = self.ui_callback.get_ui_config_data()
                ui_config_data.pop("ftp_password", None)
                self.sync_and_save_settings(ui_config_data, ftp_password)
                
                show_info("Success", "Security settings updated successfully.")
                self.reload_data_and_update_ui()
            else:
                raise Exception(result)

        except Exception as e:
            # If anything fails, show an error and force the UI checkbox to revert.
            show_error("Security Operation Failed", f"{e}\n\nReverting the change.")
            self.ui_callback.root.after(0, self.ui_callback.update_ui_state)

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
                    except Exception:
                        pass
            else:
                show_error("Backup Failed", message)

        self.security_tab_frame.after(0, update_ui)

    def _update_ftp_dependent_widgets_state(self, *args):
        """Duplicate-safe single implementation retained for backward compat."""
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
