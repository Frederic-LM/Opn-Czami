# ui/core_workflow_tabs.py v3
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
import time
import tempfile
import webbrowser
import subprocess
import sys
import os
import logging
import threading
from pathlib import Path
from typing import Union
from urllib.parse import urlparse

# --- Third-Party Imports ---
import ttkbootstrap as ttk
from PIL import Image, ImageTk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox

# --- Local Imports ---
from opn_czami_logic import OpnCzamiLogic, UploadButtonState
from models.config import (
    MAX_LOGO_SIZE_BYTES, MAX_LOGO_PIXELS, STANDARDIZED_LOGO_BASENAME,
    APP_DATA_DIR, MAX_SUMMARY_CHARS
)
from models.utils import show_error, show_info

class CoreWorkflowTabs:
    """
     'Issuer Identity' and 'Sign Document'.
    """

    def __init__(self, notebook: ttk.Notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic
        
        self._init_state_variables()

        # Create the frames that will hold the content of each tab
        self.identity_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.signer_tab_frame = ttk.Frame(self.notebook, padding=10)

        # Build the UI inside the frames
        self._create_identity_tab(self.identity_tab_frame)
        self._create_signer_tab(self.signer_tab_frame)

        # Add the completed frames to the notebook
        self.notebook.add(self.identity_tab_frame, text=" 1. Issuer Identity ")
        self.notebook.add(self.signer_tab_frame, text=" 2. Sign Document ")

    def _init_state_variables(self):

        # --- Variables for Identity Creation ---
        self.url_path_var = ttk.StringVar(value="https://")
        self.image_base_url_var = ttk.StringVar()
        self.logo_path = None  # Holds the Path object to the selected logo

        # --- Variables for Document Signing ---
        self.include_doc_num_var = ttk.BooleanVar(value=False)
        self.auto_gen_doc_num_var = ttk.BooleanVar(value=False)
        self.doc_num_var = ttk.StringVar()

        # --- Variables for UI display images ---
        self.selected_image_file_path: Union[Path, None] = None
        self.qr_image_tk: Union[ImageTk.PhotoImage, None] = None
        self.issuer_qr_image_tk: Union[ImageTk.PhotoImage, None] = None
        self.lkey_image_tk: Union[ImageTk.PhotoImage, None] = None
        
        # --- State for upload button ---
        self.upload_button_state = UploadButtonState.INITIAL

    # --- Tab Creation Methods ---

    def _create_identity_tab(self, parent_frame):
        """Creates all widgets for the 'Issuer Identity' tab."""
        # This frame is shown when no identity exists
        self.setup_frame = ttk.LabelFrame(parent_frame, text="🔑 Create Your Issuer Identity", padding=15)
        self.setup_frame.pack(fill="x", pady=(0, 10))
        self.setup_frame.grid_columnconfigure(1, weight=1)

        # Logo selection panel
        logo_panel = ttk.Frame(self.setup_frame)
        logo_panel.grid(row=0, column=0, sticky="n", padx=(0, 20))
        logo_container = ttk.LabelFrame(logo_panel, text="Your Logo (Optional)")
        logo_container.pack()
        self.logo_placeholder_frame = ttk.Frame(logo_container, width=250, height=250)
        self.logo_placeholder_frame.pack(padx=10, pady=10)
        self.logo_placeholder_frame.grid_propagate(False)
        self.logo_placeholder_frame.grid_rowconfigure(0, weight=1)
        self.logo_placeholder_frame.grid_columnconfigure(0, weight=1)
        self.logo_text_frame = ttk.Frame(self.logo_placeholder_frame)
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")
        ttk.Label(self.logo_text_frame, text="No Logo Selected", bootstyle="secondary").pack(expand=True)
        self.logo_display_label = ttk.Label(self.logo_placeholder_frame, anchor="center")
        logo_button_frame = ttk.Frame(logo_container)
        logo_button_frame.pack(pady=(0, 10), fill="x", padx=5)
        ttk.Button(logo_button_frame, text="🖼️ Browse...", command=self._browse_for_logo, bootstyle="outline").pack(side="left", expand=True, fill="x", padx=(0,2))
        ttk.Button(logo_button_frame, text="🗑️ Clear", command=self._clear_logo, bootstyle="outline-danger").pack(side="left", expand=True, fill="x", padx=(2,0))

        # Identity details input panel
        right_panel = ttk.Frame(self.setup_frame)
        right_panel.grid(row=0, column=1, sticky="new")
        ttk.Label(right_panel, text="Issuer Name / Organisation:", font="-weight bold").pack(anchor="w")
        self.name_entry = ttk.Entry(right_panel)
        self.name_entry.pack(fill="x", pady=(2, 10))
        ttk.Label(right_panel, text="Public ID URL:", font="-weight bold").pack(anchor="w")
        vcmd_https = (parent_frame.register(self._validate_https_prefix), "%P")
        self.url_path_entry = ttk.Entry(right_panel, textvariable=self.url_path_var, validate="key", validatecommand=vcmd_https)
        self.url_path_entry.pack(fill="x", pady=(2, 10))
        ttk.Label(right_panel, text="Image Base URL (for signed documents):", font="-weight bold").pack(anchor="w")
        self.image_base_url_entry = ttk.Entry(right_panel, textvariable=self.image_base_url_var)
        self.image_base_url_entry.pack(fill="x", pady=(2, 10))
        self.url_path_var.trace_add("write", self.update_image_base_url_proposal)
        
        # Optional contact info
        optional_frame = ttk.LabelFrame(right_panel, text="Optional Public Contact Info", padding=10)
        optional_frame.pack(fill="x", pady=(5, 15))
        optional_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(optional_frame, text="Email:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=2)
        self.email_entry = ttk.Entry(optional_frame)
        self.email_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(optional_frame, text="Phone:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=2)
        self.phone_entry = ttk.Entry(optional_frame)
        self.phone_entry.grid(row=1, column=1, sticky="ew")
        ttk.Label(optional_frame, text="Address:").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=2)
        self.address_entry = ttk.Entry(optional_frame)
        self.address_entry.grid(row=2, column=1, sticky="ew")
        
        ttk.Button(self.setup_frame, text="Generate and Save Identity", command=self.handle_create_identity, bootstyle=SUCCESS).grid(row=2, column=0, columnspan=2, sticky="ew", ipady=5, pady=10)

        # This is the UI frame  showned when an identity already exists
        self.manage_frame = ttk.LabelFrame(parent_frame, text="🔑 Your Active Issuer Identity", padding="15")
        self.manage_frame.grid_columnconfigure(1, weight=1)
        self.issuer_qr_display_label = ttk.Label(self.manage_frame)
        self.issuer_qr_display_label.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, 20)) # Span 2 rows
        
        right_panel_manage = ttk.Frame(self.manage_frame)
        right_panel_manage.grid(row=0, column=1, sticky="new")
        
        info_box = ttk.Frame(right_panel_manage)
        info_box.pack(fill="x", pady=(0, 15), anchor="n")
        info_box.grid_columnconfigure(1, weight=1)
        ttk.Label(info_box, text="Issuer ID:").grid(row=0, column=0, sticky="w", pady=2)
        self.id_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.id_label.grid(row=0, column=1, sticky="w", padx=5)
        ttk.Label(info_box, text="Name:").grid(row=1, column=0, sticky="w", pady=2)
        self.name_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.name_label.grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(info_box, text="Info URL:").grid(row=2, column=0, sticky="nw", pady=2)
        self.url_button = ttk.Button(info_box, text="N/A", bootstyle="link-primary")
        self.url_button.grid(row=2, column=1, sticky="w", padx=0)
        
        ttk.Label(info_box, text="Doc Path URL:").grid(row=3, column=0, sticky="nw", pady=2)
        self.image_base_url_button = ttk.Button(info_box, text="N/A", bootstyle="link-primary")
        self.image_base_url_button.grid(row=3, column=1, sticky="w", padx=0)

        # --- CONTACT BOX ---
        contact_box = ttk.LabelFrame(right_panel_manage, text="Public Contact Info (from server)", padding=10)
        contact_box.pack(fill="x", pady=(0, 15), anchor="n")
        contact_box.grid_columnconfigure(1, weight=1)
        ttk.Label(contact_box, text="Email:").grid(row=0, column=0, sticky="w", pady=2)
        self.email_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.email_label_val.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(contact_box, text="Phone:").grid(row=1, column=0, sticky="w", pady=2)
        self.phone_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.phone_label_val.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(contact_box, text="Address:").grid(row=2, column=0, sticky="nw", pady=2)
        self.address_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
  

        btn_frame = ttk.Frame(self.manage_frame) 
        btn_frame.grid(row=1, column=1, sticky="sew", pady=(10,0)) 
        btn_frame.grid_columnconfigure(list(range(4)), weight=1)
        ttk.Button(btn_frame, text="📤 Export", command=self.export_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=0, sticky="ew", padx=(0, 2))
        ttk.Button(btn_frame, text="✉️ Email", command=self.email_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=1, sticky="ew", padx=(2, 2))
        ttk.Button(btn_frame, text="🖨️ Print", command=self.print_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=2, sticky="ew", padx=(2, 2))
        ttk.Button(btn_frame, text="🗑️ Delete", command=self.handle_delete_identity, bootstyle=DANGER).grid(row=0, column=3, sticky="ew", padx=(2, 0))

    def _create_signer_tab(self, parent_frame):
        """Creates all widgets for the 'Sign Document' tab."""
        parent_frame.grid_columnconfigure((0, 1), weight=1, uniform="signer_cols")
        parent_frame.grid_rowconfigure(3, weight=1)

        # Top area for inputs
        input_area_frame = ttk.Frame(parent_frame)
        input_area_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        input_area_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Button(input_area_frame, text="📄 Select Image...", command=self.browse_and_set_image_file, bootstyle="primary-outline").grid(row=0, column=0, sticky="ns", padx=(0, 10))
        
        # Summary and Doc # section
        summary_frame = ttk.Frame(input_area_frame)
        summary_frame.grid(row=0, column=1, sticky="nsew")
        summary_frame.grid_columnconfigure(0, weight=1)
        header_frame = ttk.Frame(summary_frame)
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(header_frame, text="Document Summary / Message:").grid(row=0, column=0, sticky="w")
        self.doc_num_frame = ttk.Frame(header_frame)
        self.doc_num_entry = ttk.Entry(self.doc_num_frame, textvariable=self.doc_num_var, width=20, font=("TkDefaultFont", 9))
        self.doc_num_entry.grid(row=0, column=0, padx=(0, 5))
        ttk.Checkbutton(self.doc_num_frame, text="Auto", variable=self.auto_gen_doc_num_var, command=self._update_doc_num_entry_state).grid(row=0, column=1, padx=(0, 10))
        ttk.Checkbutton(header_frame, text="+ Doc #", variable=self.include_doc_num_var, bootstyle="round-toggle", command=self._toggle_doc_num_frame_visibility).grid(row=0, column=2, sticky="e")
        self.message_text = ttk.Text(summary_frame, height=4, wrap="word")
        self.message_text.grid(row=1, column=0, sticky="nsew", pady=(5,0))
        
        status_line_frame = ttk.Frame(input_area_frame)
        status_line_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        self.char_count_label = ttk.Label(status_line_frame, text=f"0 / {MAX_SUMMARY_CHARS}", bootstyle="secondary")
        self.char_count_label.pack(side="right")
        self.doc_id_helper_label = ttk.Label(status_line_frame, text="No Image selected.", bootstyle="secondary", anchor="w")
        self.doc_id_helper_label.pack(side="left", fill="x", expand=True)
        self.message_text.bind("<KeyRelease>", self._validate_summary_length)

        # Action buttons
        self.generate_qr_button = ttk.Button(parent_frame, text="✨ Fingerprint, Sign & Save", command=self.handle_generate_document_qr, bootstyle=PRIMARY, state=DISABLED)
        self.generate_qr_button.grid(row=2, column=0, sticky="ew", ipady=5, padx=(0, 5), pady=10)
        self.upload_button = ttk.Button(parent_frame, text="🚀 Upload LKey", command=self.handle_upload_lkey_file, state=DISABLED)
        self.upload_button.grid(row=2, column=1, sticky="ew", ipady=5, padx=(5, 0), pady=10)
        
        # LKey Image Display
        lkey_lf = ttk.LabelFrame(parent_frame, text="Fingerprinted Legato Key Image")
        lkey_lf.grid(row=3, column=0, sticky="nsew", padx=(0, 5), pady=(10,0))
        lkey_lf.grid_rowconfigure(1, weight=1)
        lkey_lf.grid_columnconfigure(0, weight=1)
        self.lkey_image_display_label = ttk.Label(lkey_lf, relief="flat", anchor="center")
        self.lkey_image_display_label.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.lkey_folder_button = ttk.Button(lkey_lf, text="📁", command=self._open_lkey_save_location, bootstyle="secondary-outline", width=3)
        
        # QR Code Display
        qr_lf = ttk.LabelFrame(parent_frame, text="Generated LegatoKey QR")
        qr_lf.grid(row=3, column=1, sticky="nsew", padx=(5, 0), pady=(10,0))
        self.qr_display_label = ttk.Label(qr_lf, relief="flat", anchor="center")
        self.qr_display_label.pack(fill="both", expand=True, padx=5, pady=5)
        self.qr_print_button = ttk.Button(qr_lf, text="🖨️", command=self.print_document_qr, bootstyle="secondary-outline", width=3)
        self.qr_email_button = ttk.Button(qr_lf, text="✉️", command=self.email_document_qr, bootstyle="secondary-outline", width=3)
        self.qr_folder_button = ttk.Button(qr_lf, text="📁", command=self._open_qr_save_location, bootstyle="secondary-outline", width=3)

        # Progress bar
        top_status_bar_frame = ttk.Frame(lkey_lf)
        top_status_bar_frame.grid(row=0, column=0, sticky="ew", padx=5)
        top_status_bar_frame.grid_columnconfigure(1, weight=1)
        self.auto_upload_indicator_label = ttk.Label(top_status_bar_frame, text="", bootstyle="success")
        self.auto_upload_indicator_label.grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.upload_progress_bar = ttk.Progressbar(top_status_bar_frame, mode="indeterminate", length=150)
        self.upload_progress_bar.grid(row=0, column=1, sticky="ew")
        self.upload_progress_bar.grid_remove()

    # --- UI Event Handlers (Trigger Logic calls) ---

    def handle_create_identity(self):
        """Gathers data from the UI and tells the logic layer to create an identity."""
        name = self.name_entry.get().strip()
        url_path = self.url_path_var.get().strip()
        image_base_url = self.image_base_url_var.get().strip()
        contact_info = {
            "email": self.email_entry.get().strip(), 
            "phone": self.phone_entry.get().strip(), 
            "address": self.address_entry.get().strip()
        }
        
        errors = []
        if not name: errors.append("• Issuer Name is required.")
        if not url_path or url_path == "https://": errors.append("• Public ID URL is required.")
        if not image_base_url or image_base_url == "https://": errors.append("• Image Base URL is required.")
        if errors:
            show_error("Input Error", "Please correct the following errors:\n\n" + "\n".join(errors))
            return
        if not self.logo_path and not messagebox.askyesno("Confirm: No Logo", "You have not selected a logo. This decision is PERMANENT.\n\nAre you sure you want to continue?", icon=WARNING):
            return
        
        issuer_id = self.logic.crypto_manager.generate_id_from_name(name)
        if not messagebox.askokcancel("Confirm Identity Creation", f"This will create the identity '{name}' with the permanent ID:\n\n{issuer_id}\n\nProceed?"):
            return

        self.logic.handle_identity_creation(name, url_path, image_base_url, self.logo_path, contact_info)

    def handle_delete_identity(self):
        """Tells the logic layer to delete the active identity after confirmation."""
        if not self.logic.active_issuer_id: return
        if not messagebox.askyesno("CONFIRM DELETION", "Are you absolutely sure?\nThis is PERMANENT.", icon=WARNING): return
        self.logic.handle_identity_deletion()

    def handle_generate_document_qr(self):
        """Gathers signing data and starts the QR generation process in a thread."""
        if not self.selected_image_file_path: return

        message = self.message_text.get("1.0", "end-1c").strip()
        doc_num_manual = self.doc_num_var.get().strip()
        use_doc_num = self.include_doc_num_var.get()
        auto_gen = self.auto_gen_doc_num_var.get()

        self.logic.generate_document_qr_threaded(
            self.selected_image_file_path, message, doc_num_manual, use_doc_num, auto_gen
        )

    def handle_upload_lkey_file(self):
        """Starts the manual LKey upload process."""
        if not self.logic.prepared_upload_path or self.upload_button_state == UploadButtonState.UPLOADING: return
        self.upload_button_state = UploadButtonState.UPLOADING
        self.update_upload_button_display()
        self.upload_progress_bar.grid()
        self.upload_progress_bar.start()
        threading.Thread(target=self._run_and_show_upload_result, args=(self.logic.prepared_upload_path,), daemon=True).start()

    def _run_and_show_upload_result(self, local_path: Path):
        """Worker function for manual upload, run in a background thread."""
        try:
            is_success, result = self.logic.upload_lkey_file(local_path)
            self.upload_button_state = UploadButtonState.SUCCESS if is_success else UploadButtonState.FAILURE
            
            if not is_success:
                self.signer_tab_frame.after(0, lambda res=result: show_error("FTP Upload Error", res))
            else:
                self.signer_tab_frame.after(0, lambda: self.qr_print_button.config(state=NORMAL))
                self.signer_tab_frame.after(0, lambda: self.qr_email_button.config(state=NORMAL))
                
                if local_path and local_path.exists():
                    local_path.unlink()
                    logging.info(f"Deleted temporary upload file: {local_path.name}")
                    
        except Exception as e:
            logging.error(f"Error in manual upload worker: {e}", exc_info=True)
            self.signer_tab_frame.after(0, lambda err=e: show_error("Upload Error", f"An unexpected error occurred during manual upload: {err}"))
            self.upload_button_state = UploadButtonState.FAILURE
        finally:
            self.signer_tab_frame.after(0, self.upload_progress_bar.stop)
            self.signer_tab_frame.after(0, self.upload_progress_bar.grid_remove)
            self.signer_tab_frame.after(0, self.update_upload_button_display)
            
    # --- Logic -> UI Callbacks ---
    
    def on_identity_creation_failed(self, message: str):
        show_error("Identity Creation Error", message)
        
    def on_identity_deleted(self):
        """Callback to clear UI elements when identity is deleted."""
        self.clear_lkey_image_display()
        self.message_text.delete("1.0", "end")
        self.qr_display_label.config(image="")

    def on_signing_start(self):
        """Callback before document signing begins."""
        self.generate_qr_button.config(state=DISABLED)
        self.reset_upload_button_state()
        self._hide_qr_action_buttons()
        self.upload_progress_bar.grid()
        self.upload_progress_bar.start()

    def on_signing_failure(self, message: str):
        """Callback when document signing fails."""
        show_error("Signing Failed", message)
        self.upload_button_state = UploadButtonState.FAILURE
        self.update_upload_button_display()
        self.upload_progress_bar.stop()
        self.upload_progress_bar.grid_remove()
        self.generate_qr_button.config(state=NORMAL)

    def on_signing_success(self, prepared_upload_path: Path, qr_image_pil: Image.Image, last_signed_payload: str, was_auto_upload_successful: bool, final_lkey_image_with_overlay: Image.Image):
        """Callback when document signing is successful."""
            
        if final_lkey_image_with_overlay:
            self.update_lkey_display(final_lkey_image_with_overlay)
        
        self.update_qr_display(qr_image_pil)
        self._show_qr_action_buttons()
        self.lkey_folder_button.config(state=NORMAL)
        self.qr_folder_button.config(state=NORMAL)

        if was_auto_upload_successful:
            self.upload_button_state = UploadButtonState.SUCCESS
            self.qr_print_button.config(state=NORMAL)
            self.qr_email_button.config(state=NORMAL)
        else:
            self.upload_button_state = UploadButtonState.READY
            self.qr_print_button.config(state=DISABLED)
            self.qr_email_button.config(state=DISABLED)

        self.update_upload_button_display()
        self.generate_qr_button.config(state=NORMAL)
        self.upload_progress_bar.stop()
        self.upload_progress_bar.grid_remove()
        logging.info(f"UI updated after signing success (Auto-upload successful: {was_auto_upload_successful}).")

    
    def update_ui_state(self, has_identity: bool):
        """Shows/hides frames based on whether an identity exists."""
        if has_identity:
            self.setup_frame.pack_forget()
            self.manage_frame.pack(fill=X, pady=(0, 10))
            self.update_manage_frame_display()
            self.update_issuer_qr_display()

        else:
            self.manage_frame.pack_forget()
            self.setup_frame.pack(fill=X, pady=(0, 10))
        
        self.reset_upload_button_state()
        self.update_auto_upload_indicator()

    def update_manage_frame_display(self):
        """Populates the manage frame with the active identity's data."""
        if not self.logic.active_issuer_data: return
        self.id_label.config(text=self.logic.active_issuer_id)
        self.name_label.config(text=self.logic.active_issuer_data.get("name", "N/A"))
        info_url = self.logic.active_issuer_data.get("infoUrl", "N/A")
        self.url_button.config(text=info_url, command=lambda: webbrowser.open(info_url))
        
        base_url = self.logic.active_issuer_data.get("imageBaseUrl", "N/A")
        self.image_base_url_button.config(text=base_url, command=lambda: webbrowser.open(base_url))
        contact = self.logic.active_issuer_contact_info
        self.email_label_val.config(text=contact.get("email", "N/A"))
        self.phone_label_val.config(text=contact.get("phone", "N/A"))
        self.address_label_val.config(text=contact.get("address", "N/A"))


    def update_qr_display(self, pil_image: Image.Image):
        """Updates the QR code image label on the signer tab."""
        display_qr = pil_image.copy()
        display_qr.thumbnail((300, 300), self.logic.image_processor.resample_method)
        self.qr_image_tk = ImageTk.PhotoImage(display_qr)
        self.qr_display_label.config(image=self.qr_image_tk)

    def update_lkey_display(self, pil_image: Image.Image):
        """Updates the LKey image label on the signer tab."""
        display_lkey = pil_image.copy()
        display_lkey.thumbnail((600, 480), self.logic.image_processor.resample_method)
        self.lkey_image_tk = ImageTk.PhotoImage(display_lkey.convert("RGB"))
        self.lkey_image_display_label.config(image=self.lkey_image_tk)

    def clear_lkey_image_display(self):
        """Clears the LKey image."""
        self.lkey_image_display_label.config(image="")
        self.logic.lkey_image_pil = None
        self.lkey_image_tk = None

    def update_issuer_qr_display(self):
        """Generates and displays the QR code for the active issuer."""
        if not self.logic.active_issuer_id:
            self.issuer_qr_display_label.config(image="")
            return
        issuer_qr_pil = self.logic.generate_issuer_qr()
        display_img = issuer_qr_pil.copy()
        display_img.thumbnail((250, 250), self.logic.image_processor.resample_method)
        self.issuer_qr_image_tk = ImageTk.PhotoImage(display_img)
        self.issuer_qr_display_label.config(image=self.issuer_qr_image_tk)

    def reset_upload_button_state(self):
        """Resets the signer tab to its initial state for a new document."""
        self.upload_button_state = UploadButtonState.INITIAL
        self.update_upload_button_display()
        self.logic.last_signed_payload = None
        self._hide_qr_action_buttons()
        return True

    def update_upload_button_display(self):
        """Updates the text, color, and state of the main upload button."""
        text, style, state = self.upload_button_state.value
        if self.logic.config.ftp_auto_upload and self.upload_button_state == UploadButtonState.INITIAL:
            style = "success-outline"
        self.upload_button.config(text=text, bootstyle=style, state=state)
        
    def update_auto_upload_indicator(self):
        """Updates the small label indicating if auto-upload is on or off."""
        text, style = ("✓ Auto-Upload: ON", SUCCESS) if self.logic.config.ftp_auto_upload else ("✗ Auto-Upload: OFF", SECONDARY)
        self.auto_upload_indicator_label.config(text=text, bootstyle=style)

    def _show_qr_action_buttons(self):
        """Places the small action buttons over the QR and LKey images."""
        self.qr_folder_button.place(relx=0.0, rely=1.0, x=5, y=-5, anchor=SW)
        self.qr_email_button.place(relx=1.0, rely=1.0, x=-5, y=-5, anchor=SE)
        self.qr_print_button.place(relx=1.0, rely=1.0, x=-45, y=-5, anchor=SE)
        self.lkey_folder_button.place(relx=1.0, rely=1.0, x=-5, y=-5, anchor=SE)

    def _hide_qr_action_buttons(self):
        """Removes the small action buttons."""
        self.qr_print_button.place_forget()
        self.qr_email_button.place_forget()
        self.qr_folder_button.place_forget()
        self.lkey_folder_button.place_forget()

    # --- Utility UI Handlers and Helpers ---

    def _browse_for_logo(self):
        """
        Handles browsing for, validating, and converting a logo image.
        The standardized logo is saved locally for later use.
        """
        if not (filepath := filedialog.askopenfilename(title="Select Logo", filetypes=[("Image Files", "*.png *.jpg *.jpeg"), ("All files", "*.*")])): return
        source_path = Path(filepath)
        if source_path.stat().st_size > MAX_LOGO_SIZE_BYTES:
            show_error("File Too Large", f"Logo exceeds {MAX_LOGO_SIZE_BYTES / 1024:.0f}KB size limit.")
            return
        try:
            img = Image.open(source_path)
            # Resize if necessary
            if (img.width * img.height) > MAX_LOGO_PIXELS:
                ratio = (MAX_LOGO_PIXELS / (img.width * img.height)) ** 0.5
                new_size = (int(img.width * ratio), int(img.height * ratio))
                img = img.resize(new_size, Image.Resampling.LANCZOS)
            
            # Convert to PNG for consistency and transparency support
            if img.mode != "RGBA":
                img = img.convert("RGBA")

            # Clean up old logos and save new one with a unique name to bust caches
            for old_logo in APP_DATA_DIR.glob(f"{STANDARDIZED_LOGO_BASENAME}-*.png"):
                old_logo.unlink(missing_ok=True)
            
            unique_suffix = int(time.time())
            standardized_filename = f"{STANDARDIZED_LOGO_BASENAME}-{unique_suffix}.png"
            standardized_path = APP_DATA_DIR / standardized_filename
            img.save(standardized_path, format="PNG")
            
            self.logo_path = standardized_path # Store the full path
            
            # Display the selected logo
            display_img = img.copy()
            display_img.thumbnail((250, 250), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(display_img)
            self.logo_display_label.config(image=logo_photo)
            self.logo_display_label.image = logo_photo # Keep a reference
            self.logo_text_frame.grid_remove()
            self.logo_display_label.grid(row=0, column=0, sticky="nsew")
        except Exception as e:
            show_error("File Error", f"Could not process logo file. Error: {e}")
            self._clear_logo()

    def _clear_logo(self):
        """Clears the selected logo."""
        self.logo_path = None
        self.logo_display_label.config(image=None)
        self.logo_display_label.grid_remove()
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")

    def browse_and_set_image_file(self):
        """Handles browsing for the main document image to be signed."""
        if not self.reset_upload_button_state(): return
        if not (filepath_str := filedialog.askopenfilename(title="Select image file", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp"), ("All files", "*.*")])):
            self.clear_lkey_image_display()
            self.doc_id_helper_label.config(text="File selection cancelled.")
            self.generate_qr_button.config(state=DISABLED)
            self.selected_image_file_path = None
            return
        
        self.selected_image_file_path = Path(filepath_str)
        self.doc_id_helper_label.config(text=f"Selected: {self.selected_image_file_path.name}")
        try:
            lkey_image_pil = Image.open(self.selected_image_file_path)
            self.logic.lkey_image_pil = lkey_image_pil # Store in logic
            self.update_lkey_display(lkey_image_pil)
            self.generate_qr_button.config(state=NORMAL)
        except Exception as e:
            show_error("Image Load Error", f"Could not load image: {e}")
            self.clear_lkey_image_display()

    def _toggle_doc_num_frame_visibility(self, *args):
        """Shows or hides the document number entry fields."""
        if self.include_doc_num_var.get():
            self.doc_num_frame.grid(row=0, column=1, sticky="e", padx=(10, 5))
            self._update_doc_num_entry_state()
        else:
            self.doc_num_frame.grid_remove()

    def _update_doc_num_entry_state(self, *args):
        """Updates the document number entry based on auto-gen/masking state."""
        is_masking_licensed = self.logic.license_manager.is_feature_enabled("masked_ids")
        mask = self.logic.config.doc_num_mask.strip()

        if self.auto_gen_doc_num_var.get():
            self.doc_num_entry.config(state="readonly")
            if is_masking_licensed and mask:
                self.doc_num_var.set(self.logic._apply_number_mask(self.logic.config.doc_num_mask))
            else:
                self.doc_num_var.set(self.logic._get_next_auto_doc_num_str())
        else:
            self.doc_num_entry.config(state="normal")
            auto_num_str = self.logic._get_next_auto_doc_num_str()
            masked_num_str = self.logic._apply_number_mask(mask) if is_masking_licensed and mask else ""
            if self.doc_num_var.get() in [auto_num_str, masked_num_str]:
                self.doc_num_var.set("")


    def _validate_https_prefix(self, v):
        """Validation command for entry fields to ensure they start with 'https://'."""
        return v.startswith("https://")

    def update_image_base_url_proposal(self, *args):
        """Suggests a value for the image base URL based on the main URL."""
        try:
            if parsed := urlparse(self.url_path_var.get()):
                if parsed.scheme and parsed.netloc:
                    self.image_base_url_var.set(f"{parsed.scheme}://{parsed.netloc}/")
        except Exception: pass

    def _validate_summary_length(self, event=None):
        """Validates the length of the summary text and updates the character count."""
        current_text = self.message_text.get("1.0", "end-1c")
        char_len = len(current_text)
        if char_len > MAX_SUMMARY_CHARS:
            self.message_text.delete(f"1.0 + {MAX_SUMMARY_CHARS} chars", "end")
            char_len = MAX_SUMMARY_CHARS
        self.char_count_label.config(text=f"{char_len} / {MAX_SUMMARY_CHARS}", bootstyle=DANGER if char_len >= MAX_SUMMARY_CHARS else SECONDARY)

    def _open_lkey_save_location(self):
        """Opens the local folder where signed LKey files are saved."""
        path = Path(self.logic.config.legato_files_save_path)
        if path.exists():
            webbrowser.open(path.resolve().as_uri())
        else:
            show_error("Path Not Found", f"The directory '{path}' does not exist.")

    def _open_qr_save_location(self):
        """Opens the local folder where QR code images are saved."""
        path = Path(self.logic.config.legato_files_save_path)
        if path.exists():
            webbrowser.open(path.resolve().as_uri())
        else:
            show_error("Path Not Found", f"The directory '{path}' does not exist.")
            
    # --- Print and Email Handlers ---

    def print_document_qr(self):
        """Saves the QR to a temp file and opens it with the default print handler."""
        if not self.logic.qr_image_pil: return show_error("Print Error", "No QR Code is available.")
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                self.logic.qr_image_pil.save(tf.name)
                if sys.platform == "win32": os.startfile(tf.name, "print")
                elif sys.platform == "darwin": subprocess.run(["open", "-a", "Preview", tf.name], check=True)
                else: subprocess.run(["xdg-open", tf.name], check=True)
        except Exception as e:
            show_error("Printing Error", f"Could not open image for printing: {e}")

    def email_document_qr(self):
        """Opens the default email client with a pre-filled mailto URI."""
        if not self.logic.qr_image_pil or not self.logic.last_signed_payload:
            return show_error("Email Error", "No QR Code or payload data is available.")

        try: filename, summary, _ = self.logic.last_signed_payload.split('|', 2)
        except (ValueError, AttributeError): filename, summary = "signed_document", "See attached."
        
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            temp_path = Path(tf.name)
            self.logic.qr_image_pil.save(temp_path)

        subject = f"LegatoKey for document: {filename}"
        body = (f"Hello,\n\nAttached is the LegatoKey for the following item:\n\n"
                f"Document: {filename}\nSummary: {summary}\n\n"
                f"Best regards,\n{self.logic.active_issuer_data.get('name', 'The Issuer')}")
        
        mailto_uri = self.logic.prepare_mailto_uri(subject, body)
        webbrowser.open(mailto_uri)
        show_info("Email Client Opened", f"Your email client has been opened. Please attach the following file to your email:\n\n{temp_path}")

    def export_issuer_qr(self):
        """Saves the issuer QR code to a user-selected file."""
        if not self.logic.issuer_qr_image_pil: return
        if file_path_str := filedialog.asksaveasfilename(defaultextension=".png", initialfile=f"issuer_{self.logic.active_issuer_id}_qr.png", title="Save Issuer QR"):
            self.logic.issuer_qr_image_pil.save(file_path_str)

    def email_issuer_qr(self):
        """Opens the default email client to send the issuer QR code."""
        if not self.logic.issuer_qr_image_pil: return
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            temp_path = Path(tf.name)
            self.logic.issuer_qr_image_pil.save(temp_path)

        name = self.logic.active_issuer_data.get("name", "My Issuer")
        subject = f"LegatoLink Authority ID for {name}"
        body = (f"Hello,\n\nAttached is my LegatoLink Authority ID.\n\n"
                f"Info URL: {self.logic.active_issuer_data.get('infoUrl', 'N/A')}\n\n"
                f"Best regards,\n{name}")

        mailto_uri = self.logic.prepare_mailto_uri(subject, body)
        webbrowser.open(mailto_uri)
        show_info("Email Client Opened", f"Please attach the following file to your email:\n\n{temp_path}")

    def print_issuer_qr(self):
        """Saves the issuer QR to a temp file and opens it for printing."""
        if not self.logic.issuer_qr_image_pil: return
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                self.logic.issuer_qr_image_pil.save(tf.name)
                if sys.platform == "win32": os.startfile(tf.name, "print")
                elif sys.platform == "darwin": subprocess.run(["open", "-a", "Preview", tf.name], check=True)
                else: subprocess.run(["xdg-open", tf.name], check=True)
        except Exception as e:
            show_error("Printing Error", f"Could not open image for printing: {e}")