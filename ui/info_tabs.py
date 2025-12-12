# ui/info_tabs.py (Working Version)
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


import sys
import webbrowser
import textwrap
import logging
from pathlib import Path
import tkinter as tk
from tkinter import ttk
import ttkbootstrap
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from tkinter import Toplevel 

# --- Local Imports ---
from opn_czami import OpnCzamiLogic
from models.config import APP_VERSION
from models.utils import show_error, show_info, resource_path 



class InfoTabs:
    """Manage 'Guide' and 'About' information tabs."""

    def __init__(self, notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic
               
        self.guide_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.about_tab_frame = ttk.Frame(self.notebook, padding=10)

        self._create_guide_tab(self.guide_tab_frame)
        self._create_about_tab(self.about_tab_frame)

        # Info tabs will be added later at positions 8-9 (after settings/backup tabs)

    def add_info_tabs(self):
        """Add Guide and About tabs at correct positions (called after settings tabs)."""
        self.notebook.add(self.guide_tab_frame, text=" 8. Guide ")
        self.notebook.add(self.about_tab_frame, text=" 9. About ")

    def get_ui_config_data(self) -> dict:
        return {
            "check_for_updates": self.check_for_updates_var.get()
        }    
       
 

    def _create_guide_tab(self, parent_frame):
        """Build read-only guide with LegatoKey workflow steps."""
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_rowconfigure(0, weight=1)

        guide_text = ScrolledText(parent_frame, padding=(20, 20, 0, 20), hbar=False, autohide=True, wrap="word")
        guide_text.grid(row=0, column=0, sticky="nsew")

        inner_text_widget = guide_text.text
        inner_text_widget.tag_configure("h1", font="-size 14 -weight bold", spacing3=15)
        inner_text_widget.tag_configure("h2", font="-size 11 -weight bold", spacing1=20, spacing3=5)
        inner_text_widget.tag_configure("p", font="-size 10", lmargin1=10, lmargin2=10, spacing3=10)

        guide_content = [
            ("Day-to-Day LegatoKey Workflow\n", "h1"),
            ("Once you've created your legacy document (certificate, valuation letter, photos, etc.), follow these steps:", "p"),
            ("Step 1: Select your source image\n", "h2"),
            ("Choose your supporting image (photo of the instrument, a scan of the certificate letter). Its fingerprint will be linked to the LegatoKey.", "p"),
            ("Step 2: Write a short summary of your document\n", "h2"),
            ("""For example:
    -"We [Your Name] certify that the violin examined and reproduced on our certificate and its digital counterpart is, in our opinion, an instrument by [Name of the Maker], authentic in all its major parts and  measuring 35.5 cm."
    -"Valuation issued to Count Ignazio Alessandro Cozio di Salabue etc..."
This summary will be securely encrypted and embedded in the LegatoKey and cannot be changed.""", "p"),
            ("Step 3: Click 'Fingerprint, Sign & Save'\n", "h2"),
            ("This creates your secure LegatoKey (.lky) file and its corresponding QR code. If 'Automatic Upload' is enabled in Settings, the .lky file will upload to your web server automatically. If not, click the 'Upload LKey' button to send it manually.", "p"),
            ("Step 4: Print the LegatoKey\n", "h2"),
            ("You can now print the generated LegatoKey (QR code) onto a label, an envelope, or directly onto the physical document.", "p"),
        ]

        for text, tag in guide_content:
            for i, line in enumerate(textwrap.dedent(text).strip().splitlines()):
                inner_text_widget.insert("end", " ".join(line.split()), tag)
                if i < len(textwrap.dedent(text).strip().splitlines()) - 1:
                    inner_text_widget.insert("end", "\n")
            inner_text_widget.insert("end", "\n")
            
        inner_text_widget.configure(state="disabled")

    def _create_about_tab(self, parent_frame):
        """Build about/license/status section with upgrade button, legal links, and contact info."""
        outer_container = ttk.Frame(parent_frame)
        outer_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header frame with 3 columns: image | text | image
        header_frame = ttk.Frame(outer_container)
        header_frame.pack(pady=(0, 15), anchor="center")
        header_frame.grid_columnconfigure((0, 1, 2), weight=0)
        header_frame.grid_rowconfigure(0, weight=0)

        # --- LEFT: Logo ---
        try:
            from models.utils import resource_path
            logo_path = resource_path("logo.png")
            if logo_path.exists():
                from PIL import Image, ImageTk
                logo_img = Image.open(logo_path)
                logo_img.thumbnail((120, 120), Image.Resampling.LANCZOS)
                logo_photo = ImageTk.PhotoImage(logo_img)
                left_logo_label = ttk.Label(header_frame, image=logo_photo)
                left_logo_label.image = logo_photo
                left_logo_label.grid(row=0, column=0, padx=(0, 20), sticky="w")
        except Exception as e:
            logging.warning(f"Could not load logo.png: {e}")

        # --- CENTER: Text Information ---
        center_frame = ttk.Frame(header_frame)
        center_frame.grid(row=0, column=1, sticky="nsew", padx=20)
        ttk.Label(center_frame, text="Op'n-Czami", font="-size 24 -weight bold").pack()
        ttk.Label(center_frame, text="Legato-Key Certification Authority Dashboard", font="-size 12", bootstyle="secondary").pack(pady=(5, 0))
        ttk.Label(center_frame, text="© 2025 Frédéric Levi Mazloum. All rights reserved.", font="-size 8", bootstyle="secondary").pack(pady=(3, 0))
        ttk.Label(center_frame, text=f"Version {APP_VERSION}", font="-size 10", bootstyle="info").pack(pady=(10, 0))

        # --- RIGHT: AL Logo (2x bigger) ---
        try:
            from models.utils import resource_path
            al_path = resource_path("AL.png")
            if al_path.exists():
                from PIL import Image, ImageTk
                al_img = Image.open(al_path)
                al_img.thumbnail((160, 160), Image.Resampling.LANCZOS)
                al_photo = ImageTk.PhotoImage(al_img)
                right_logo_label = ttk.Label(header_frame, image=al_photo)
                right_logo_label.image = al_photo
                right_logo_label.grid(row=0, column=2, padx=(20, 0), sticky="e")
        except Exception as e:
            logging.warning(f"Could not load AL.png: {e}")
        
        ttk.Separator(outer_container, orient="horizontal").pack(fill="x", pady=15)
        
        # --- TOP SECTION (3-Column Grid) ---
        info_frame = ttk.Frame(outer_container)
        info_frame.pack(fill="x", pady=(0, 15), anchor="n")
        info_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="info_cols")
        info_frame.grid_rowconfigure(0, weight=1)
        
        # --- COLUMN 0: Description Frame ---
        DESCRIPTION_TEXT = DESCRIPTION_TEXT = (
        "Op’n Cezami is a secure, professional tool for creating tamper-proof, cryptographically signed digital certificates.\n"
        "As part of the Legato ecosystem, it builds a verifiable link between digital certificates and their physical counterparts that anyone can independently validate.\n"
        "It uses modern NIST-approved cryptographic algorithms and employs multiple redondant tamper-detection mechanisms.\n"
        "The Pro license adds a blockchain-style signing audit trail for traceability, security, accountability, fraud prevention, and legal compliance, among other advanced features."
        )
        description_frame = ttk.LabelFrame(info_frame, text="About This Application", padding=10)
        description_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        desc_label = ttk.Label(description_frame, text=DESCRIPTION_TEXT, justify="left", wraplength=180)
        desc_label.pack(fill="x", anchor="nw")

        description_frame.bind(
            "<Configure>",
            lambda e, w=desc_label: w.config(wraplength=max(190, e.width - 20)),
        )
        
        
            
             
        # --- COLUMN 1: License Text Frame  ---
        license_frame = ttk.LabelFrame(info_frame, text="Our Open Core License", padding=15)
        license_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 5))

        license_text = ("This application is built to be a tool you can trust in your professional environment and is designed to respect your privacy.The core codebase is open source and publicly auditable.\n\n"
                        "The core functionality is free for personal and commercial use under the under the GNU Lesser General Public License (LGPL); only some additional features require a Pro License"
                        )
        license_label = ttk.Label(license_frame, text=license_text, justify="left", wraplength=200)
        license_label.pack(fill="x", anchor="nw")

        # Button frame for GitHub link
        button_frame = ttk.Frame(license_frame)
        button_frame.pack(anchor="w", pady=(5,0))

        github_button = ttk.Button(
            button_frame, text="View on GitHub ↗", bootstyle="link-primary",
            command=lambda: webbrowser.open("https://github.com/Frederic-LM/Opn-Czami")
        )
        github_button.pack(side="left")


        license_frame.bind("<Configure>", lambda e, w=license_label: w.config(wraplength=max(150, e.width - 30)))
        
        
        # --- COLUMN 2: License Status Frame (THE VERTICAL SPLIT) ---
        license_status_frame = ttk.Frame(info_frame) 
        license_status_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        license_status_frame.grid_rowconfigure((0, 1), weight=1, uniform="lic_rows")
        license_status_frame.grid_columnconfigure(0, weight=1)
        
        # 1. UPGRADE BUTTON GROUP (TOP HALF)
        upgrade_frame = ttk.LabelFrame(license_status_frame, text="🔓 Pro License Subscription", padding=10)
        upgrade_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        
        self.upgrade_button = ttk.Button(
            upgrade_frame, 
            text="💰 Upgrade to Pro", 
            command=self._handle_upgrade_button_click, 
            bootstyle="success",
            state=DISABLED 
        )
        self.upgrade_button.pack(fill="x", ipady=5, pady=5)
        
        # 2. CURRENT STATUS GROUP (BOTTOM HALF)
        current_status_frame = ttk.LabelFrame(license_status_frame, text="✨ Current License Status", padding=10)
        current_status_frame.grid(row=1, column=0, sticky="nsew", pady=(5, 0))

        # Re-use Existing Widgets in the new current_status_frame
        self.license_content_frame = ttk.Frame(current_status_frame)
        self.license_content_frame.pack(fill="both", expand=True, pady=5)
        
        # Original status content widgets 
        self.lic_customer_label = ttk.Label(self.license_content_frame, bootstyle="success", justify="center", anchor="center")
        self.lic_features_label = ttk.Label(self.license_content_frame, justify="center", anchor="center", wraplength=250)
        self.mac_activate_label = ttk.Label(self.license_content_frame, text="To activate, place license.key in the License Folder.", justify="center")
        self.mac_open_folder_button = ttk.Button(self.license_content_frame, text="📂 Open License Folder", bootstyle="success")
        self.dnd_activate_label = ttk.Label(self.license_content_frame, text="\nTo activate, drag and drop your\n'license.key' file here.", font="-size 11", justify="center", anchor="center", bootstyle="secondary")
        
        # --- Support and Footer Frames (Original Layout) ---
        
        support_frame = ttk.LabelFrame(outer_container, text="Contact", padding=15)
        support_frame.pack(fill="x", pady=(0, 15), anchor="n")
        line_frame = ttk.Frame(support_frame)
        line_frame.pack(fill="x", anchor="w")
        ttk.Label(line_frame, text="Need help in the integration process? You can hire me to streamline and style your setup.").pack(side="left")
        email_button = ttk.Button(
            line_frame, text="fredlm@ruederome.com", bootstyle="link-primary",
            command=lambda: webbrowser.open("mailto:fredlm@ruederome.com")
        )
        email_button.pack(side="left")

        # Add Legal link to Contact section
        legal_button = ttk.Button(
            line_frame, text="Legal ↗", bootstyle="link-primary",
            command=self._show_legal_popup
        )
        legal_button.pack(side="left", padx=(10, 0))


        footer_frame = ttk.Frame(outer_container)
        footer_frame.pack(fill="x", pady=(10, 0), side="bottom")
        # Copyright moved to header below "Legato-Key Certification Authority Dashboard"


    # --- Utility Methods ---

    def update_pro_license_status_display(self, open_folder_handler, drop_handler):
        """Display current license status or activation options (macOS folder/Windows drag-drop)."""
        self.lic_customer_label.pack_forget()
        self.lic_features_label.pack_forget()
        self.mac_activate_label.pack_forget()
        self.mac_open_folder_button.pack_forget()
        self.dnd_activate_label.pack_forget()

        self.about_tab_frame.drop_target_register("DND_Files")
        self.about_tab_frame.dnd_bind("<<Drop>>", drop_handler)

        if self.logic.license_manager.is_licensed:
            customer = self.logic.license_manager.customer_info
            expiry = self.logic.license_manager.expiry_date

            status_text = f"Pro Licensed to:\n{customer}"
            if expiry:
                try:
                    import datetime
                    exp_date = datetime.datetime.strptime(expiry, '%Y-%m-%d').date()
                    formatted_expiry = exp_date.strftime('%d/%m/%Y')
                    status_text += f"\n\nExpires: {formatted_expiry}"
                except:
                    status_text += f"\n\nExpires: {expiry}"

            self.lic_customer_label.config(text=status_text)
            self.lic_customer_label.pack(pady=(0, 10))
        else:
            if sys.platform == 'darwin':
                self.mac_open_folder_button.config(command=open_folder_handler)
                self.mac_activate_label.pack(pady=(10, 10))
                self.mac_open_folder_button.pack(fill='x', pady=5)
            else:
                self.dnd_activate_label.pack(fill="both", expand=True)

    def _update_wraplength(self, event, label_widget):
        label_widget.config(wraplength=event.width - 20)

    
    # ---  Button Click ---
    def update_ui_state(self, has_identity: bool):
        """Enable upgrade button if identity exists and license not active."""

        if hasattr(self, 'upgrade_button'):
            is_licensed = self.logic.license_manager.is_licensed
            should_be_active = has_identity and not is_licensed
            new_state = NORMAL if should_be_active else DISABLED
            self.upgrade_button.config(state=new_state)


    def _handle_upgrade_button_click(self):
        """Start purchase flow in modal window if issuer exists."""
        logging.debug("InfoTabs._handle_upgrade_button_click: Button clicked")
        if not self.logic.active_issuer_id:
            show_error("Action Blocked", "Please create or load an Issuer Identity before starting the purchase flow.")
            return
        progress_ui_handler = PurchaseProgressUI(self.logic.ui_callback.root, self)
        self.logic.delegate_purchase_flow_threaded(progress_ui_handler)
        # Disable the button and show the progress window
        self.upgrade_button.config(state=DISABLED)
        progress_ui_handler.show()

    def _show_legal_popup(self):
        """Open modal with legal notices and license files as tabbed interface."""
        try:
            # Find licenses directory - it's at project root
            # Try multiple locations for flexibility (dev, bundled, etc)
            possible_locations = [
                Path(__file__).parent.parent / "licenses",  # In source: ui/../licenses
                resource_path("licenses"),                   # In bundled: resources/licenses
                Path.cwd() / "licenses",                     # In current working directory
            ]

            licenses_dir = None
            for location in possible_locations:
                if location.exists():
                    licenses_dir = location
                    logging.info(f"[LEGAL] Found licenses directory: {licenses_dir}")
                    break

            if not licenses_dir:
                show_error("Not Found", f"Licenses directory not found in:\n" +
                          "\n".join(str(loc) for loc in possible_locations))
                return

            # Create popup window
            legal_window = Toplevel(self.notebook.winfo_toplevel())
            legal_window.title("Legal Notices & Licenses")
            legal_window.geometry("800x600")
            legal_window.minsize(600, 400)

            # Center the window
            legal_window.update_idletasks()
            x = (legal_window.winfo_screenwidth() // 2) - (800 // 2)
            y = (legal_window.winfo_screenheight() // 2) - (600 // 2)
            legal_window.geometry(f"+{x}+{y}")

            # Create frame with tabs or sections
            main_frame = ttk.Frame(legal_window, padding=10)
            main_frame.pack(fill="both", expand=True)

            # Title
            title_label = ttk.Label(main_frame, text="Legal Notices & Third-Party Licenses",
                                    font=("-size", 14, "-weight", "bold"))
            title_label.pack(anchor="w", pady=(0, 10))

            # Create notebook for tabs
            notebook = ttk.Notebook(main_frame)
            notebook.pack(fill="both", expand=True, pady=10)

            # Load all .txt files from licenses directory
            license_files = sorted(licenses_dir.glob("*.txt"))

            if not license_files:
                show_error("Not Found", "No license files found in licenses directory.")
                legal_window.destroy()
                return

            for license_file in license_files:
                try:
                    # Read file content
                    content = license_file.read_text(encoding='utf-8')

                    # Create tab
                    tab_frame = ttk.Frame(notebook, padding=10)
                    notebook.add(tab_frame, text=license_file.stem)

                    # Add scrolled text widget
                    text_widget = ScrolledText(tab_frame, wrap="word", height=20, width=80)
                    text_widget.pack(fill="both", expand=True)
                    text_widget.insert("1.0", content)
                    
                    # Make read-only - suppress warning if state parameter not supported
                    try:
                        text_widget.configure(state=DISABLED)
                    except Exception:
                        # FIX: Specific exception handling + try/except fallback
                        try:
                            text_widget.text.config(state=DISABLED)
                        except Exception as e:
                            logging.debug(f"Could not set text widget state to disabled: {e}")

                except Exception as e:
                    logging.warning(f"Failed to load license file {license_file.name}: {e}")
                    continue

            # Close button
            close_button = ttk.Button(main_frame, text="Close", command=legal_window.destroy)
            close_button.pack(anchor="e", pady=(10, 0))

        except Exception as e:
            logging.error(f"Error opening legal popup: {e}", exc_info=True)
            show_error("Error", f"Failed to open legal notices: {e}")

# --- PurchaseProgressUI Class (for the modal window) ---

class PurchaseProgressUI:
    """Modal window showing license purchase and activation polling progress."""
    def __init__(self, master, info_tabs_instance):
        """Build modal with status display, progress bar, and result buttons."""
        from ttkbootstrap.constants import HORIZONTAL

        self.master = master
        self.info_tabs = info_tabs_instance
        self.top = Toplevel(master)
        self.top.title("Pro License Activation")
        self.top.resizable(False, False)
        
        # Center the window
        self.top.update_idletasks()
        width = 500 
        height = 300 
        x = (self.top.winfo_screenwidth() // 2) - (width // 2)
        y = (self.top.winfo_screenheight() // 2) - (height // 2)
        self.top.geometry(f'{width}x{height}+{x}+{y}')
        
        self.top.protocol("WM_DELETE_WINDOW", self._on_close_attempt)
        
        main_frame = ttk.Frame(self.top, padding=20)
        main_frame.pack(fill="both", expand=True)

        self.status_label = ttk.Label(main_frame, text="Initializing purchase flow...", font="-weight bold", bootstyle=PRIMARY)
        self.status_label.pack(fill="x", pady=(0, 10))

        self.detail_label = ttk.Label(main_frame, text="Contacting Stripe API...", wraplength=450)
        self.detail_label.pack(fill="x", pady=(0, 20))
        
        self.progress_bar = ttk.Progressbar(main_frame, orient=HORIZONTAL, length=400, mode="determinate")
        self.progress_bar.pack(fill="x", pady=(0, 5))
        
        self.poll_count_label = ttk.Label(main_frame, text="")
        self.poll_count_label.pack(anchor="e", pady=(0, 10))

        self.close_button = ttk.Button(main_frame, text="Close", command=self.top.destroy, bootstyle=SECONDARY, state=DISABLED)
        self.close_button.pack(pady=(10, 0))

    def show(self):
        """Display modal as foreground window (modal)."""
        self.master.grab_set()
        self.top.deiconify()

    def _on_close_attempt(self):
        """Prevent window close during activation; inform user to wait."""
        from models.utils import show_info
        if self.close_button.cget("state") == NORMAL:
            self.top.destroy()
        else:
            show_info("Activation In Progress", "Please complete your payment and wait for the license key retrieval to finish.")


    # --- Callbacks  ---

    def on_polling_start(self, total_seconds: int):
        # This method is now called AFTER the initial wait
        # because there is no need to pool while user it trying to find his credit card :p
        self.status_label.config(text="Payment Window Expired. Checking for License...", bootstyle=WARNING)
        self.detail_label.config(text=f"Now actively polling the server for your license key. This will take up to {total_seconds} seconds.")
        self.progress_bar.config(mode="indeterminate")
        self.progress_bar.start(100)
        self.poll_count_label.config(text="Polling...")

    def on_polling_progress(self, current: int, total: int):
        self.progress_bar.stop()
        self.progress_bar.config(mode="determinate", maximum=total, value=current)
        self.detail_label.config(text=f"License retrieval in progress. Attempting fetch from server...")
        self.poll_count_label.config(text=f"Check {current}/{total}")
        

    def on_polling_success(self, message: str):
        self.progress_bar.stop()
        self.status_label.config(text="✅ Activation Complete!", bootstyle=SUCCESS)
        self.detail_label.config(text=f"The license key was successfully retrieved and activated. {message}")
        self.close_button.config(state=NORMAL)
        self.info_tabs.upgrade_button.config(state=DISABLED) 
        self.top.protocol("WM_DELETE_WINDOW", self.top.destroy) 
        show_info("Success", "Professional license has been successfully activated!")


    def on_polling_failure(self, message: str):
        self.progress_bar.stop()
        self.status_label.config(text="❌ Activation Failed!", bootstyle=DANGER)
        self.detail_label.config(text=f"The purchase failed or the license key could not be retrieved.\n\nDetails: {message}\n\nPlease check the logs and try again.")
        self.close_button.config(state=NORMAL)
        # Reset button state to proper logic-based state instead of hardcoding NORMAL
        self.info_tabs.update_ui_state(has_identity=bool(self.info_tabs.logic.active_issuer_id))
        self.top.protocol("WM_DELETE_WINDOW", self.top.destroy)
        show_error("Activation Failed", message)
        
    def on_initial_wait_start(self, wait_seconds: int):
        wait_minutes = wait_seconds // 60
        self.status_label.config(text="Waiting for Payment Completion...", bootstyle=PRIMARY)
        self.detail_label.config(text=f"Please complete your payment in the browser. This window will remain open for {wait_minutes} minutes, then automatically begin checking for your license.")
        self.progress_bar.config(mode="determinate", maximum=100, value=100) # Show a full, static bar
        self.poll_count_label.config(text=f"Waiting ({wait_minutes} min)...")