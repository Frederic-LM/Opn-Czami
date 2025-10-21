# ui/app.py
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
import logging
import shutil
import sys
import webbrowser
from pathlib import Path
import threading

# --- Third-Party Imports ---
import ttkbootstrap as ttk
from PIL import Image, ImageTk
from ttkbootstrap.constants import *
from tkinter import font, messagebox

# --- Local Imports ---
# Logic Layer
from opn_czami_logic import OpnCzamiLogic

# Models (for constants and utilities)
from models.config import APP_DATA_DIR, APP_VERSION
from models.utils import resource_path, show_error, show_info

# UI Components
from .core_workflow_tabs import CoreWorkflowTabs
from .settings_tabs import SettingsTabs
from .pro_feature_tabs import ProFeatureTabs
from .info_tabs import InfoTabs


class OpnCzamiApp:
    """
    The main application orchestrates the mainframe window,
    and the global status panel loads and manages the individual tab.
    """
    def __init__(self, root: ttk.Window):
        self.root = root
        self._after_id = None
        self._configure_root_window()

        # Initialize the single instance of Op'n-Czami logic
        self.logic = OpnCzamiLogic(ui_callback_interface=self)

        # --- Create Main UI Structure ---
        self.create_status_panel()
        self.notebook = self.create_notebook()

        # --- Start UI Components (Tabs) ---
        # Each component is now responsible for creating its own tabs
        self.tabs = {
        "core": CoreWorkflowTabs(self.notebook, self.logic),       # Tabs 1 & 2
        "settings": SettingsTabs(self.notebook, self.logic),   # Tabs 3 & 4
        "pro": ProFeatureTabs(self.notebook, self.logic),       # Tabs 5 & 6 (Batch, Audit)
        "info": InfoTabs(self.notebook, self.logic)        # Tabs 8 & 9 (Guide, About)
        }

        # "About" tab will ALWAYS listens for drops, regardless of license state.
        # (only for non-macOS platforms).
        if sys.platform != 'darwin':
            about_tab_frame = self.tabs["info"].about_tab_frame
            about_tab_frame.drop_target_register("DND_Files")
            # Bind the drop event on that frame to our handler method
            about_tab_frame.dnd_bind("<<Drop>>", self.handle_license_drop)

        # --- Finalize Initialization ---
        self._bind_events()
        self.logic.load_initial_data() 
        self.start_license_watcher_threaded()

        
    # --- Web3 Satus Display Handler  ---
    def _open_web3_anchor_link(self, event=None):
        """Opens the IPFS gateway link using the current CID from logic."""
        ipfs_cid = self.logic.active_issuer_data.get("ipfsCid")
        
        if ipfs_cid:
            # Only open if a CID exists
            webbrowser.open(f"https://ipfs.io/ipfs/{ipfs_cid}")
        else:
            # Show an informational message if they click on an inactive feature
            show_info("Web3 Anchor Not Set", "The Decentralized IPFS Anchor (a Pro Feature) is not yet enabled or successfully published for this identity.")

    def on_managed_anchor_complete(self, success: bool, message: str):
        """Delegates  completion of all managed anchor operations to the settings tab."""
        if self.tabs and "settings" in self.tabs:
            self.tabs["settings"].on_managed_anchor_complete(success, message)

    def on_ipfs_status_update(self, is_online: bool, ipfs_cid: str):
        """Updates main status panel with a clean, concise IPFS status."""
        if is_online:
 
            final_text = "| Web3 Anchor (Online ✓)"
            style = "success"
            cursor = "hand2" # it's clickable
        else:
            final_text = "| Web3 Anchor (Offline ✗)"
            style = "danger"
            cursor = "" # Normal cursor

        self.web3_status_label.config(text=final_text, bootstyle=style, cursor=cursor)
        
        # The "Info" tab can still show the full CID, so this part is unchanged.
        if "info" in self.tabs:
            self.tabs["info"].update_ipfs_link_display(ipfs_cid, is_online)
            
    def on_web3_anchor_complete(self, success: bool, message: str):
        if self.tabs and "settings" in self.tabs:
            self.tabs["settings"].on_web3_anchor_complete(success, message)
            

    # --- UI and Window Configuration ---
    def get_ui_config_data(self) -> dict:
            """
            Get the current configuration data from all relevant UI components.
            This allows the logic layer to request the latest state from the UI on-demand.
            """
            if self.tabs and "settings" in self.tabs:
                return self.tabs["settings"].get_ui_config_data()
            return {}
        
    # --- Window Scaling ETC ---
    # done in an empirical way (hack) to accommodate different OS and Screen behaviors
    # works reasonably well across platforms on not to old hardware and high dpi screens
        
    def _configure_root_window(self):
        """Sets up the main application window properties."""
        self.root.title("Op’n-Czami - Legato-Key Certification Authority Dashboard")
        
        # --- ORIGINAL BASE GEOMETRY ---
        BASE_WIDTH = 1270
        BASE_HEIGHT = 985
        
        # --- MACOS SCALING FIX (ISOLATED) ---
        if sys.platform == 'darwin':
            TARGET_SCALE = 1.5
            self.root.tk.call('tk', 'scaling', TARGET_SCALE) 
            screen_height = self.root.winfo_screenheight()
            pixel_height = BASE_HEIGHT * TARGET_SCALE
            if pixel_height > screen_height:
                 NEW_BASE_HEIGHT = int((screen_height * 0.95) / TARGET_SCALE)
            else:
                NEW_BASE_HEIGHT = BASE_HEIGHT
        else:
            # --- WINDOWS/LINUX/OTHER (Use original fixed size) ---
            NEW_BASE_HEIGHT = BASE_HEIGHT
            # No base tk scaling is forced, relying on the OS/DPI aware mode
        # --- END MACOS FIX ---

        # Apply geometry, which is either the original or the reduced Mac size
        self.root.geometry(f"{BASE_WIDTH}x{NEW_BASE_HEIGHT}")
        self.root.minsize(BASE_WIDTH, NEW_BASE_HEIGHT)
        self.root.resizable(False, True)
        self._set_window_icon()

    def _set_window_icon(self):
        """Sets the application icon based on the os."""
        try:
            ico_path = resource_path("icon.ico")
            png_path = resource_path("icon.png")
            if sys.platform == "win32" and ico_path.exists():
                self.root.iconbitmap(ico_path)
            elif png_path.exists():
                photo = ttk.PhotoImage(file=png_path)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.error(f"Could not set window icon: {e}", exc_info=True)

    def _bind_events(self):
        """Binds root-level events."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Configure>", self._on_configure_debounced)

    def on_close(self):
        """Handles application shutdown procedures."""
        temp_dir = APP_DATA_DIR / "temp_upload"
        if temp_dir.exists() and temp_dir.is_dir():
            try:
                shutil.rmtree(temp_dir)
                logging.info(f"Securely removed temp directory: {temp_dir}")
            except OSError as e:
                logging.warning(f"Could not fully remove temp directory on exit: {e}")
        self.root.destroy()

    # --- DPI/Scaling ---

    def _on_configure_debounced(self, event=None):
        """Debounces window configuration changes to avoid excessive DPI calculations."""
        if self._after_id:
            self.root.after_cancel(self._after_id)
        self._after_id = self.root.after(200, self._apply_dpi_scaling)
        
     # --- Final Pain ---
         
    def _apply_dpi_scaling(self, event=None):


        try:
            # --- CRITICAL! kick MAC  ---
            if sys.platform == 'darwin':
                 return # Mac is handled above by the tk scaling call in _configure_root_window
            # --- END CRITICAL ---
            
            # --- WINDOWS/LINUX SCALING LOGIC ---
            
            last_scaling_factor = getattr(self, "_last_scaling_factor", 0)
            DESIGN_DPI = 96.0
            
            current_dpi = self.root.winfo_fpixels("1i") 
            scaling_factor = current_dpi / DESIGN_DPI

            if abs(scaling_factor - last_scaling_factor) < 0.05:
                return

            self._last_scaling_factor = scaling_factor
            logging.info(f"DPI change detected. Applying new scaling factor: {scaling_factor:.2f}")

            # --- FINAL FONT BASELINE LOGIC ---
            # I'll leave heavy comments here if you need to tweak this in the future.
            # 1. Base sizes for 1.0x (1440p) screen where scaling fails (needs a minimum of 8).
            BASE_SIZE_1X = 8        # Minimum size required for 1440p (1.0x)
            BASE_SIZE_4K = 9        # Base size for 4K where scaling applies (2.0x) (in fact it is more 1.5x)
   
            
            # 2. Calculate Scaled Size: Check if the factor is near 1.0 (1440p) or higher (4K).
            if scaling_factor < 1.1:
                # If scaling factor is near 1.0, use the minimum required size (8)
                scaled_size = BASE_SIZE_1X  
            elif scaling_factor < 1.6:
                # 1.5x screen (4K): We override the calculated size and use the desired smaller size (6)
                # This is the manual fix for the 1.5x scaling misbehavior
                scaled_size = BASE_SIZE_4K
                
            else:
                # 2.0x+ screen (Very High DPI): Apply the factor to the smallest base (6)
                # This handles scenarios where the scaling factor is 2.0 or greater.
                raw_scaled_size = int(BASE_SIZE_4K * scaling_factor)
                
                # We can cap it at 12 to prevent going wild on 2.5x or 3.0x screens
                MAX_FONT_SIZE = 12
                scaled_size = min(raw_scaled_size, MAX_FONT_SIZE)
                
            # Apply the calculated scaled_size to the three base types
            # Note: You can customize individual sizes if needed, e.g. scaled_tab_size = scaled_size - 1
            
            scaled_default_size = scaled_size
            scaled_text_size = scaled_size
            scaled_tab_size = scaled_size
            
           

            style = ttk.Style.get_instance()
            default_family = font.nametofont("TkDefaultFont").cget("family")

            style.configure("TLabel", font=(default_family, scaled_default_size))
            style.configure("TButton", font=(default_family, scaled_default_size))
            style.configure("TCheckbutton", font=(default_family, scaled_default_size))
            style.configure("TRadiobutton", font=(default_family, scaled_default_size))
            style.configure("TEntry", font=(default_family, scaled_text_size))
            style.configure("TCombobox", font=(default_family, scaled_text_size))
            style.configure("TLabelframe.Label", font=(default_family, scaled_default_size, "bold"))
            style.configure("TNotebook.Tab", font=(default_family, scaled_tab_size))

            self.root.option_add("*Text*Font", (default_family, scaled_text_size))
            self.set_status_logo(self.logic.original_status_logo_pil)

        except Exception as e:
            logging.error(f"Failed to apply DPI scaling: {e}", exc_info=True)

    # --- Main UI Creation ---

    def create_status_panel(self):
        """Creates the top-lvl status display frame."""
        self.status_frame = ttk.LabelFrame(self.root, text="System Status", padding=10)
        self.status_frame.pack(fill=X, padx=10, pady=(10, 0))

        logo_frame = ttk.Frame(self.status_frame, width=180, height=100)
        logo_frame.pack(side=LEFT, padx=(0, 15), anchor='nw')
        logo_frame.pack_propagate(False)

        self.status_logo_label = ttk.Label(logo_frame)
        self.status_logo_label.pack(fill="both", expand=True)

        info_frame = ttk.Frame(self.status_frame)
        info_frame.pack(side=LEFT, fill=X, expand=True)

        self.status_message_label = ttk.Label(info_frame, text="Starting up...", font="-weight bold", bootstyle=PRIMARY)
        self.status_message_label.pack(anchor=W)

    
    
    # --- TWO-LABEL LAYOUT ---
        details_container = ttk.Frame(info_frame)
        details_container.pack(fill=X, anchor=W, pady=(5, 0))

        self.status_details_label = ttk.Label(details_container, text="Load an identity or create one to begin.")
        self.status_details_label.pack(side=LEFT, anchor=W)

        self.web3_status_label = ttk.Label(details_container, text="") # Starts empty
        self.web3_status_label.pack(side=LEFT, anchor=W, padx=(10, 0))
      
        self.web3_status_label.bind("<Button-1>", self._open_web3_anchor_link)
            
        self.pro_status_label = ttk.Label(info_frame, text="Pro License: Not Active", bootstyle=WARNING)
        self.pro_status_label.pack(anchor=W, pady=(5, 0))

        self.check_status_button = ttk.Button(self.status_frame, text="Check Status", command=self.logic.check_system_status_threaded, state=DISABLED, bootstyle=SECONDARY)
        self.check_status_button.pack(side=RIGHT, anchor=S, padx=(10, 0))

        ttk.Separator(self.root, orient=HORIZONTAL).pack(fill=X, padx=10, pady=5)

    def create_notebook(self) -> ttk.Notebook:
        """Main Notebook widget that will contain all the tabs."""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=True)
        notebook = ttk.Notebook(main_frame, bootstyle=PRIMARY)
        notebook.pack(fill=BOTH, expand=True)
        return notebook

    # --- Global UI State Management ---

    def update_ui_state(self):
        """
        Enables or disables tabs and features based on global app state.
        Pro tabs ar no longer locked.
        """
        has_identity = bool(self.logic.active_issuer_id)
        is_licensed = self.logic.license_manager.is_licensed 

        # Loop enables ALL tabs after the first one if an identity exists.
        for i in range(1, self.notebook.index(END)):
            self.notebook.tab(i, state=NORMAL if has_identity else DISABLED)

        if "core" in self.tabs:
            self.tabs["core"].update_ui_state(has_identity)
        if "settings" in self.tabs:
            self.tabs["settings"].update_ui_state(has_identity)
        if "pro" in self.tabs:
            self.tabs["pro"].update_ui_state(has_identity)
        
        # --- AUDIT LOG REFRESH LOGIC ---
        # Only refresh the audit log if:
        # 1. An identity is loaded.
        # 2. The audit feature is enabled in config.
        # 3. The app is licensed 
        if has_identity and self.logic.config.enable_audit_trail and is_licensed:
            pro_tab = self.tabs.get("pro")
  
            if pro_tab and hasattr(pro_tab, '_handle_refresh_audit'): 
                pro_tab._handle_refresh_audit()

        self.update_pro_license_status_display()
        
        # --- STATUS FALLBACK ---
        if not has_identity:
            self.status_message_label.config(text="No identity. Create one to begin.", bootstyle=PRIMARY)
            self.status_details_label.config(text="Go to the 'Issuer Identity' tab.")
            self.set_status_logo(None)
            self.check_status_button.config(state=DISABLED)

    def set_status_logo(self, pil_image: Image.Image):
        """Sets the logo in the status panel, handling resizing."""
        self.logic.original_status_logo_pil = pil_image

        container_width = self.status_logo_label.master.winfo_width()
        container_height = self.status_logo_label.master.winfo_height()
        if container_width <= 1: container_width = 180
        if container_height <= 1: container_height = 100

        if pil_image:
            display_logo = pil_image.copy()
            display_logo.thumbnail((container_width, container_height), Image.Resampling.LANCZOS)
            self.status_logo_tk = ImageTk.PhotoImage(display_logo)
            self.status_logo_label.config(image=self.status_logo_tk, background="")
        else:
            self.status_logo_tk = None
            self.status_logo_label.config(image="", background="lightgray")

    # --- Logic -> UI Callbacks ---

    def on_logic_data_loaded(self, success: bool):
        if self.logic.active_issuer_id:
            self.notebook.select(1)
            self.root.after(500, self.logic.check_system_status_threaded)

        self.update_ui_state()

    def on_identity_creation_success(self, issuer_id: str, config, ftp_guess: str):
        show_info("Success & Next Steps",
            "IDENTITY CREATED SUCCESSFULLY!\n\n"
            "Your critical identity files have been generated and MUST be backed up.\n\n"
            "NEXT STEP: SERVER SETUP\n\n"
            "You will now be taken to the 'Settings' tab to finalize your server configuration."
        )
        self.update_ui_state()
        self.logic.check_system_status_threaded()
        self.notebook.select(2)

    def on_identity_deleted(self):
        self.tabs["core"].on_identity_deleted()
        self.notebook.select(0)
        self.update_ui_state()

    def on_status_check_start(self, info_url: str):
        self.check_status_button.config(state=DISABLED)
        self.status_message_label.config(text="Checking...", bootstyle=WARNING)
        self.status_details_label.config(text=f"Fetching: {info_url}")
        self.web3_status_label.config(text="") 
        self.set_status_logo(None)
        self.tabs["core"].update_manage_frame_display()

    def on_status_check_complete(self, success: bool, msg: str, style: str, details: str, logo_pil: Image.Image = None):
        self.status_message_label.config(text=msg, bootstyle=style)
        self.status_details_label.config(text=details)
        self.check_status_button.config(state=NORMAL)
        self.set_status_logo(logo_pil)
        
        if success:
            self.tabs["core"].update_issuer_qr_display()
            self.tabs["core"].update_manage_frame_display()
            self.update_ui_state()
        
        # Trigger the Web3 check, which will populate the second label
        self.check_and_display_web3_status()
    
    def on_critical_security_failure(self):
        show_error("CRITICAL SECURITY FAILURE", "Failed to move the private key back to the OS Keychain. The key is currently stored insecurely on disk. Please re-enable Hardened Security manually from the Backup & Security tab immediately.")

    # --- Callback & Delegation to UI Components ---

    def on_ipfs_publish_start(self):
        # Find the Settings tab instance
        settings_tab = self.tabs["settings"]
        settings_tab.web3_anchor_check.config(state=DISABLED, text="Publishing Anchor...")

    def on_ipfs_publish_complete(self):
        settings_tab = self.tabs["settings"]
        
        # Re-enable and reset the text 
        if self.logic.active_issuer_data.get("ipfsCid"):
            settings_tab.web3_anchor_check.config(state=NORMAL, text="Enable Decentralized IPFS Anchor")
            # is toggle ON?
            settings_tab.web3_anchor_var.set(True) 
            show_info("Success", "IPFS Anchor is now enabled and active!")
        else:
            # If it failed, show an error and ensure the toggle is OFF
            settings_tab.web3_anchor_check.config(state=NORMAL, text="Enable Decentralized IPFS Anchor")
            settings_tab.web3_anchor_var.set(False) 

        # Now update the entire UI with new state (e.g., the status )
        self.update_ui_state()
            
    
    def check_and_display_web3_status(self):
        ipfs_cid = self.logic.active_issuer_data.get("ipfsCid")
        is_web3_licensed = self.logic.license_manager.is_feature_enabled("web3")

        if ipfs_cid and is_web3_licensed:
            self.web3_status_label.config(text=f"| Web3 Anchor: ipfs://{ipfs_cid} (Verifying...)", bootstyle="warning", cursor="")
            self.logic.pro_handler.check_ipfs_link_threaded(ipfs_cid)
        else:
            # If no CID exists, but the user is licensed (or not), we should still clear the binding
            # The label is set to blank, but explicitly clear the clickability.
            self.web3_status_label.config(text="", cursor="") 
         

    def on_identity_creation_failed(self, message: str):
        self.tabs["core"].on_identity_creation_failed(message)
        
    def sync_ui_from_config(self, config, priv_key_pem: str):
        self.tabs["settings"].sync_ui_from_config(config, priv_key_pem)

    def on_signing_start(self):
        self.tabs["core"].on_signing_start()

    def on_signing_failure(self, message: str):
        self.tabs["core"].on_signing_failure(message)

    def on_signing_success(self, prepared_upload_path: Path, qr_image_pil: Image.Image, last_signed_payload: str, was_auto_upload_successful: bool, final_lkey_image_with_overlay: Image.Image):
        """Delegates signing success event to the core workflow tabs."""
        self.tabs["core"].on_signing_success(prepared_upload_path, qr_image_pil, last_signed_payload, was_auto_upload_successful, final_lkey_image_with_overlay)

    def on_batch_load_start(self):
        self.tabs["pro"].on_batch_load_start()

    def on_batch_load_success(self, filename: str, total_items: int, row_data: list):
        self.tabs["pro"].on_batch_load_success(filename, total_items, row_data)

    def on_batch_load_failure(self, message: str):
        self.tabs["pro"].on_batch_load_failure(message)

    def on_batch_process_start(self, total_items: int):
        self.tabs["pro"].on_batch_process_start(total_items)

    def on_batch_item_processing(self, item_id: str, values: tuple):
        self.tabs["pro"].on_batch_item_processing(item_id, values)

    def on_batch_item_complete(self, item_id: str, values: tuple, tag: str):
        self.tabs["pro"].on_batch_item_complete(item_id, values, tag)

    def on_batch_process_complete(self):
        self.tabs["pro"].on_batch_process_complete()

    # --- License Management (Global) ---

    def start_license_watcher_threaded(self):
        if sys.platform != 'darwin' or self.logic.license_manager.is_licensed: return
        if getattr(self, "_license_watcher_running", False): return
        self._license_watcher_running = True
        threading.Thread(target=self._license_watcher_worker, daemon=True).start()

    def _license_watcher_worker(self):
        self.logic.license_manager.license_watcher_worker(self.on_license_activated_by_watcher)
        self._license_watcher_running = False

    def on_license_activated_by_watcher(self):
        self.root.after(0, lambda: show_info("Activation Successful!", f"Professional license for '{self.logic.license_manager.customer_info}' has been activated!\n\nAll features are now unlocked."))
        self.root.after(0, self.update_ui_state)

    def _open_license_folder(self):
        folder_path = APP_DATA_DIR
        folder_path.mkdir(parents=True, exist_ok=True)
        webbrowser.open(folder_path.as_uri())
        

    def handle_license_drop(self, event):
        filepath_str = event.data.strip("{}")
        dropped_path = Path(filepath_str)

        if dropped_path.name.lower() != "license.key":
            show_error("Invalid File", "Please drop a valid 'license.key' file.")
            return
        # If no issuer is loaded, pass a safe identifier like "N/A"
        active_id = self.logic.active_issuer_id or "N/A"
        
        try:
            success, message = self.logic.license_manager.activate_from_path(dropped_path, active_id)
            
            if success:
                show_info("License Updated", message)
            else:
                # NOTE: The LicenseManager now handles showing the Security Check Failed error itself.
                if "cancelled by user" not in message and "Activation requires an active Issuer Identity" not in message:
                    show_error("Activation Failed", message)

        except Exception as e:
            show_error("License Error", f"An unexpected error occurred during activation: {e}")
        finally:
            self.update_ui_state()

    def update_pro_license_status_display(self, event=None):

        if self.logic.license_manager.is_licensed:
            text = f"Pro License: {self.logic.license_manager.customer_info}"
            style = SUCCESS # Green
        elif self.logic.license_manager.is_licensed_expired:
            text = f"Pro License: EXPIRED / {self.logic.license_manager.customer_info}"
            style = DANGER # Red
        else:
            text = "Pro License: Not Active"
            style = WARNING # Orange
            
        self.pro_status_label.config(text=text, bootstyle=style)
        
        if self.tabs and "info" in self.tabs:
            self.tabs["info"].update_pro_license_status_display(
                self._open_license_folder, 
                self.handle_license_drop
            )
    def on_status_check_complete_from_worker(self, results_dict: dict):
        """
        Runs the final UI update on the main thread.
        Unpacks the detailed error information set by the worker.
        """
        success = results_dict.get("success", False)
        msg = results_dict.get("msg", "Unknown Error")
        style = results_dict.get("style", DANGER)
        details = results_dict.get("details", "No detailed information available.")
        logo_pil = self.logic.original_status_logo_pil if success else None 
        self.on_status_check_complete(success, msg, style, details, logo_pil)
        
    def on_legacy_anchor_complete(self, success: bool, message: str):
        """Delegates the completion of the legacy anchor activation to the settings tab."""
        if self.tabs and "settings" in self.tabs:
            self.tabs["settings"].on_legacy_anchor_complete(success, message)