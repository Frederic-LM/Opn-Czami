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


import logging
import shutil
import sys
import webbrowser
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk
import ttkbootstrap
from PIL import Image, ImageTk
from ttkbootstrap.constants import *
from tkinter import font, messagebox

# --- Local Imports ---
# Logic Layer
from opn_czami import OpnCzamiLogic
from models.config import APP_DATA_DIR 
from models.utils import resource_path, show_error, show_info

# UI Components
from .core_workflow_tabs import CoreWorkflowTabs
from .settings_tabs import SettingsTabs
from .pro_feature_tabs import ProFeatureTabs
from .info_tabs import InfoTabs


class OpnCzamiApp:
    """Orchestrate main window and tab management via dependency injection."""
    def __init__(self, root: ttkbootstrap.Window, app_context, app_state):
        """Initialize with AppContext and AppState for clean DI (backward-compatible path removed)."""
        self.root = root
        self._after_id = None
        self._configure_root_window()

        # Initialize the single instance of Op'n-Czami logic with DI
        self.logic = OpnCzamiLogic(
            ui_callback_interface=self,
            app_context=app_context,
            app_state=app_state
        )

        # Subscribe to events from the logic layer
        self.event_bus = app_context.event_bus
        self.event_bus.subscribe("logic_data_loaded", self.on_logic_data_loaded)
        self.event_bus.subscribe("pro_license_status_update", self.update_pro_license_status_display)
        self.event_bus.subscribe("qr_insights_status_update", self.update_qr_insights_status)
        self.event_bus.subscribe("ui_state_update", self.update_ui_state)
        self.event_bus.subscribe("sync_ui_from_config", self.sync_ui_from_config)
        self.event_bus.subscribe("identity_creation_failed", self.on_identity_creation_failed)
        self.event_bus.subscribe("identity_creation_success", self.on_identity_creation_success)
        self.event_bus.subscribe("identity_deleted", self.on_identity_deleted)
        self.event_bus.subscribe("signing_start", self.on_signing_start)
        self.event_bus.subscribe("signing_success", self.on_signing_success)
        self.event_bus.subscribe("signing_failure", self.on_signing_failure)
        self.event_bus.subscribe("server_compatibility_status_update", self.update_server_compatibility_status)
        self.event_bus.subscribe("status_check_start", self.on_status_check_start)
        self.event_bus.subscribe("status_check_complete", self.on_status_check_complete)
        self.event_bus.subscribe("byok_complete", self.on_byok_complete)

        logging.info("[APP] OpnCzamiApp initialized with AppContext and AppState (DI)")

        # --- Create Main UI Structure ---
        self.create_status_panel()
        self.notebook = self.create_notebook()

        # --- Start UI Components (Tabs) ---
        # Each component is now responsible for creating its own tabs
        self.tabs = {
        "core": CoreWorkflowTabs(self.notebook, self.logic),       # Tabs 1-2: Issuer Identity, Sign Document
        "settings": SettingsTabs(self.notebook, self.logic),       # Tabs 6-7: Backup, Settings
        "pro": ProFeatureTabs(self.notebook, self.logic),          # Tabs 3-5: Dashboard, Sign Multiple, Audit Trail
        "info": InfoTabs(self.notebook, self.logic)                # Tabs 8-9: Guide, About
        }

        # Add backup and settings tabs after pro tabs to ensure correct tab ordering (1,2,3,4,5,6,7,8,9)
        self.tabs["settings"].add_backup_and_settings_tabs()

        # Add info tabs last to ensure they appear at the end (tabs 8-9)
        self.tabs["info"].add_info_tabs()

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

        # Trigger initial UI state update for all tabs
        # This ensures buttons like "Upgrade to Pro" are enabled/disabled correctly
        has_identity = bool(self.logic.active_issuer_id)

        if "core" in self.tabs:
            self.tabs["core"].update_ui_state(has_identity)
        if "settings" in self.tabs:
            self.tabs["settings"].update_ui_state(has_identity)
        if "pro" in self.tabs:
            # Don't load dashboard analytics on startup - only when user clicks the tab
            self.tabs["pro"].update_ui_state(has_identity, load_dashboard_analytics=False)
        if "info" in self.tabs:
            self.tabs["info"].update_ui_state(has_identity)

        self.start_license_watcher_threaded()


    def on_byok_complete(self, success: bool, message: str):
        """Delegate BYOK completion to settings tab."""
        if self.tabs and "settings" in self.tabs:
            self.tabs["settings"].on_byok_complete(success, message)


    # --- UI and Window Configuration ---
    def get_ui_config_data(self) -> dict:
            """Return current UI configuration from all tabs for logic layer to use."""
            if self.tabs and "settings" in self.tabs:
                return self.tabs["settings"].get_ui_config_data()
            return {}
        
    # --- Window Scaling ETC ---
    # done in an empirical way (hack) to accommodate different OS and Screen behaviors
    # works reasonably well across platforms on not to old hardware and high dpi screens
        
    def _configure_root_window(self):
        """Configure window properties (size, scaling, icon) based on platform."""
        self.root.title("Op’n-Czami - Legato-Key Certification Authority Dashboard")
        
        # --- ORIGINAL BASE GEOMETRY ---
        BASE_WIDTH = 1270
        BASE_HEIGHT = 985
        
        # --- MACOS SCALING FIX (ISOLATED) ---
        if sys.platform == 'darwin':
            TARGET_SCALE = 1.2
            self.root.tk.call('tk', 'scaling', TARGET_SCALE) 
            screen_height = self.root.winfo_screenheight()
            pixel_height = BASE_HEIGHT * TARGET_SCALE
            if pixel_height > screen_height:
                 NEW_BASE_HEIGHT = int((screen_height * 1.0) / TARGET_SCALE)
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
        """Set application icon (.ico on Windows, .png elsewhere)."""
        try:
            ico_path = resource_path("icon.ico")
            png_path = resource_path("icon.png")
            if sys.platform == "win32" and ico_path.exists():
                self.root.iconbitmap(ico_path)
            elif png_path.exists():
                photo = tk.PhotoImage(file=png_path)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.error(f"Could not set window icon: {e}", exc_info=True)

    def _bind_events(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Configure>", self._on_configure_debounced)
        # Bind notebook tab selection to refresh dashboard when tab is clicked
        self.notebook.bind("<<NotebookTabChanged>>", self._on_notebook_tab_changed)

    def on_close(self):
        temp_dir = APP_DATA_DIR / "temp_upload"
        if temp_dir.exists() and temp_dir.is_dir():
            try:
                shutil.rmtree(temp_dir)
                logging.info(f"Securely removed temp directory: {temp_dir}")
            except OSError as e:
                logging.warning(f"Could not fully remove temp directory on exit: {e}")
        self.logic.license_manager.stop_watcher()
        self.root.destroy()

    def _load_dashboard_analytics(self):
        """Load cached analytics in background thread and refresh dashboard UI."""
        if not self.logic.active_issuer_id:
            logging.warning("[APP] Cannot load dashboard: no active issuer")
            return

        def _direct_load():
            try:
                # logging.info("[APP] Loading dashboard analytics...")  # Commented out - verbose log for debugging
                self.logic.load_cached_analytics()
                # logging.info("[APP] Dashboard analytics loaded successfully")  # Commented out - verbose log for debugging
                if hasattr(self.tabs.get("pro"), '_refresh_dashboard_with_local_data'):
                    self.root.after(0, self.tabs["pro"]._refresh_dashboard_with_local_data)
                    # logging.debug("[APP] Dashboard UI refreshed with local data")  # Commented out - verbose log for debugging
            except Exception as e:
                logging.error(f"[APP] Failed to load dashboard analytics: {e}", exc_info=True)

        # Run in background thread to avoid blocking UI
        threading.Thread(target=_direct_load, daemon=True).start()

    def _on_notebook_tab_changed(self, event=None):
        """Load dashboard analytics or refresh audit trail when respective tabs are activated."""
        try:
            current_tab_index = self.notebook.index("current")

            if "pro" not in self.tabs:
                return

            dashboard_frame = self.tabs["pro"].dashboard_tab_frame
            audit_frame = self.tabs["pro"].audit_tab_frame

            # Find which tab is now active
            for i, tab_info in enumerate(self.notebook.tabs()):
                tab_widget = self.notebook.nametowidget(tab_info)

                if current_tab_index != i:
                    continue

                # Dashboard tab activated
                if tab_widget == dashboard_frame:
                    # logging.debug("[APP] Dashboard tab activated")  # Commented out - verbose log for debugging
                    self._load_dashboard_analytics()

                # Audit trail tab activated
                elif tab_widget == audit_frame:
                    # logging.debug("[APP] Audit trail tab activated")  # Commented out - verbose log for debugging
                    if hasattr(self.tabs["pro"], '_handle_refresh_audit'):
                        self.tabs["pro"]._handle_refresh_audit()

        except Exception as e:
            logging.error(f"Error handling tab change: {e}", exc_info=True)

    # --- DPI/Scaling ---

    def _on_configure_debounced(self, event=None):
        """Debounce window config events to delay DPI scaling calculations."""
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

            # --- FINAL FONT BASELINE LOGIC ---
            # I'll leave heavy comments here if you need to tweak this in the future.
            # 1. Base sizes for 1.0x (1440p) screen where scaling fails (needs a minimum of 8).
            BASE_SIZE_1X = 8        # Minimum size required for 1440p (1.0x)
            BASE_SIZE_4K = 8       # Base size for 4K where scaling applies (2.0x) (in fact it is more 1.5x)
   
            
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
            
           

            style = ttk.Style()
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
        """Build top-level status display with logo, status labels, and server check button."""
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

        self.pro_status_label = ttk.Label(info_frame, text="Pro License: Not Active", bootstyle=WARNING)
        self.pro_status_label.pack(anchor=W, pady=(5, 0))

        # Right-side status panel: Server compatibility and QR Insights
        right_status_frame = ttk.Frame(self.status_frame)
        right_status_frame.pack(side=RIGHT, fill=Y, anchor=NE, padx=(10, 0))

        # Server compatibility status (sticky display)
        self.server_status_label = ttk.Label(right_status_frame, text="", justify=RIGHT)
        self.server_status_label.pack(anchor=E, pady=(0, 1))

        # QR Insights/Logging status (sticky display)
        self.qr_insights_status_label = ttk.Label(right_status_frame, text="", justify=RIGHT)
        self.qr_insights_status_label.pack(anchor=E, pady=(0, 5))

        self.check_status_button = ttk.Button(right_status_frame, text="Check Server", command=self.logic.check_server_compatibility_threaded, state=DISABLED, bootstyle=SECONDARY)
        self.check_status_button.pack(anchor=E, pady=(5, 0))

        ttk.Separator(self.root, orient=HORIZONTAL).pack(fill=X, padx=10, pady=5)

    def create_notebook(self) -> ttk.Notebook:
        """Main Notebook widget that will contain all the tabs."""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=True)
        notebook = ttk.Notebook(main_frame, bootstyle=PRIMARY)
        notebook.pack(fill=BOTH, expand=True)

        # Bind tab change event to refresh Insights data when switching to Dashboard tab
        notebook.bind("<<NotebookTabChanged>>", self._on_notebook_tab_changed)

        return notebook

    # --- Global UI State Management ---

    def update_ui_state(self):
        """Enable/disable tabs and refresh all tab states based on identity and license status."""
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
            # Don't load dashboard analytics here - only when user clicks the Dashboard tab
            self.tabs["pro"].update_ui_state(has_identity, load_dashboard_analytics=False)
        if "info" in self.tabs:
            self.tabs["info"].update_ui_state(has_identity)    
        
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
        else:
            # Enable check server button when identity is loaded
            self.check_status_button.config(state=NORMAL)

    def set_status_logo(self, pil_image: Image.Image):
        """Display or clear logo in status panel, resizing to fit container."""
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
            # Note: System status check already triggered automatically in _load_issuer_data()
            # with _initial_status_check_fired guard to prevent redundant calls

            # Load dashboard analytics on startup
            # logging.info("[APP] Logic data loaded, loading dashboard analytics...")  # Commented out - verbose log for debugging
            self._load_dashboard_analytics()

        self.update_ui_state()

    def on_identity_creation_success(self, issuer_id: str, config, ftp_guess: str):
        show_info("Success & Next Steps",
            "IDENTITY CREATED SUCCESSFULLY!\n\n"
            "Your critical identity files have been generated and MUST be backed up.\n\n"
            "NEXT STEP: SERVER SETUP\n\n"
            "You will now be taken to the 'Settings' tab to finalize your server configuration."
        )
        self.update_ui_state()
        # Don't check status here - files haven't been uploaded yet (no FTP settings configured)
        # Status check will happen after user uploads files via Settings tab
        self.notebook.select(6)  # Settings tab is now at index 6

    def on_identity_deleted(self):
        self.tabs["core"].on_identity_deleted()
        self.notebook.select(0)
        self.update_ui_state()

    def on_status_check_start(self, info_url: str):
        self.check_status_button.config(state=DISABLED)
        self.status_message_label.config(text="Checking...", bootstyle=WARNING)
        self.status_details_label.config(text=f"Fetching: {info_url}")
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

    def update_server_compatibility_status(self, status_text: str):
        """Update the server compatibility status display (sticky)"""
        self.server_status_label.config(text=status_text)

    def update_qr_insights_status(self, enabled: bool):
        """Update the QR Insights/Logging status display (sticky)"""
        status_text = "| QR Insights: On" if enabled else "| QR Insights: Off"
        bootstyle = "success" if enabled else "secondary"
        self.qr_insights_status_label.config(text=status_text, bootstyle=bootstyle)

    def on_critical_security_failure(self):
        show_error("CRITICAL SECURITY FAILURE", "Failed to secure the private key in the OS Keychain. The key is currently stored insecurely on disk. Please contact support for assistance.")

    # --- Callback & Delegation to UI Components ---

    def on_identity_creation_failed(self, message: str):
        self.tabs["core"].on_identity_creation_failed(message)
        
    def sync_ui_from_config(self, config, priv_key_pem: str):
        self.tabs["settings"].sync_ui_from_config(config, priv_key_pem)

    def on_signing_start(self):
        self.tabs["core"].on_signing_start()

    def on_signing_failure(self, message: str):
        self.tabs["core"].on_signing_failure(message)

    def on_signing_success(self, prepared_upload_path: Path, qr_image_pil: Image.Image, last_signed_payload: str, was_auto_upload_successful: bool, final_lkey_image_with_overlay: Image.Image):
        """Delegates signing success event to the core workflow tabs and pro tabs (dashboard)."""
        self.tabs["core"].on_signing_success(prepared_upload_path, qr_image_pil, last_signed_payload, was_auto_upload_successful, final_lkey_image_with_overlay)
        # Also notify pro tabs to refresh the dashboard
        self.tabs["pro"].on_signing_success(prepared_upload_path, qr_image_pil, last_signed_payload, was_auto_upload_successful, final_lkey_image_with_overlay)


        # Dashboard will be refreshed when user manually clicks the tab or uses refresh button
        # This avoids unnecessary overhead after every signing operation

    def on_batch_load_start(self):
        self.tabs["pro"].on_batch_load_start()

    def on_batch_load_success(self, filename: str, total_items: int, row_data: list):
        self.tabs["pro"].on_batch_load_success(filename, total_items, row_data)

    def on_batch_load_failure(self, message: str):
        self.tabs["pro"].on_batch_load_failure(message)

    def on_batch_process_start(self, total_items: int):
        self.tabs["pro"].on_batch_process_start(total_items)

    def on_batch_item_processing(self, item_id: str, values: tuple, progress_info=None):
        # logging.info(f"[APP] on_batch_item_processing WRAPPER called: item_id={item_id}, progress_info={progress_info}")  # Commented out - verbose log for debugging
        self.tabs["pro"].on_batch_item_processing(item_id, values, progress_info)

    def on_batch_item_complete(self, item_id: str, values: tuple, tag: str, progress_info=None):
        # logging.info(f"[APP] on_batch_item_complete WRAPPER called: item_id={item_id}, progress_info={progress_info}")  # Commented out - verbose log for debugging
        self.tabs["pro"].on_batch_item_complete(item_id, values, tag, progress_info)

    def on_batch_process_complete(self):
        self.tabs["pro"].on_batch_process_complete()

    # --- License Management (Global) ---

    def start_license_watcher_threaded(self):
        self.logic.license_manager.start_watcher(self.on_license_activated_by_watcher)

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
            # Use licensing_handler (closed-source) for verification
            public_key_path = self.logic.license_manager.public_key_file
            success, result = self.logic.pro_handler.licensing_handler.verify_and_activate_license(
                dropped_path, active_id, public_key_path, self.logic.license_manager
            )

            if success:
                # result is the payload dict; update license_manager with the verified data
                payload = result
                self.logic.license_manager.set_license_data(
                    customer=payload.get("customer", "Licensed User"),
                    issuer_id=payload.get("issuer_id"),
                    expiry_date=payload.get("expiry_date"),
                    ipfs_cid=payload.get("ipfs_cid")
                )
                # Copy the verified license file to the target location
                self.logic.license_manager._replace_license_file(dropped_path)

                # SECURITY: Validate and enforce expiry (closed-source check)
                self.logic.pro_handler.licensing_handler.validate_and_enforce_license_expiry(self.logic.license_manager)

                # Show success message with appropriate status
                if self.logic.license_manager.is_licensed:
                    show_info("License Updated", f"License successfully activated for {payload.get('customer', 'Licensed User')}")
                elif self.logic.license_manager.is_licensed_expired:
                    show_error("License Expired", f"The license for {payload.get('customer', 'Licensed User')} has expired and cannot be activated.")
                else:
                    show_error("License Invalid", f"The license could not be activated.")
            else:
                # result is the error message
                message = result
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