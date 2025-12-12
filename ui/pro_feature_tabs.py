# ui/pro_feature_tabs.py
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
from pathlib import Path
import webbrowser
from functools import wraps
import threading

# --- Third-Party Imports ---
import tkinter as tk
from tkinter import ttk
import ttkbootstrap
from ttkbootstrap.constants import *
from ttkbootstrap.tableview import Tableview
from tkinter import filedialog, messagebox
from PIL import Image as PILImage, ImageTk, ImageDraw, ImageFont
from io import BytesIO

# --- Local Imports ---
from opn_czami import OpnCzamiLogic
from models.utils import show_error, show_info
from models.config import FEATURE_BATCH, FEATURE_AUDIT, FEATURE_DASHBOARD
from ui.dashboard import DashboardTab


class BatchProgressWindow:
    """Popup window showing batch processing progress."""

    def __init__(self, parent_window):
        """
        Create a progress popup window.

        Args:
            parent_window: Parent Tk/Ttk window
        """
        # logging.info("[BATCH_POPUP] Creating new popup window")  # Commented out - verbose log for debugging
        self.window = tk.Toplevel(parent_window)
        self.window.title("Batch Processing Progress")
        self.window.geometry("500x250")
        self.window.resizable(False, False)

        # Make window stay on top
        self.window.attributes('-topmost', True)
        # Center the window on parent (without blocking)
        self.window.transient(parent_window)
        # logging.info("[BATCH_POPUP] Popup window created and shown")  # Commented out - verbose log for debugging

        # Main frame with padding
        main_frame = ttk.Frame(self.window, padding=20)
        main_frame.pack(fill="both", expand=True)

        # Title label
        title_label = ttk.Label(main_frame, text="Processing Batch Files", font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 15))

        # Current file label
        self.file_label = ttk.Label(main_frame, text="Preparing...", wraplength=460, justify="left", bootstyle="info")
        self.file_label.pack(fill="x", pady=(0, 15))

        # Progress bar
        self.progress_bar = ttk.Progressbar(main_frame, mode="determinate", length=400)
        self.progress_bar.pack(fill="x", pady=(0, 10))

        # Progress text (e.g., "3 of 10")
        self.progress_text = ttk.Label(main_frame, text="0 of 0", bootstyle="secondary")
        self.progress_text.pack(pady=(0, 15))

        # Status message
        self.status_label = ttk.Label(main_frame, text="", wraplength=460, justify="left", bootstyle="secondary")
        self.status_label.pack(fill="x")

        # Make window modal
        self.window.focus()

    def close(self):
        """Close the progress window."""
        try:
            self.window.destroy()
        except Exception as e:
            logging.debug(f"Error closing progress window: {e}")

    def update_progress(self, current, total, filename, action="Processing"):
        """
        Update the progress window with current status.

        Args:
            current: Current item number (1-based)
            total: Total number of items
            filename: Name of file being processed
            action: Current action (e.g., "Processing", "Completed")
        """
        try:
            # Ensure current and total are integers (they might come as strings through root.after)
            current = int(current) if isinstance(current, str) else current
            total = int(total) if isinstance(total, str) else total
            filename = str(filename)

            # Update progress bar
            self.progress_bar.config(maximum=total, value=current if action != "Processing" else current - 1)

            # Update progress text
            self.progress_text.config(text=f"{current} of {total}")

            # Update file label
            self.file_label.config(text=f"Current file: {filename}")

            # Update status message
            if action == "Processing":
                self.status_label.config(text="Signing document...", bootstyle="info")
            elif action == "Completed":
                self.status_label.config(text="✓ Document signed and processed", bootstyle="success")

            # Force immediate UI update - critical for responsiveness
            self.window.update_idletasks()
            self.window.update()
            logging.debug(f"[BATCH_POPUP] Updated: {current}/{total} - {filename} ({action})")
        except Exception as e:
            logging.error(f"Error updating progress window: {e}")

    def set_complete(self):
        """Mark the batch as complete."""
        try:
            self.status_label.config(text="✓ Batch processing complete!", bootstyle="success")
            self.file_label.config(text="All files processed successfully")
            self.window.update_idletasks()
        except Exception as e:
            logging.error(f"Error marking batch complete: {e}")


class ProFeatureTabs:
    """Manages the 'Batch Processing', 'Audit Trail', and 'Dashboard' Pro tabs."""

    def __init__(self, notebook: ttk.Notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic

        # Guard flags to prevent redundant analytics loads
        self._analytics_loading = False  # True while analytics load is in progress
        self._last_loaded_issuer_id = None  # Track which issuer's data is currently displayed

        self.dashboard_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.batch_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.audit_tab_frame = ttk.Frame(self.notebook, padding=10)
        # Create dashboard using the new DashboardTab class
        self.dashboard_tab = DashboardTab(self.dashboard_tab_frame, self.logic)
        self._create_batch_signing_tab(self.batch_tab_frame)
        self._create_audit_viewer_tab(self.audit_tab_frame)
        self.notebook.add(self.dashboard_tab_frame, text=" 3. Dashboard ")
        self.notebook.add(self.batch_tab_frame, text=" 💎 4. Sign Multiple ")
        self.notebook.add(self.audit_tab_frame, text=" 💎 5. Audit Trail ")

    # --- Decorator for License Checks ---

    def _requires_feature(feature_name):
        def decorator(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                if not self.logic.license_manager.is_feature_enabled(feature_name):
                    self._show_upgrade_prompt(feature_name.replace("_", " ").title())
                    return
                return func(self, *args, **kwargs)
            return wrapper
        return decorator

    # --- Tab Creation Methods ---

    def _create_batch_signing_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)

        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.load_batch_button = ttk.Button(control_frame, text="📂 Load Data File...", command=self._handle_load_data_file, bootstyle=PRIMARY)
        self.load_batch_button.pack(side="left", padx=(0, 10))

        self.batch_file_label = ttk.Label(control_frame, text="No file loaded.", bootstyle="secondary")
        self.batch_file_label.pack(side="left", anchor="w")

        self.batch_coldata = [{"text": "Status", "stretch": False, "width": 150}, {"text": "Image File Path", "stretch": True}, {"text": "Summary", "stretch": True}]
        self.batch_tree = Tableview(parent_frame, coldata=self.batch_coldata, rowdata=[], paginated=False, searchable=False, bootstyle=PRIMARY)
        self.batch_tree.grid(row=1, column=0, sticky="nsew")
        
        action_frame = ttk.Frame(parent_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)

        # Auto-upload indicator
        self.batch_auto_upload_indicator = ttk.Label(action_frame, text="", bootstyle="success")
        self.batch_auto_upload_indicator.grid(row=0, column=1, sticky="e", padx=(0, 10))

        self.process_batch_button = ttk.Button(action_frame, text="▶️ Process Batch", command=self._handle_process_batch, state=DISABLED)
        self.process_batch_button.grid(row=0, column=2, sticky="e")

    def _create_audit_viewer_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)

        # Status label (no refresh button - audit auto-refreshes on tab entry)
        self.audit_status_label = ttk.Label(parent_frame, text="Load an identity to view the audit trail.", bootstyle="secondary")
        self.audit_status_label.grid(row=0, column=0, sticky="ew", pady=(0, 10), padx=10)

        # Store coldata as instance variable so callbacks can access it
        self.audit_coldata = [
            {"text": "Status", "stretch": False, "width": 120},
            {"text": "Timestamp (UTC)", "stretch": False, "width": 200},
            {"text": "Event Type", "stretch": False, "width": 180},
            {"text": "Details", "stretch": True}
        ]
        self.audit_tree = Tableview(parent_frame, coldata=self.audit_coldata, rowdata=[], paginated=True, pagesize=50, searchable=True, bootstyle=INFO)
        self.audit_tree.grid(row=1, column=0, sticky="nsew")

    # NOTE: _create_dashboard_tab has been replaced with DashboardTab class in ui/dashboard.py
    # All dashboard UI is now handled by the DashboardTab class, keeping this file focused on
    # pro feature tab management (Batch, Audit, and delegation to Dashboard).

    # --- UI State and Event Handlers ---

    def update_ui_state(self, has_identity: bool, load_dashboard_analytics: bool = True):
        """Updates widget states based on identity and license.

        Args:
            has_identity: Whether user has an active identity
            load_dashboard_analytics: Whether to load dashboard analytics (default True).
                                      Set to False on startup to avoid unnecessary load.
        """
        logging.debug(f"[PRO_TABS] update_ui_state: has_identity={has_identity}, load_analytics={load_dashboard_analytics}")
        # Batch Tab
        is_batch_licensed = self.logic.license_manager.is_feature_enabled(FEATURE_BATCH)
        self.load_batch_button.config(state=NORMAL if has_identity and is_batch_licensed else DISABLED)
        if not has_identity:
            self.batch_file_label.config(text="Load an identity to begin.")
            self.batch_tree.delete_rows()
            self.process_batch_button.config(state=DISABLED)

        # Audit Tab
        if not has_identity:
            self.audit_status_label.config(text="Load an identity to view the audit trail.")
            self.audit_tree.delete_rows()

        # Dashboard Tab
        is_dashboard_licensed = self.logic.license_manager.is_feature_enabled(FEATURE_DASHBOARD)

        if has_identity:
            # Load analytics only if explicitly requested (e.g., when user clicks the dashboard tab)
            # Don't load on startup - save processing for when user actually wants to view
            current_issuer_id = self.logic.active_issuer_id

            # Only check if we're ALREADY loading (prevent parallel redundant loads)
            should_load_analytics = load_dashboard_analytics and not self._analytics_loading

            logging.debug(f"[PRO_TABS] Dashboard: issuer={current_issuer_id}, should_load={should_load_analytics}")

            if should_load_analytics:
                self.dashboard_tab.update_status_label("Loading certificates...")
                if self.logic:
                    logging.debug(f"[PRO_TABS] Loading analytics for issuer {current_issuer_id}")
                    self._analytics_loading = True

                    def _load_analytics_wrapper():
                        """Wrapper to reset flag after loading."""
                        try:
                            self.logic.load_cached_analytics()
                        finally:
                            self._analytics_loading = False

                    threading.Thread(target=_load_analytics_wrapper, daemon=True).start()
                else:
                    logging.warning(f"[PRO_TABS] logic not available")
            else:
                logging.debug(f"[PRO_TABS] Skipping analytics load: already loading in progress")
        else:
            self.dashboard_tab.update_status_label("Load an identity to view QR log.")
            self.dashboard_tab.update_table_data([])
            self.dashboard_tab.clear_certificate_details()
            # Reset state when no identity
            self._last_loaded_issuer_id = None
            self._analytics_loading = False

    @_requires_feature(FEATURE_BATCH)
    def _handle_load_data_file(self):
        """Opens file dialogs and triggers a threaded data file load."""
        if not (base_dir_str := filedialog.askdirectory(title="Select Base Folder Containing Your Proof Images")):
            return
        if not (filepath_str := filedialog.askopenfilename(title="Select Data File (*.xlsx, *.csv)", filetypes=[("Data Files", "*.xlsx *.csv")])):
            return
        
        self.logic.pro_handler.load_data_file_threaded(Path(base_dir_str), Path(filepath_str))

    @_requires_feature(FEATURE_BATCH)
    def _handle_process_batch(self):
        """Triggers the threaded batch processing job."""
        self.logic.pro_handler.process_batch_threaded()

    def _handle_refresh_audit(self):
        """Triggers a non-blocking refresh and verification of the audit trail."""
        # Check if Audit feature is licensed
        if not self.logic.license_manager.is_feature_enabled(FEATURE_AUDIT):
            logging.warning("[AUDIT_UI] Cannot load audit trail: Audit feature not licensed")
            self.audit_status_label.config(text="Audit Trail requires a Pro license.", bootstyle="warning")
            self.audit_tree.delete_rows()
            return

        if not self.logic.active_issuer_id:
            logging.warning("[AUDIT_UI] Cannot refresh audit: no active issuer ID")
            self.audit_status_label.config(text="No identity loaded.", bootstyle="warning")
            return

        logging.info(f"[AUDIT_UI] Starting audit refresh for issuer {self.logic.active_issuer_id}")
        # NOTE: This assumes the logic layer implements this threaded method
        # and calls back to on_audit_load_start/on_audit_load_complete.
        try:
            self.logic.pro_handler.load_and_verify_audit_log_threaded(
                active_issuer_id=self.logic.active_issuer_id,
                active_issuer_data=self.logic.active_issuer_data,
                ui_callback=self
            )
        except Exception as e:
            logging.error(f"[AUDIT_UI] Error triggering audit refresh: {e}", exc_info=True)
            self.audit_status_label.config(text=f"Error: {str(e)}", bootstyle="danger")

    def _resize_worldmap_to_container(self):
        """Dynamically resize worldmap image to fill container width."""
        try:
            if not hasattr(self, '_worldmap_img_orig') or not hasattr(self, 'dashboard_worldmap_label'):
                return

            # Get the actual frame width
            frame = self.dashboard_worldmap_label.master  # Get parent (worldmap_frame)
            frame.update_idletasks()  # Force layout update
            frame_width = frame.winfo_width()

            if frame_width > 20:  # Only resize if we have reasonable width
                # Calculate image width (minus frame padding of 5px on each side)
                img_width = frame_width - 10
                img_height = int(img_width * (self._worldmap_img_h / self._worldmap_img_w))

                # Resize original image to fit
                worldmap_img = self._worldmap_img_orig.resize((img_width, img_height), PILImage.Resampling.LANCZOS)
                worldmap_photo = ImageTk.PhotoImage(worldmap_img)

                # Update label with new image
                self.dashboard_worldmap_label.config(image=worldmap_photo)
                self.dashboard_worldmap_label.image = worldmap_photo
        except Exception as e:
            logging.debug(f"Failed to dynamically resize worldmap: {e}")

    def _refresh_dashboard_with_local_data(self):
        """Refresh dashboard with local database data (immediate, no FTP call)."""
        try:
            if not self.logic.insights_db:
                return

            # logging.info("[DASHBOARD] Refreshing with local data from insights_db")  # Commented out - verbose log for debugging

            # Get certificate stats from local database
            cert_stats = self.logic.insights_db.get_certificate_stats()
            if not cert_stats:
                logging.warning("[DASHBOARD] No certificate stats found in local database")
                self.dashboard_tab.update_table_data([])
                return

            # Build table rows
            row_data = []
            for cert in cert_stats:
                # Remove .lky extension from filename
                filename = cert['filename']
                if filename.endswith('.lky'):
                    filename = filename[:-4]

                # Strip time from dates, keep only date (YYYY-MM-DD)
                date_created = cert['date_created'].split(' ')[0] if cert['date_created'] else ''
                date_uploaded = (cert['date_uploaded'].split(' ')[0] if cert['date_uploaded'] else '') if cert['date_uploaded'] else ''

                row = [
                    filename,
                    cert['upload_status'],
                    date_created,
                    date_uploaded,
                    cert['total_scans'],
                    cert['top_city'] or ''
                ]
                row_data.append(row)

            # Update table via DashboardTab
            self.dashboard_tab.update_table_data(row_data)

            # Update Local Insight stats via DashboardTab
            db_stats = self.logic.insights_db.get_database_statistics()
            total_signed = db_stats.get('total_certificates', 0)
            deleted = db_stats.get('deleted', 0)
            local_count = total_signed - deleted  # Local = Total - Deleted

            self.dashboard_tab.update_local_insights(
                total_signed=local_count,  # Show only local certificates (not deleted)
                pending=db_stats.get('pending', 0),
                online=db_stats.get('online', 0),
                deleted=deleted
            )

            # Update Online Insights as well
            self._update_online_insights_from_database()

            # logging.info(f"[DASHBOARD] Local data refresh complete: {len(row_data)} certificates, stats={db_stats}")  # Commented out - verbose log for debugging

        except Exception as e:
            logging.error(f"[DASHBOARD] Error refreshing with local data: {e}", exc_info=True)

    @_requires_feature(FEATURE_DASHBOARD)
    def _handle_dashboard_refresh(self):
        """Refresh QR log data from FTP and repopulate dashboard."""
        if not self.logic.active_issuer_id:
            return
        self.dashboard_tab.update_status_label("Refreshing QR log...", "info")
        # Trigger async refresh in logic layer
        self.logic.pro_handler.refresh_dashboard_analytics_threaded()

    @_requires_feature(FEATURE_DASHBOARD)
    def _handle_dashboard_show_map(self):
        """Open the world map in the browser showing scan distribution by country."""
        try:
            self.dashboard_tab.update_status_label("Opening world map...", "info")

            # Call map display in logic layer (runs in background thread)
            self.logic.pro_handler.open_world_map_window()

            self.dashboard_tab.update_status_label("Map opened in browser", "success")
        except Exception as e:
            logging.error(f"Failed to open map: {e}", exc_info=True)
            self.dashboard_tab.update_status_label(f"Map failed: {str(e)}", "danger")

    def _on_dashboard_cert_selected(self, event):
        """Handle certificate selection in dashboard table."""
        selection = self.dashboard_table.get_rows(selected=True)
        if selection:
            table_row = selection[0]
            # TableRow has values attribute containing the row data
            row_data = table_row.values if hasattr(table_row, 'values') else table_row
            # row_data is: [Certificate, Status, Scans, Last Scan, Top Location]
            cert_name = row_data[0] if row_data else ""
            if cert_name:
                # Normalize filename to include .lky extension (table displays without it for cleaner UI)
                cert_name_with_ext = cert_name if cert_name.endswith('.lky') else f"{cert_name}.lky"
                logging.info(f"[UI] User clicked certificate: {cert_name} (normalized to {cert_name_with_ext})")
                self.logic.pro_handler.load_certificate_details(cert_name_with_ext)

    def _clear_dashboard_details(self):
        """Clear the certificate details panel."""
        self.dashboard_image_label.config(text="[Image will load here]", foreground="gray", compound="none")
        self.dashboard_image_label.image = None  # Explicitly destroy image reference
        self.dashboard_message_text = ""
        self.dashboard_date_text = ""
        # Reset LKey Detail labels
        self.dashboard_lkey_date_label.config(text="—")
        self.dashboard_lkey_message_label.config(text="—")

    def _update_logging_status_indicator(self):
        """Update the QR Log status indicator on the dashboard."""
        # QR Log status indicator removed (cosmetic cleanup)
        try:
            self.dashboard_logging_status_label.config(text="")
        except Exception as e:
            logging.debug(f"Error clearing QR Log status: {e}")

    def _update_batch_auto_upload_indicator(self):
        """Update the auto-upload indicator for batch signing."""
        try:
            if self.logic and self.logic.config:
                text, style = ("✓ Auto-Upload: ON", "success") if self.logic.config.ftp_auto_upload else ("✗ Auto-Upload: OFF", "secondary")
                self.batch_auto_upload_indicator.config(text=text, bootstyle=style)
        except Exception as e:
            logging.error(f"[BATCH_UI] Error updating auto-upload indicator: {e}")

    # --- Batch Processing Callbacks ---

    def on_batch_load_start(self):
        self.process_batch_button.config(state=DISABLED)
        self.batch_file_label.config(text="Loading data file...")

    def on_batch_load_success(self, filename, total_items, row_data):
        """Handle successful batch file load with data validation."""
        logging.info(f"[BATCH_UI] on_batch_load_success: {filename} with {total_items} items, row_data count={len(row_data) if row_data else 0}")
        self.batch_tree.delete_rows()
        if row_data:
            try:
                # Validate and sanitize row data before displaying
                validated_rows = []
                for row in row_data:
                    if len(row) >= 3:
                        status, path, summary = row[0], row[1], row[2]
                        # Truncate summary to 400 chars max
                        if isinstance(summary, str) and len(summary) > 400:
                            summary = summary[:400]
                        # Only include 3 columns (status, path, summary)
                        # Tags (4th element) are handled separately by the table
                        validated_rows.append([status, path, summary])
                    else:
                        logging.warning(f"[BATCH_UI] Skipping malformed row: {row}")

                if validated_rows:
                    self.batch_tree.build_table_data(self.batch_coldata, validated_rows)
                else:
                    logging.warning("[BATCH_UI] No valid rows to display after validation")

            except Exception as e:
                logging.error(f"[BATCH_UI] Error building batch table: {e}", exc_info=True)
                show_error("Data Load Error", f"Failed to display batch data:\n{e}")
                self.batch_file_label.config(text="Error displaying data.")
                return

        self.batch_file_label.config(text=f"Loaded: {Path(filename).name} ({total_items} items)")
        if total_items > 0:
            self.process_batch_button.config(state=NORMAL)
        # Update auto-upload indicator now that logic is ready
        self._update_batch_auto_upload_indicator()

    def on_batch_load_failure(self, message):
        show_error("File Load Error", message)
        self.batch_file_label.config(text="File load failed.", bootstyle="danger")

    def on_batch_process_start(self, total_items):
        self.load_batch_button.config(state=DISABLED)
        self.process_batch_button.config(state=DISABLED)
        logging.info(f"[BATCH_UI] Starting batch processing with {total_items} items")

    def on_batch_item_processing(self, item_id, values, progress_info=None):
        """Update item status to PROCESSING (Signing...) in the table."""
        try:
            # values = (status, path, summary) from batch_processor
            status, path, summary = values if len(values) >= 3 else ("Processing...", str(values[0]) if values else "", "")
            # Show "Signing..." status in table by updating the existing row
            processing_values = ["⏳ Signing...", path, summary]

            # Find the row that matches this file path (not by index)
            # Only search if we're in a batch context (path should be provided)
            if not path:
                return

            for row in self.batch_tree.tablerows:
                # Row values are [status, path, summary]
                if len(row.values) >= 2 and row.values[1] == path:
                    row.values = processing_values
                    break
        except Exception as e:
            logging.debug(f"[BATCH_UI] Error updating item {item_id}: {e}")

    def on_batch_item_complete(self, item_id, values, tag, progress_info=None):
        """Update item status to complete with appropriate message (SUCCESS or FAILURE)."""
        try:
            # values = (status, path, summary) from batch_processor
            status, path, summary = values if len(values) >= 3 else ("Complete", str(values[0]) if values else "", "")

            # Status message already provided by batch_processor (✅ or ❌)
            complete_values = [status, path, summary]

            # Find the row that matches this file path (not by index)
            # Only search if we're in a batch context (path should be provided)
            if not path:
                return

            for row in self.batch_tree.tablerows:
                # Row values are [status, path, summary]
                if len(row.values) >= 2 and row.values[1] == path:
                    row.values = complete_values
                    break
        except Exception as e:
            logging.debug(f"[BATCH_UI] Error completing item {item_id}: {e}")

    def on_batch_process_complete(self):
        self.load_batch_button.config(state=NORMAL)
        self.process_batch_button.config(state=NORMAL)
        logging.info("[BATCH_UI] Batch processing complete")
        show_info("Batch Complete", "Batch processing has finished. Check the table above for results.")

    # --- Audit Log Callbacks (for new threaded refresh) ---

    def on_audit_load_start(self):
        """Called by logic layer before starting audit log verification."""
        self.audit_status_label.config(text="Verifying Audit Trail...", bootstyle=INFO)
        self.audit_tree.delete_rows()

    def on_audit_load_complete(self, row_data, is_valid, msg, style):
        """Called by logic layer after audit log verification is complete."""
        # Check if UI components exist before updating them.
        if not hasattr(self, 'audit_tree'):
            logging.warning("[AUDIT_UI] Callback ignored: audit_tree does not exist")
            return

        if not hasattr(self, 'audit_status_label'):
            logging.warning("[AUDIT_UI] Callback ignored: audit_status_label does not exist")
            return

        try:
            logging.debug(f"[AUDIT_UI] on_audit_load_complete: rows={len(row_data)}")
            if row_data:
                logging.debug(f"[AUDIT_UI] Building table with {len(row_data)} rows")
                # Use audit_coldata stored in _create_audit_viewer_tab
                if hasattr(self, 'audit_coldata'):
                    self.audit_tree.build_table_data(self.audit_coldata, row_data)
                    logging.debug(f"[AUDIT_UI] Table populated")
                else:
                    logging.warning("[AUDIT_UI] audit_coldata not found - cannot populate table")

            self.audit_status_label.config(text=msg, bootstyle=style)
            logging.info("[AUDIT_UI] Audit table updated successfully")
        except Exception as e:
            logging.error(f"[AUDIT_UI] Error updating audit table: {e}", exc_info=True)
            self.audit_status_label.config(text=f"Error displaying audit: {str(e)}", bootstyle="danger")

    # --- Dashboard Callbacks (delegated to DashboardTab) ---

    def on_dashboard_refresh_start(self):
        """Called when dashboard refresh starts. Delegated to DashboardTab."""
        self.dashboard_tab.update_status_label("Fetching analytics from server...", "info")

    def on_dashboard_status_update(self, status_msg: str):
        """Called during refresh to update status with progress. Delegated to DashboardTab."""
        try:
            self.dashboard_tab.update_status_label(status_msg, "info")
        except Exception as e:
            logging.error(f"Error updating dashboard status: {e}")

    def on_dashboard_refresh_complete(self, row_data, msg, style, map_html=None):
        """Called when dashboard refresh completes. Delegated to DashboardTab."""
        try:
            # Schedule all UI updates on the main thread using root.after()
            # This is necessary because this method may be called from a background thread
            # and Tkinter requires all UI updates to happen on the main thread
            def _update_ui():
                try:
                    # Update table with row data
                    self.dashboard_tab.update_table_data(row_data)

                    # Get and update Local Insight statistics from database
                    try:
                        if self.logic.insights_db:
                            db_stats = self.logic.insights_db.get_database_statistics()
                            # logging.info(f"[DASHBOARD] Database stats: {db_stats}")  # Commented out - verbose log for debugging

                            # Update Local Insight (below table)
                            self.dashboard_tab.update_local_insights(
                                total_signed=db_stats.get('total_certificates', 0),
                                pending=db_stats.get('pending', 0),
                                online=db_stats.get('online', 0),
                                deleted=db_stats.get('deleted', 0)
                            )

                            # Calculate and update Online Insights (top section)
                            self._update_online_insights_from_database()
                    except Exception as e:
                        logging.error(f"Failed to update statistics: {e}", exc_info=True)

                    # Update status label
                    self.dashboard_tab.update_status_label(msg, style)

                except Exception as e:
                    logging.error(f"Error in dashboard refresh UI update: {e}", exc_info=True)

            # Use root.after(0, ...) to schedule on main thread
            if hasattr(self.logic, 'ui_callback') and hasattr(self.logic.ui_callback, 'root'):
                self.logic.ui_callback.root.after(0, _update_ui)
            else:
                # Fallback: call directly if root not available (less safe but handles edge cases)
                _update_ui()

        except Exception as e:
            logging.error(f"Error in dashboard refresh complete: {e}", exc_info=True)

    def _update_online_insights_from_database(self):
        """Calculate and update Online Insights (top countries, cities, Lky, users, scans)."""
        try:
            if not self.logic.insights_db:
                return

            # Get all scans for aggregation (using abstraction method instead of raw SQL)
            scans_dicts = self.logic.insights_db.get_all_certificate_scans()
            all_scans = scans_dicts  # For compatibility with len(all_scans) below

            country_counts = {}
            city_counts = {}
            unique_users = set()

            for scan_dict in scans_dicts:
                country = scan_dict.get('country')
                city = scan_dict.get('city')
                ip_anon = scan_dict.get('ip_anonymized')

                # Count non-empty, non-UNKNOWN values
                if country and country.strip() and country.upper() != "UNKNOWN":
                    country_counts[country] = country_counts.get(country, 0) + 1
                if city and city.strip() and city.upper() != "UNKNOWN":
                    city_counts[city] = city_counts.get(city, 0) + 1
                if ip_anon and ip_anon.strip():
                    unique_users.add(ip_anon)

            # Format top countries
            top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:4]
            top_country_text = "\n".join([f"{c[0][:10]}: {c[1]}" for c in top_countries]) if top_countries else "—"

            # Format top cities
            top_cities = sorted(city_counts.items(), key=lambda x: x[1], reverse=True)[:4]
            top_city_text = "\n".join([f"{c[0][:10]}: {c[1]}" for c in top_cities]) if top_cities else "—"

            # Get top Lky (most scanned certificates) using abstraction method instead of raw SQL
            top_certs = self.logic.insights_db.get_top_certificates_by_scan_count(limit=4)
            top_lky_text = "\n".join([f"{cert['filename'][:10]}: {cert['scan_count']}" for cert in top_certs]) if top_certs else "—"

            # Update Online Insights
            self.dashboard_tab.update_online_insights(
                top_countries_text=top_country_text,
                top_cities_text=top_city_text,
                top_lkys_text=top_lky_text,
                num_users=len(unique_users),
                num_scans=len(all_scans)
            )

            # logging.info(f"[DASHBOARD] Online Insights updated: {len(unique_users)} users, {len(all_scans)} scans")  # Commented out - verbose log for debugging

        except Exception as e:
            logging.error(f"Failed to calculate Online Insights: {e}", exc_info=True)

    def on_dashboard_cert_loading_start(self, cert_filename):
        """Called when certificate loading starts. Delegated to DashboardTab."""
        logging.info(f"[UI] Certificate loading started: {cert_filename}")
        self.dashboard_tab.update_certificate_details(None, "", "")

    def on_dashboard_cert_loading_error(self, cert_filename, error_msg):
        """Called when certificate loading fails. Delegated to DashboardTab."""
        logging.warning(f"[UI] Certificate loading error: {cert_filename} - {error_msg}")
        self.dashboard_tab.update_certificate_details(None, f"❌ {error_msg}", "—")

    def on_dashboard_cert_details_loaded(self, cert_data, image_bytes, scan_locations=None, map_html=None):
        """Called when certificate details are loaded. Delegated to DashboardTab."""
        decoded_message = "—"
        date_signed = "—"

        if cert_data:
            cert_filename = cert_data.get('filename', '—')
            logging.info(
                f"[UI] Certificate details loaded: {cert_filename}, has_image={image_bytes is not None and len(image_bytes) > 0}"
            )
            decoded_message = cert_data.get('decoded_message', cert_data.get('message', '—'))
            if not decoded_message:
                decoded_message = "—"
            date_signed = cert_data.get('date_signed', '—')

        self.dashboard_tab.update_certificate_details(image_bytes, decoded_message, date_signed)

        if map_html:
            logging.debug(f"[MAP] Certificate map data available but not displayed (length: {len(map_html)})")
        else:
            logging.debug("[MAP] No map_html received")

    def on_dashboard_export_complete(self, success, msg):
        """Called when export completes."""
        if success:
            show_info("Export Complete", msg)
        else:
            show_error("Export Failed", msg)

    def on_signing_success(self, prepared_upload_path, qr_image_pil, last_signed_payload, was_auto_upload_successful, final_lkey_image_with_overlay):
        """
        Called when a document is successfully signed.
        Updates the dashboard with newly signed certificate (lightweight).
        """
        try:
            logging.info("[PRO_TABS] Document signed successfully - updating dashboard")

            # Refresh dashboard with local data to show the newly signed certificate
            # This is lightweight - reads from local insights_db, not FTP
            if hasattr(self, 'dashboard') and self.dashboard and self.dashboard_tab:
                self._refresh_dashboard_with_local_data()
                logging.debug("[PRO_TABS] Dashboard refreshed with newly signed certificate")

        except Exception as e:
            logging.error(f"[PRO_TABS] Error in on_signing_success: {e}", exc_info=True)

    # --- Helper Methods ---

    def _show_upgrade_prompt(self, feature_name: str):
        show_info("Professional Feature", f"'{feature_name}' is a Professional feature.\n\nPlease purchase or activate a license to unlock this functionality.")