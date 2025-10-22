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

# --- Third-Party Imports ---
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tableview import Tableview
from tkinter import filedialog

# --- Local Imports ---
from opn_czami_logic import OpnCzamiLogic
from models.utils import show_error, show_info
from models.config import FEATURE_BATCH, FEATURE_AUDIT

class ProFeatureTabs:
    """Manages the 'Batch Processing' and 'Audit Trail' Pro tabs."""

    def __init__(self, notebook: ttk.Notebook, logic: OpnCzamiLogic):
        self.notebook = notebook
        self.logic = logic
        self.batch_tab_frame = ttk.Frame(self.notebook, padding=10)
        self.audit_tab_frame = ttk.Frame(self.notebook, padding=10)
        self._create_batch_signing_tab(self.batch_tab_frame)
        self._create_audit_viewer_tab(self.audit_tab_frame)
        self.notebook.add(self.batch_tab_frame, text="💎 5. Batch Processing")
        self.notebook.add(self.audit_tab_frame, text="💎 6. Audit Trail")

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
        
        coldata = [{"text": "Status", "stretch": False, "width": 150}, {"text": "Image File Path", "stretch": True}, {"text": "Summary", "stretch": True}]
        self.batch_tree = Tableview(parent_frame, coldata=coldata, paginated=False, searchable=False, bootstyle=PRIMARY)
        self.batch_tree.grid(row=1, column=0, sticky="nsew")
        
        action_frame = ttk.Frame(parent_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)
        
        self.process_batch_button = ttk.Button(action_frame, text="▶️ Process Batch", command=self._handle_process_batch, state=DISABLED)
        self.process_batch_button.grid(row=0, column=1, sticky="e")
        
        self.batch_progress = ttk.Progressbar(action_frame, mode="determinate")
        self.batch_progress.grid(row=0, column=0, sticky="ew", padx=(0, 10))

    def _create_audit_viewer_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        
        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.refresh_audit_button = ttk.Button(control_frame, text="🔄 Refresh Audit Trail", command=self._handle_refresh_audit, bootstyle=PRIMARY)
        self.refresh_audit_button.pack(side="left", padx=(0, 10))
        
        self.audit_status_label = ttk.Label(control_frame, text="Load an identity to view the audit trail.", bootstyle="secondary")
        self.audit_status_label.pack(side="left", anchor="w")
        
        coldata = [{"text": "Status", "stretch": False, "width": 120}, {"text": "Timestamp (UTC)", "stretch": False, "width": 200}, {"text": "Event Type", "stretch": False, "width": 180}, {"text": "Details", "stretch": True}]
        self.audit_tree = Tableview(parent_frame, coldata=coldata, paginated=True, pagesize=50, searchable=True, bootstyle=INFO)
        self.audit_tree.grid(row=1, column=0, sticky="nsew")

    # --- UI State and Event Handlers ---

    def update_ui_state(self, has_identity: bool):
        """Updates widget states based on identity and license."""
        # Batch Tab
        is_batch_licensed = self.logic.license_manager.is_feature_enabled(FEATURE_BATCH)
        self.load_batch_button.config(state=NORMAL if has_identity and is_batch_licensed else DISABLED)
        if not has_identity:
            self.batch_file_label.config(text="Load an identity to begin.")
            self.batch_tree.delete_rows()
            self.process_batch_button.config(state=DISABLED)

        # Audit Tab
        is_audit_licensed = self.logic.license_manager.is_feature_enabled(FEATURE_AUDIT)
        self.refresh_audit_button.config(state=NORMAL if has_identity and is_audit_licensed else DISABLED)
        if not has_identity:
            self.audit_status_label.config(text="Load an identity to view the audit trail.")
            self.audit_tree.delete_rows()

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
        if not self.logic.active_issuer_id:
            return
        # NOTE: This assumes the logic layer implements this threaded method
        # and calls back to on_audit_load_start/on_audit_load_complete.
        self.logic.pro_handler.load_and_verify_audit_log_threaded()

    # --- Batch Processing Callbacks ---

    def on_batch_load_start(self):
        self.process_batch_button.config(state=DISABLED)
        self.batch_file_label.config(text="Loading data file...")

    def on_batch_load_success(self, filename, total_items, row_data):
        self.batch_tree.delete_rows()
        if row_data:
            self.batch_tree.build_table_data(self.batch_tree.coldata, row_data)
        self.batch_file_label.config(text=f"Loaded: {Path(filename).name} ({total_items} items)")
        if total_items > 0:
            self.process_batch_button.config(state=NORMAL)

    def on_batch_load_failure(self, message):
        show_error("File Load Error", message)
        self.batch_file_label.config(text="File load failed.", bootstyle="danger")

    def on_batch_process_start(self, total_items):
        self.load_batch_button.config(state=DISABLED)
        self.process_batch_button.config(state=DISABLED)
        self.batch_progress.config(maximum=total_items, value=0)

    def on_batch_item_processing(self, item_id, values):
        self.batch_tree.update_row(item_id, values, "PROCESSING")

    def on_batch_item_complete(self, item_id, values, tag):
        self.batch_tree.update_row(item_id, values, tag)
        self.batch_progress.step()

    def on_batch_process_complete(self):
        self.load_batch_button.config(state=NORMAL)
        self.process_batch_button.config(state=NORMAL)
        show_info("Batch Complete", "Batch processing has finished.")

    # --- Audit Log Callbacks (for new threaded refresh) ---

    def on_audit_load_start(self):
        """Called by logic layer before starting audit log verification."""
        self.audit_status_label.config(text="Verifying Audit Trail...", bootstyle=INFO)
        self.audit_tree.delete_rows()
        self.refresh_audit_button.config(state=DISABLED)

    def on_audit_load_complete(self, row_data, is_valid, msg, style):
        """Called by logic layer after audit log verification is complete."""
        # Defensively check if UI components exist before updating them.
        if not hasattr(self, 'audit_tree') or not hasattr(self.audit_tree, 'coldata'):
            logging.warning("Audit refresh callback ignored: UI components not fully initialized.")
            return

        if row_data:
            self.audit_tree.build_table_data(self.audit_tree.coldata, row_data)
        self.audit_status_label.config(text=msg, bootstyle=style)
        self.refresh_audit_button.config(state=NORMAL)

    # --- Helper Methods ---
    
    def _show_upgrade_prompt(self, feature_name: str):
        show_info("Professional Feature", f"'{feature_name}' is a Professional feature.\n\nPlease purchase or activate a license to unlock this functionality.")