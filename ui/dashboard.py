# ui/dashboard.py
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
DashboardTab: A "dumb" UI-only dashboard widget.

This class is responsible ONLY for:
- Creating dashboard UI widgets
- Displaying data provided by the logic layer
- Capturing user interactions (clicks, selections)
- Calling methods in the logic layer via callbacks

All business logic (file operations, database queries, FTP operations, analytics)
should be delegated to OpnCzamiLogic.
"""

import logging
import tkinter as tk
from tkinter import ttk
from pathlib import Path
from io import BytesIO

import ttkbootstrap
from ttkbootstrap.constants import *
from ttkbootstrap.tableview import Tableview
from tkinter import messagebox

from PIL import Image as PILImage, ImageTk


class DashboardTab:
    """Display-only dashboard UI without business logic (MVC view layer)."""

    def __init__(self, parent_frame, logic):
        """Build dashboard layout with worldmap, table, insights, and LKey viewer."""
        self.parent_frame = parent_frame
        self.logic = logic

        # Store message and date text
        self.dashboard_message_text = ""
        self.dashboard_date_text = ""

        # Create the dashboard UI
        self._create_dashboard_ui()

    def _create_dashboard_ui(self):
        """Create the entire dashboard UI layout."""
        self.parent_frame.grid_rowconfigure(1, weight=1)
        self.parent_frame.grid_columnconfigure(0, weight=0, minsize=700)
        self.parent_frame.grid_columnconfigure(1, weight=1)

        # --- LEFT COLUMN: Stats + Certificates Table ---
        left_column_frame = ttk.Frame(self.parent_frame)
        left_column_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=5)
        left_column_frame.grid_rowconfigure(0, weight=0)
        left_column_frame.grid_rowconfigure(1, weight=1)
        left_column_frame.grid_rowconfigure(2, weight=0)
        left_column_frame.grid_columnconfigure(0, weight=1)

        # Online Insights / World Map (top)
        self._create_online_insights_section(left_column_frame)

        # Certificates table (middle)
        self._create_certificates_table(left_column_frame)

        # Local Insight with buttons (bottom)
        self._create_local_insight_section(left_column_frame)

        # --- RIGHT COLUMN: LKey Viewer ---
        self._create_lkey_viewer_section()

        # --- BOTTOM STATUS LABEL ---
        self._create_status_bar()

    def _create_online_insights_section(self, parent_frame):
        """Create the Online Insights section with worldmap and data columns."""
        stats_frame = ttk.Frame(parent_frame)
        stats_frame.grid(row=0, column=0, sticky="ew", pady=(0, 0))
        stats_frame.grid_columnconfigure(0, weight=1)

        worldmap_frame = ttk.LabelFrame(
            stats_frame, text="💎Online Insights / Click the Map (Pro feature) ", padding=5
        )
        worldmap_frame.pack(fill="x", pady=(0, 5))

        map_container = ttk.Frame(worldmap_frame)
        map_container.pack(fill="x")

        # Load worldmap image using centralized path manager
        try:
            worldmap_path = self.logic.path_manager.worldmap_image_path
            if worldmap_path.exists():
                worldmap_img_orig = PILImage.open(worldmap_path)
                w, h = worldmap_img_orig.size
                new_w = 200
                new_h = int(new_w * (h / w))
                worldmap_img = worldmap_img_orig.resize((new_w, new_h), PILImage.Resampling.LANCZOS)

                worldmap_photo = ImageTk.PhotoImage(worldmap_img)
                self.dashboard_worldmap_label = ttk.Label(map_container, image=worldmap_photo, cursor="hand2")
                self.dashboard_worldmap_label.image = worldmap_photo
                self.dashboard_worldmap_label.pack(side="left", padx=0, pady=0)

                # Make worldmap clickable with license check
                self.dashboard_worldmap_label.bind("<Button-1>", self._on_worldmap_clicked)

                # Store original image for dynamic resizing
                self._worldmap_img_orig = worldmap_img_orig
                self._worldmap_img_w = w
                self._worldmap_img_h = h

                # Schedule dynamic resizing
                self.parent_frame.after(50, self._resize_worldmap_to_container)
            else:
                logging.warning("Worldmap image not found")
        except Exception as e:
            logging.error(f"Failed to load worldmap image: {e}")

        # Data columns (right side)
        data_container = ttk.Frame(map_container)
        data_container.pack(side="right", fill="both", expand=True, padx=(10, 0))
        data_container.grid_columnconfigure(0, weight=1)
        data_container.grid_columnconfigure(1, weight=1)
        data_container.grid_columnconfigure(2, weight=1)
        data_container.grid_columnconfigure(3, weight=1)

        # Column 1 - Top Country
        col1_frame = ttk.Frame(data_container)
        col1_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
        ttk.Label(col1_frame, text="Top Country", font=("TkDefaultFont", 9)).pack(anchor="nw", fill="x")
        self.dashboard_top_country_value = ttk.Label(col1_frame, text="—", font=("TkDefaultFont", 8), justify="left")
        self.dashboard_top_country_value.pack(anchor="nw", fill="x")

        # Column 2 - Top City
        col2_frame = ttk.Frame(data_container)
        col2_frame.grid(row=0, column=1, sticky="nsew", padx=(3, 3))
        ttk.Label(col2_frame, text="Top City", font=("TkDefaultFont", 9)).pack(anchor="nw", fill="x")
        self.dashboard_top_city_value = ttk.Label(col2_frame, text="—", font=("TkDefaultFont", 8), justify="left")
        self.dashboard_top_city_value.pack(anchor="nw", fill="x")

        # Column 3 - Top Lky
        col3_frame = ttk.Frame(data_container)
        col3_frame.grid(row=0, column=2, sticky="nsew", padx=(3, 3))
        ttk.Label(col3_frame, text="Top Lky", font=("TkDefaultFont", 9)).pack(anchor="nw", fill="x")
        self.dashboard_top_lky_value = ttk.Label(col3_frame, text="—", font=("TkDefaultFont", 8), justify="left")
        self.dashboard_top_lky_value.pack(anchor="nw", fill="x")

        # Column 4 - Users / Scans
        col4_frame = ttk.Frame(data_container)
        col4_frame.grid(row=0, column=3, sticky="nsew", padx=(3, 0))
        ttk.Label(col4_frame, text="Users", font=("TkDefaultFont", 7)).pack(anchor="nw", fill="x")
        self.dashboard_num_users_value = ttk.Label(col4_frame, text="0", font=("TkDefaultFont", 11, "bold"))
        self.dashboard_num_users_value.pack(anchor="nw", fill="x")

        ttk.Label(col4_frame, text="Scans", font=("TkDefaultFont", 7)).pack(anchor="nw", fill="x", pady=(5, 0))
        self.dashboard_num_scans_value = ttk.Label(
            col4_frame, text="0", font=("TkDefaultFont", 11, "bold"), foreground="blue"
        )
        self.dashboard_num_scans_value.pack(anchor="nw", fill="x")

    def _create_certificates_table(self, parent_frame):
        """Create the certificates table."""
        table_frame = ttk.Frame(parent_frame, padding=5)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.pack_propagate(False)

        dashboard_coldata = [
            {"text": "Certificate", "stretch": False, "width": 180},
            {"text": "Status", "stretch": False, "width": 85},
            {"text": "Signed On", "stretch": False, "width": 100},
            {"text": "Upload On", "stretch": False, "width": 100},
            {"text": "Scans", "stretch": False, "width": 60},
            {"text": "City", "stretch": False, "width": 110},
        ]
        self.dashboard_table = Tableview(
            table_frame, coldata=dashboard_coldata, rowdata=[], paginated=False, searchable=True, bootstyle=PRIMARY
        )
        self.dashboard_table.coldata = dashboard_coldata
        self.dashboard_table.pack(fill="both", expand=True)

        # Bind double-click to load certificate details
        self.dashboard_table.view.bind("<Double-Button-1>", self._on_cert_selected, add="+")

    def _create_local_insight_section(self, parent_frame):
        """Create the Local Insight section with buttons."""
        local_insight_container = ttk.Frame(parent_frame)
        local_insight_container.grid(row=2, column=0, sticky="ew", pady=(5, 0), padx=5)
        local_insight_container.grid_columnconfigure(0, weight=1)
        local_insight_container.grid_columnconfigure(1, weight=0)

        # Local Insight summary frame
        local_insight_frame = ttk.Frame(local_insight_container, padding=5)
        local_insight_frame.grid(row=0, column=0, sticky="ew")

        stats_line = ttk.Frame(local_insight_frame)
        stats_line.grid(row=0, column=0, columnspan=3, sticky="ew")

        ttk.Label(stats_line, text="Total Signed", font=("TkDefaultFont", 8)).pack(side="left", padx=(0, 3))
        self.dashboard_total_signed_label = ttk.Label(
            stats_line, text="0", font=("TkDefaultFont", 9, "bold"), foreground="blue"
        )
        self.dashboard_total_signed_label.pack(side="left", padx=(0, 15))

        ttk.Label(stats_line, text="Pending", font=("TkDefaultFont", 8)).pack(side="left", padx=(0, 3))
        self.dashboard_local_pending_label = ttk.Label(
            stats_line, text="0", font=("TkDefaultFont", 9, "bold"), foreground="orange"
        )
        self.dashboard_local_pending_label.pack(side="left", padx=(0, 15))

        ttk.Label(stats_line, text="Online", font=("TkDefaultFont", 8)).pack(side="left", padx=(0, 3))
        self.dashboard_local_online_label = ttk.Label(
            stats_line, text="0", font=("TkDefaultFont", 9, "bold"), foreground="green"
        )
        self.dashboard_local_online_label.pack(side="left", padx=(0, 15))

        ttk.Label(stats_line, text="Deleted", font=("TkDefaultFont", 8)).pack(side="left", padx=(0, 3))
        self.dashboard_local_deleted_label = ttk.Label(
            stats_line, text="0", font=("TkDefaultFont", 9, "bold"), foreground="gray"
        )
        self.dashboard_local_deleted_label.pack(side="left")

        # Buttons frame
        buttons_frame = ttk.Frame(local_insight_container)
        buttons_frame.grid(row=0, column=1, sticky="ns", padx=(5, 0))

        ttk.Button(buttons_frame, text="Delete", command=self._on_delete_clicked, width=5, bootstyle="danger").pack(
            side="left", padx=(0, 2)
        )
        ttk.Button(buttons_frame, text="Remove", command=self._on_remove_clicked, width=7, bootstyle="warning").pack(
            side="left", padx=(0, 2)
        )
        ttk.Button(buttons_frame, text="Upload", command=self._on_upload_clicked, width=6, bootstyle="info").pack(
            side="left"
        )

    def _create_lkey_viewer_section(self):
        """Create the LKey Viewer section on the right."""
        right_column_frame = ttk.Frame(self.parent_frame)
        right_column_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        right_column_frame.grid_rowconfigure(0, weight=1)
        right_column_frame.grid_rowconfigure(1, weight=0)
        right_column_frame.grid_columnconfigure(0, weight=1)

        details_frame = ttk.LabelFrame(right_column_frame, text="Lkey Viewer", padding=0)
        details_frame.grid(row=0, column=0, sticky="nsew")
        details_frame.grid_rowconfigure(0, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)

        self.dashboard_image_label = ttk.Label(details_frame, text="Double-click a certificate to view", anchor="center")
        self.dashboard_image_label.grid(row=0, column=0, sticky="nsew")

        # Message content frame
        self.dashboard_message_frame = tk.Frame(right_column_frame, relief="flat", borderwidth=0, bg="white")
        self.dashboard_message_frame.grid(row=1, column=0, sticky="ew", pady=0, ipady=10)
        self.dashboard_message_frame.grid_columnconfigure(0, weight=1)

        self.dashboard_lkey_message_label = tk.Label(
            self.dashboard_message_frame,
            text="—",
            font=("TkDefaultFont", 7),
            anchor="nw",
            justify="left",
            bg="white",
            wraplength=600,
        )
        self.dashboard_lkey_message_label.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    def _create_status_bar(self):
        """Create the bottom status bar."""
        bottom_status_frame = ttk.Frame(self.parent_frame)
        bottom_status_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=(10, 0))
        bottom_status_frame.grid_columnconfigure(0, weight=1)
        bottom_status_frame.grid_columnconfigure(1, weight=0)
        bottom_status_frame.grid_columnconfigure(2, weight=0)

        self.dashboard_status_label = ttk.Label(
            bottom_status_frame, text="Load an identity to view QR log.", bootstyle="secondary"
        )
        self.dashboard_status_label.grid(row=0, column=0, sticky="ew")

        # Signed date
        date_frame = ttk.Frame(bottom_status_frame)
        date_frame.grid(row=0, column=1, sticky="e", padx=(20, 20))
        ttk.Label(date_frame, text="Signed on the:", font=("TkDefaultFont", 8, "bold")).pack(side="left")
        self.dashboard_lkey_date_label = ttk.Label(date_frame, text="—", font=("TkDefaultFont", 8))
        self.dashboard_lkey_date_label.pack(side="left", padx=(5, 0))

        # Analytics logging status
        self.dashboard_logging_status_label = ttk.Label(bottom_status_frame, text="", font=("TkDefaultFont", 9, "bold"))
        self.dashboard_logging_status_label.grid(row=0, column=2, sticky="e")

    # ========================================================================
    # UI DISPLAY METHODS (dumb - just update widgets with provided data)
    # ========================================================================

    def update_table_data(self, row_data):
        """Populate table with certificate data (filename, status, dates, scans, city)."""
        try:
            self.dashboard_table.delete_rows()
            if row_data:
                self.dashboard_table.build_table_data(self.dashboard_table.coldata, row_data)
        except Exception as e:
            logging.error(f"[DASHBOARD] Error updating table: {e}")

    def update_local_insights(self, total_signed, pending, online, deleted):
        """Update local statistics display (total, pending, online, deleted counts)."""
        self.dashboard_total_signed_label.config(text=str(total_signed))
        self.dashboard_local_pending_label.config(text=str(pending))
        self.dashboard_local_online_label.config(text=str(online))
        self.dashboard_local_deleted_label.config(text=str(deleted))

    def update_online_insights(
        self, top_countries_text, top_cities_text, top_lkys_text, num_users, num_scans
    ):
        """Update online statistics (top countries/cities/Lky, user and scan counts)."""
        from models.config import FEATURE_DASHBOARD

        self.dashboard_top_country_value.config(text=top_countries_text or "—")
        self.dashboard_top_city_value.config(text=top_cities_text or "—")

        # Only show Top Lky data for Pro users
        if self.logic.license_manager.is_feature_enabled(FEATURE_DASHBOARD):
            self.dashboard_top_lky_value.config(text=top_lkys_text or "—")
        else:
            # Free users: show empty dash in Top Lky column
            self.dashboard_top_lky_value.config(text="—")

        self.dashboard_num_users_value.config(text=str(num_users))
        self.dashboard_num_scans_value.config(text=str(num_scans))

    def update_certificate_details(self, image_bytes, message_text, date_text):
        """Display certificate LKey image, message, and signing date in viewer panel."""
        self.dashboard_message_text = message_text
        self.dashboard_date_text = date_text

        # Update labels
        self.dashboard_lkey_date_label.config(text=date_text)
        self.dashboard_lkey_message_label.config(text=message_text)

        if image_bytes:
            try:
                img = PILImage.open(BytesIO(image_bytes))

                # Get the actual container dimensions
                # Use after_idle to ensure widget geometry is updated
                self.dashboard_image_label.update_idletasks()
                container_width = self.dashboard_image_label.winfo_width()
                container_height = self.dashboard_image_label.winfo_height()

                # If widget size is not yet determined, use reasonable defaults
                if container_width <= 1:
                    container_width = 800
                if container_height <= 1:
                    container_height = 600

                # Calculate scaling to fit the image within the container while maintaining aspect ratio
                img_width, img_height = img.size
                scale_width = container_width / img_width if img_width > 0 else 1
                scale_height = container_height / img_height if img_height > 0 else 1
                scale = min(scale_width, scale_height)

                # Only scale down if image is larger than container, preserve original size if smaller
                if scale < 1:
                    new_width = int(img_width * scale)
                    new_height = int(img_height * scale)
                    img = img.resize((new_width, new_height), PILImage.Resampling.LANCZOS)

                logging.debug(f"[DASHBOARD] Image scaled from {img_width}x{img_height} to {img.size[0]}x{img.size[1]}, container: {container_width}x{container_height}")

                photo = ImageTk.PhotoImage(img)
                self.dashboard_image_label.config(image=photo, text="", compound="")
                self.dashboard_image_label.image = photo
                logging.info("[DASHBOARD] Certificate image displayed")
            except Exception as e:
                logging.error(f"Failed to display certificate image: {e}")
                self.dashboard_image_label.config(
                    image="", text="[Image load error]", foreground="gray", compound="none"
                )
                self.dashboard_image_label.image = None
        else:
            self.dashboard_image_label.config(
                image="", text="[No image available]", foreground="gray", compound="none"
            )
            self.dashboard_image_label.image = None

    def clear_certificate_details(self):
        """Reset certificate viewer to placeholder state."""
        self.dashboard_image_label.config(text="[Image will load here]", foreground="gray", compound="none")
        self.dashboard_image_label.image = None
        self.dashboard_message_text = ""
        self.dashboard_date_text = ""
        self.dashboard_lkey_date_label.config(text="—")
        self.dashboard_lkey_message_label.config(text="—")

    def update_status_label(self, text, bootstyle=None):
        """Update bottom status message with optional styling."""
        if bootstyle:
            self.dashboard_status_label.config(text=text, bootstyle=bootstyle)
        else:
            self.dashboard_status_label.config(text=text)

    def set_enabled(self, enabled):
        """Enable/disable dashboard for user interaction (placeholder for future expansion)."""
        # This is a simple placeholder - can be expanded if needed
        pass

    # ========================================================================
    # USER INTERACTION CALLBACKS (just capture, delegate to logic)
    # ========================================================================

    def _on_worldmap_clicked(self, event):
        """Open interactive worldmap if licensed, else show upgrade prompt."""
        from models.config import FEATURE_DASHBOARD

        # Check if Dashboard feature (which includes worldmap) is licensed
        if not self.logic.license_manager.is_feature_enabled(FEATURE_DASHBOARD):
            messagebox.showinfo(
                "Pro Feature Required",
                "The Interactive Worldmap is only available with a Pro License.\n\n"
                "This feature shows geographic insights about certificate verification locations.\n\n"
                "Upgrade to Pro to unlock this and other advanced analytics features."
            )
            return

        # User has Pro license - open the interactive map
        self.logic.pro_handler.open_world_map_window()

    def _on_cert_selected(self, event):
        """Load certificate details when double-clicked in table."""
        try:
            selection = self.dashboard_table.get_rows(selected=True)
            if selection:
                table_row = selection[0]
                row_data = table_row.values if hasattr(table_row, "values") else table_row
                if row_data and len(row_data) >= 6:
                    # Build cert_data from table row to pass full context to loader
                    # This includes filename, status, date_created which are needed to find local files
                    cert_data = {
                        "filename": row_data[0],
                        "status": row_data[1],
                        "date_created": row_data[2],
                        "date_uploaded": row_data[3],
                        "scans": row_data[4],
                        "city": row_data[5]
                    }
                    cert_name = cert_data.get("filename", "")
                    if cert_name:
                        logging.info(f"[UI] User clicked certificate: {cert_name} (Status: {cert_data.get('status')})")
                        # Validate that an issuer is loaded before attempting to load certificate
                        if not self.logic.active_issuer_data:
                            self.update_status_label("No active issuer - cannot load certificate", "danger")
                            return

                        # Pass cert_data so loader can:
                        # 1. Check status (PENDING = local only)
                        # 2. Use date_created to find local file path
                        # 3. Fall back to web server if needed
                        self.logic.pro_handler.load_certificate_details_with_context(cert_data)
        except Exception as e:
            logging.error(f"[DASHBOARD] Error in certificate selection: {e}")
            self.update_status_label(f"Error loading certificate: {str(e)}", "danger")

    def _on_upload_clicked(self):
        """Delegate selected certificate upload to logic layer."""
        try:
            cert_data = self._get_selected_cert()
            if cert_data:
                self.logic.dashboard_upload_certificate(cert_data)
        except Exception as e:
            logging.error(f"[DASHBOARD] Error in upload: {e}")

    def _on_remove_clicked(self):
        """Delegate selected certificate removal to logic layer."""
        try:
            cert_data = self._get_selected_cert()
            if cert_data:
                self.logic.dashboard_remove_certificate(cert_data)
        except Exception as e:
            logging.error(f"[DASHBOARD] Error in remove: {e}")

    def _on_delete_clicked(self):
        """Delegate selected certificate deletion to logic layer."""
        try:
            cert_data = self._get_selected_cert()
            if cert_data:
                self.logic.dashboard_delete_certificate(cert_data)
        except Exception as e:
            logging.error(f"[DASHBOARD] Error in delete: {e}")

    def _get_selected_cert(self) -> dict:
        """Extract selected table row as certificate data dict."""
        try:
            selected_rows = self.dashboard_table.view.selection()
            if not selected_rows:
                messagebox.showerror("No Selection", "Please select a certificate from the table.")
                return None

            row_id = selected_rows[0]
            row_data = self.dashboard_table.view.item(row_id)["values"]

            if len(row_data) >= 6:
                return {
                    "filename": row_data[0],
                    "status": row_data[1],
                    "date_created": row_data[2],
                    "date_uploaded": row_data[3],
                    "scans": row_data[4],
                    "city": row_data[5],
                }
        except Exception as e:
            logging.error(f"Error getting selected certificate: {e}")
            messagebox.showerror("Selection Error", f"Failed to get selected certificate: {str(e)}")
        return None

    # ========================================================================
    # HELPER METHODS (UI only)
    # ========================================================================

    def _resize_worldmap_to_container(self):
        """Resize worldmap image to match parent container width while maintaining aspect ratio."""
        try:
            if not hasattr(self, "_worldmap_img_orig") or not hasattr(self, "dashboard_worldmap_label"):
                return

            frame = self.dashboard_worldmap_label.master
            frame.update_idletasks()
            frame_width = frame.winfo_width()

            if frame_width > 20:
                img_width = frame_width - 10
                img_height = int(img_width * (self._worldmap_img_h / self._worldmap_img_w))

                worldmap_img = self._worldmap_img_orig.resize(
                    (img_width, img_height), PILImage.Resampling.LANCZOS
                )
                worldmap_photo = ImageTk.PhotoImage(worldmap_img)

                self.dashboard_worldmap_label.config(image=worldmap_photo)
                self.dashboard_worldmap_label.image = worldmap_photo
        except Exception as e:
            logging.debug(f"Failed to dynamically resize worldmap: {e}")
