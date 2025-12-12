# services/event_bus.py
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
THIS IS A SIMPLE EVENT BUS IMPLEMENTATION FOR PUBLISH/SUBSCRIBE MECHANISM.
COULD BE USED TO DECOUPLE UI COMPONENTS FROM BUSINESS LOGIC.
ANY IMPROVEMENTS WELCOME.
"""

import logging
from typing import Callable, Dict, List, Any

class EventBus:
    """
    Simple Publish/Subscribe mechanism for decoupling application components.
    """
    def __init__(self):
        # Dictionary mapping event names (str) to a list of subscriber functions (Callable)
        self._subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_name: str, callback: Callable) -> None:
        """Register a callback function to an event."""
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        if callback not in self._subscribers[event_name]:
            self._subscribers[event_name].append(callback)
        logging.debug(f"[EVENT_BUS] Subscribed to {event_name}: {callback.__name__}")

    def publish(self, event_name: str, *args, **kwargs) -> None:
        """Publish an event, notifying all subscribers."""
        if event_name in self._subscribers:
            logging.debug(f"[EVENT_BUS] Publishing {event_name} to {len(self._subscribers[event_name])} listeners.")
            for callback in self._subscribers[event_name]:
                try:
                    # Execute the callback with the provided arguments
                    callback(*args, **kwargs)
                except Exception as e:
                    logging.error(f"[EVENT_BUS] Error executing callback for {event_name}: {e}", exc_info=True)
