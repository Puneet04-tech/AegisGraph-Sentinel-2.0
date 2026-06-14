"""In-memory runtime containment flags."""

from __future__ import annotations

import threading
from typing import Dict


class ContainmentManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.event_throttled = False
        self.recovery_suppressed = False
        self.admin_cooldown = False

    def activate_containment(
        self,
        *,
        event_throttled: bool = True,
        recovery_suppressed: bool = True,
        admin_cooldown: bool = True,
    ) -> Dict[str, bool]:
        with self._lock:
            self.event_throttled = event_throttled
            self.recovery_suppressed = recovery_suppressed
            self.admin_cooldown = admin_cooldown
            return self.get_flags()

    def deactivate_containment(self) -> Dict[str, bool]:
        with self._lock:
            self.event_throttled = False
            self.recovery_suppressed = False
            self.admin_cooldown = False
            return self.get_flags()

    def get_flags(self) -> Dict[str, bool]:
        with self._lock:
            return {
                "event_throttled": self.event_throttled,
                "recovery_suppressed": self.recovery_suppressed,
                "admin_cooldown": self.admin_cooldown,
            }
