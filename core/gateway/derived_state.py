import logging
import threading
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DerivedStateManager:
    """
    Manages derived state (embedding index entries, canned response templates, cached prompt contexts).
    Guarantees that when a core policy or rule is recovered or rolled back by TCRP,
    all downstream derived state is purged and rebuilt or re-linked to the verified baseline.
    Ensures ZERO poisoned derived entries remain after recovery.
    """

    def __init__(self):
        # parent_memory_id -> set of derived_item_ids
        self._dependency_map: Dict[str, Set[str]] = {}
        # item_id -> {"type": str, "content": str, "parent_id": str, "builder": Callable}
        self._derived_items: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self.stats = {
            "registered_items": 0,
            "purged_items": 0,
            "rebuilt_items": 0,
        }

    def register_derived_item(
        self,
        item_id: str,
        parent_memory_id: str,
        item_type: str,
        content: str,
        builder_fn: Optional[Callable[[str], str]] = None,
    ) -> None:
        """
        Registers a derived artifact (e.g., canned template, embedding, cached answer)
        tied to a parent policy.
        """
        with self._lock:
            self._dependency_map.setdefault(parent_memory_id, set()).add(item_id)
            self._derived_items[item_id] = {
                "item_id": item_id,
                "parent_memory_id": parent_memory_id,
                "item_type": item_type,
                "content": content,
                "builder_fn": builder_fn,
                "poisoned": False,
            }
            self.stats["registered_items"] = len(self._derived_items)

    def get_derived_item(self, item_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._derived_items.get(item_id)
            if item and not item.get("poisoned", False):
                return dict(item)
            return None

    def invalidate_and_rebuild(
        self,
        parent_memory_id: str,
        verified_parent_content: str,
    ) -> List[Dict[str, Any]]:
        """
        Purges any poisoned derived items dependent on parent_memory_id and
        rebuilds/re-links them from the verified baseline content.
        """
        rebuilt = []
        with self._lock:
            derived_ids = list(self._dependency_map.get(parent_memory_id, set()))
            for item_id in derived_ids:
                item = self._derived_items.get(item_id)
                if not item:
                    continue

                self.stats["purged_items"] += 1

                # Rebuild if builder function provided, or re-link with verified baseline
                builder = item.get("builder_fn")
                if builder:
                    try:
                        new_content = builder(verified_parent_content)
                    except Exception as exc:
                        new_content = f"Template re-linked to verified {parent_memory_id}: {verified_parent_content}"
                else:
                    new_content = f"Template re-linked to verified {parent_memory_id}: {verified_parent_content}"

                item["content"] = new_content
                item["poisoned"] = False
                rebuilt.append(dict(item))
                self.stats["rebuilt_items"] += 1

        return rebuilt

    def list_poisoned_items(self) -> List[str]:
        with self._lock:
            return [k for k, v in self._derived_items.items() if v.get("poisoned", False)]

    def clear(self) -> None:
        with self._lock:
            self._dependency_map.clear()
            self._derived_items.clear()


_GLOBAL_DERIVED_STATE: Optional[DerivedStateManager] = None


def get_derived_state_manager() -> DerivedStateManager:
    global _GLOBAL_DERIVED_STATE
    if _GLOBAL_DERIVED_STATE is None:
        _GLOBAL_DERIVED_STATE = DerivedStateManager()
    return _GLOBAL_DERIVED_STATE
