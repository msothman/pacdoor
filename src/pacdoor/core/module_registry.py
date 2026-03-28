"""Auto-discovers and registers all BaseModule subclasses."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import TYPE_CHECKING, Any

from pacdoor.core.models import Phase

if TYPE_CHECKING:
    from pacdoor.modules.base import BaseModule

log = logging.getLogger(__name__)


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, BaseModule] = {}

    def discover_modules(self, external_dirs: list[str] | None = None) -> None:
        """Walk pacdoor.modules.* and register every concrete BaseModule subclass.

        If *external_dirs* is provided, also load .py files from those
        directories (custom/plugin modules).
        """
        import pacdoor.modules as root_pkg
        from pacdoor.modules.base import BaseModule

        for _importer, modname, _ispkg in pkgutil.walk_packages(
            root_pkg.__path__, prefix="pacdoor.modules."
        ):
            if modname.endswith(".base"):
                continue
            try:
                module = importlib.import_module(modname)
            except Exception as exc:
                log.warning("Skip module %s: %s", modname, exc)
                continue

            self._register_from_module(module, BaseModule)

        # Load external/plugin modules from user-specified directories.
        for ext_dir in external_dirs or []:
            self._discover_external(ext_dir, BaseModule)

    def _register_from_module(self, module: Any, base_cls: type) -> None:
        """Register all concrete BaseModule subclasses from a Python module."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                inspect.isclass(attr)
                and issubclass(attr, base_cls)
                and attr is not base_cls
                and not inspect.isabstract(attr)
            ):
                try:
                    instance = attr()
                    self._modules[instance.name] = instance
                    log.debug("Registered module: %s", instance.name)
                except Exception as exc:
                    log.debug("Failed to instantiate %s: %s", attr_name, exc)

    def _discover_external(self, directory: str, base_cls: type) -> None:
        """Load .py files from an external directory as custom modules."""
        import importlib.util
        from pathlib import Path

        ext_path = Path(directory)
        if not ext_path.is_dir():
            log.warning("External module directory does not exist: %s", directory)
            return

        for py_file in ext_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            mod_name = f"pacdoor_ext.{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self._register_from_module(module, base_cls)
                    log.info("Loaded external module: %s", py_file.name)
            except Exception as exc:
                log.warning("Failed to load external module %s: %s", py_file.name, exc)

    def register(self, module: BaseModule) -> None:
        self._modules[module.name] = module

    def all_modules(self) -> list[BaseModule]:
        return list(self._modules.values())

    def get(self, name: str) -> BaseModule | None:
        return self._modules.get(name)

    def get_by_phase(self, phase: Phase) -> list[BaseModule]:
        return [m for m in self._modules.values() if m.phase == phase]

    def remove_phase(self, phase_value: str) -> None:
        to_remove = [
            name for name, m in self._modules.items()
            if m.phase.value == phase_value
        ]
        for name in to_remove:
            del self._modules[name]

    def remove_by_name(self, name: str) -> bool:
        """Remove a module by name. Returns True if found."""
        return self._modules.pop(name, None) is not None

    def count(self) -> int:
        return len(self._modules)

    def list_names(self) -> list[str]:
        return sorted(self._modules.keys())
