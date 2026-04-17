from __future__ import annotations

import sys
from importlib import import_module
from pkgutil import walk_packages

_impl = import_module("clawpass_sdk_py")
__all__ = getattr(_impl, "__all__", [])
__path__ = list(_impl.__path__)

for name in dir(_impl):
    if not name.startswith("_"):
        globals()[name] = getattr(_impl, name)

for module_info in walk_packages(__path__, prefix=f"{_impl.__name__}."):
    canonical_name = module_info.name
    legacy_name = canonical_name.replace(_impl.__name__, __name__, 1)
    sys.modules.setdefault(legacy_name, import_module(canonical_name))
