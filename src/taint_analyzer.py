"""
src/taint_analyzer.py — Compiled module.

This module has been compiled to a native binary for intellectual property
protection. The compiled .so/.pyd file is required for operation.

To use this module:
  - Install via pip: pip install hyperium-code-audit (includes pre-built binary)
  - Or build from source: python build_protected.py (requires Cython + source license)

The .protected source files are available under a separate commercial license.
Contact: https://github.com/hyperiumia/hyperium-code-audit/issues
"""
import importlib
import os
import sys

# Auto-import from compiled .so/.pyd if available
_dir = os.path.dirname(os.path.abspath(__file__))

def _load_compiled():
    """Attempt to load the compiled binary module."""
    import importlib.util
    for ext in (".so", ".pyd"):
        for f in os.listdir(_dir):
            if f.startswith("taint_analyzer") and f.endswith(ext) and "cpython" in f:
                spec = importlib.util.spec_from_file_location(
                    "taint_analyzer",
                    os.path.join(_dir, f),
                )
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    return mod
    return None

_compiled = _load_compiled()
if _compiled:
    # Re-export everything from the compiled module
    if hasattr(_compiled, "TaintAnalyzer"):
        TaintAnalyzer = _compiled.TaintAnalyzer
    if hasattr(_compiled, "PaymentLogicAnalyzer"):
        PaymentLogicAnalyzer = _compiled.PaymentLogicAnalyzer
    # Copy all public attributes
    for attr in dir(_compiled):
        if not attr.startswith("_"):
            globals()[attr] = getattr(_compiled, attr)
else:
    raise ImportError(
        f"Compiled binary for taint_analyzer not found. "
        "Install via pip (pip install hyperium-code-audit) for pre-built binaries, "
        "or build from source with a commercial license."
    )
