"""Packaging invariants — la version es una sola fuente de verdad."""
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_is_4_0_0():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["project"]["version"] == "4.0.0"


def test_setup_py_matches_pyproject():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    setup_src = (ROOT / "setup.py").read_text()
    m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', setup_src)
    assert m, "setup.py sin version explicita"
    assert m.group(1) == data["project"]["version"]


def test_engine_tool_version_matches_pyproject(tmp_path):
    from src.engine import CodeAuditEngine

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    (tmp_path / "a.py").write_text("x = 1\n")
    result = CodeAuditEngine().scan(str(tmp_path))
    assert result.tool_version == data["project"]["version"], \
        "el tool_version del engine no coincide con pyproject"
