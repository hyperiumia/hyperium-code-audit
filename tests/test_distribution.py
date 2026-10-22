"""Fase 6.2 (P0) — Distribucion: CLI base sin binarios, packs empaquetados."""
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from src.cli import main

ROOT = Path(__file__).resolve().parent.parent


def test_rulepacks_package_ships_roblox():
    import rulepacks

    pack = Path(rulepacks.__file__).resolve().parent / "roblox.yaml"
    assert pack.exists(), "el pack roblox.yaml no viaja con el paquete rulepacks"


def test_load_custom_rules_resolves_pack_name():
    from src.custom_rules import load_custom_rules

    rules = load_custom_rules("roblox")
    assert len(rules) == 14, f"pack roblox incompleto: {len(rules)} reglas"


def test_loader_degrades_without_binary(tmp_path):
    src = ROOT / "src" / "payment_logic.py"
    dst = tmp_path / "payment_logic.py"
    shutil.copy(src, dst)
    code = (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('payment_logic', "
        + repr(str(dst)) + ")\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "assert m.COMPILED_AVAILABLE is False, 'flag no expuesto'\n"
        "a = m.PaymentLogicAnalyzer()\n"
        "assert a.analyze('x') == [], 'placeholder debe degradar sin romper'\n"
        "print('DEGRADED_OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert "DEGRADED_OK" in r.stdout, r.stderr


def test_cli_announces_degraded_modules(tmp_path):
    import src.payment_logic as pl
    import src.taint_analyzer as ta

    target = tmp_path / "proj"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")
    args = ["scan", str(target), "--no-deps", "--format", "json",
            "-o", str(tmp_path / "o")]
    with patch.object(pl, "COMPILED_AVAILABLE", False), \
         patch.object(ta, "COMPILED_AVAILABLE", False):
        r = CliRunner().invoke(main, args)
    assert "optional compiled modules unavailable" in r.output.lower(), \
        "la degradacion de modulos comerciales debe anunciarse"
