"""Fase 6.5/6.6 (P1/P2) — Casos 11-15 de la revision externa + cobertura visible.

11. .env, Dockerfile y .tf descubiertos.
12. Omisiones contadas con motivo (oversize).
13. Exclusiones profundas (.venv) respetadas.
14. Symlinks no seguidos por defecto.
15. --since validado y conectado al filtro real.
7.  Sin pack Luau: cobertura limitada, nunca "clean".
"""
import subprocess

from click.testing import CliRunner

from src.cli import main
from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine


def _git(root, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=str(root), check=True, capture_output=True)


def test_special_files_discovered(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=synthetic\n")
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\n")
    (tmp_path / "main.tf").write_text("resource \"x\" \"y\" {}\n")
    found = {p.name for p in CodeAuditEngine()._discover_files(tmp_path)}
    assert {".env", "Dockerfile", "main.tf"} <= found, found


def test_oversize_skipped_counted_with_reason(tmp_path):
    (tmp_path / "big.py").write_text("# padding\n" * 200 + "x = 1\n")
    cfg = CodeAuditConfig()
    cfg.scan.max_file_size_kb = 1
    cfg.scanners.dep_analyzer = False
    result = CodeAuditEngine(cfg).scan(str(tmp_path))
    assert result.stats.skipped_files == 1, result.stats.model_dump()
    assert any("oversize" in n for n in result.stats.discovery_notes), \
        result.stats.discovery_notes


def test_nested_default_exclusion_respected(tmp_path):
    (tmp_path / ".venv" / "lib" / "pkg").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "pkg" / "vendor.py").write_text("x = 1\n")
    found = [str(p.relative_to(tmp_path)) for p in
             CodeAuditEngine()._discover_files(tmp_path)]
    assert found == [], found


def test_symlink_not_followed_by_default(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.py").symlink_to(outside)
    found = [p.name for p in CodeAuditEngine()._discover_files(root)]
    assert "link.py" not in found, found


def test_since_filters_to_changed_files(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    (root / "a.py").write_text("x = 1\n")
    (root / "c.py").write_text("z = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "init")
    (root / "a.py").write_text("x = 2\n")
    (root / "b.py").write_text("y = 1\n")
    cfg = CodeAuditConfig()
    cfg.scanners.incremental_since = "HEAD"
    cfg.scanners.dep_analyzer = False
    eng = CodeAuditEngine(cfg)
    found = sorted(p.name for p in eng._discover_files(root))
    assert found == ["a.py", "b.py"], found


def test_since_invalid_ref_exits_operational_error(tmp_path):
    root = tmp_path / "repo2"
    root.mkdir()
    _git(root, "init")
    (root / "a.py").write_text("x = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "init")
    r = CliRunner().invoke(main, ["scan", str(root), "--no-deps", "--since",
                                  "NONEXISTENT_REF_REVIEW", "--format", "json",
                                  "-o", str(tmp_path / "o")])
    assert r.exit_code == 2, r.output[-300:]
    assert "Exit 0: clean" not in r.output


def test_luau_without_pack_never_says_clean(tmp_path):
    game = tmp_path / "game"
    game.mkdir()
    (game / "m.luau").write_text("local x = loadstring(payload)\n")
    r = CliRunner().invoke(main, ["scan", str(game), "--no-deps",
                                  "--format", "json", "-o", str(tmp_path / "o")])
    assert "no custom rule pack active" in r.output.lower()
    assert "coverage limited" in r.output.lower()
    assert "Exit 0: clean" not in r.output, "sin pack Luau no debe anunciar clean"
