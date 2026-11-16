"""Fixtures for Area C — packet/field and enrichment parsing.

Loads `passive-monitor.py` (dash in the name → importlib) as `pm`, and `db/enrich.py`
as `enrich` (db/ is already on sys.path via the root conftest). A `mkline` helper builds
a synthetic tshark field row keyed by TSHARK_FIELDS name.
"""
import importlib.util
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load_pm():
    spec = importlib.util.spec_from_file_location("passive_monitor", _ROOT / "passive-monitor.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_PM = _load_pm()
import enrich as _ENRICH  # noqa: E402  (db/ on sys.path via root conftest)


@pytest.fixture
def pm(monkeypatch):
    """The passive-monitor module, with vendor_for stubbed to a deterministic value so the
    tuple's vendor slot never depends on the OUI data files."""
    monkeypatch.setattr(_PM, "vendor_for", lambda mac, oui=None: ("V:" + mac) if mac else None)
    return _PM


@pytest.fixture
def enrich():
    return _ENRICH


@pytest.fixture
def mkline(pm):
    """Build a tshark output line (SEP-joined) from a {field_name: value} dict.
    Unspecified fields are empty strings, exactly as tshark emits for an absent field."""
    def _mk(values=None):
        row = [""] * len(pm.TSHARK_FIELDS)
        for name, val in (values or {}).items():
            row[pm.F[name]] = val
        return pm.SEP.join(row)
    return _mk


@pytest.fixture
def parse(pm, mkline):
    """parse one field dict → list of (source, mac, ip, hostname, vendor, details) tuples."""
    def _parse(values=None):
        return pm.parse_line(mkline(values), None)
    return _parse
