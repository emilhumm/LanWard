"""Area B (homechecks.py + scan.py) local helpers.

Nothing here touches the network: every probe that would do I/O is mocked in the test that uses it.
Shared conftest fixtures (db, make, _block_network, ...) still apply.
"""
import io
import urllib.error

import pytest


# ---- a synthetic hosts row for check_host / finding helpers (a dict is enough: the code subscripts h["x"]) ----

_HOST_COLS = (
    "scan_id ip mac vendor hostname ports open_ports firmware web_info tls_cert_cn tls_cert_issuer "
    "tls_cert_not_before tls_cert_not_after tls_cert_fingerprint tls_cert_san upnp_info findings bridge_mac"
).split()


def host_row(**cols):
    """A hosts-shaped dict with every column present (None unless given). ip defaults to a LAN address."""
    row = {c: None for c in _HOST_COLS}
    row["ip"] = "192.168.10.50"
    row.update(cols)
    return row


@pytest.fixture
def H():
    return host_row


# ---- a fake urllib.request.urlopen, driven by a per-URL responder ----

class FakeResp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self, n=-1):
        return self._b if n is None or n < 0 else self._b[:n]


def http_error(code, body=b""):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))


def fake_urlopen(responder):
    """responder(request_or_url) -> bytes (served) | HTTPError instance (raised) | Exception (raised)."""
    def _open(req, timeout=None):
        out = responder(req)
        if isinstance(out, BaseException):
            raise out
        return FakeResp(out)
    return _open
