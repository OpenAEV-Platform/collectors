"""The seam: the contracts between the public adapters and the core.

- **``daemons``** — collector defaults and the registration / schedule ports.
- **``detection``** — the alert-matching port.
- **``expectations``** — expectation types, signatures and data, and the
  matching / update ports.

A seam is **closed**: it imports only the standard library, third-party
libraries (including the ``xtm_oaev_sdk`` public package) and sibling seam
modules — never ``_core`` nor ``public``. The core implements its ports; the
public adapters speak its types and delegate to the core. A seam change is a
contract change (``SEAM_VERSION`` bump, changelog).
"""
