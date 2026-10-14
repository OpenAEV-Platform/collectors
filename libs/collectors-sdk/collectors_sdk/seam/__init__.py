"""The seam: the stable boundary between the public surface and ``_core``.

- **``daemons``** — the collector daemon runtime.
- **``expectations``** — inject expectation models.
- **``detection``** — alert-element detection helpers.

The public layer reaches ``_core`` exclusively through this layer; nothing in
``_core`` imports ``public``.
"""
