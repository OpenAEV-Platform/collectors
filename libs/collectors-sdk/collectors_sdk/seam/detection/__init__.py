"""Alert-element detection helpers."""

from collectors_sdk._core.detection import OpenAEVDetectionHelper, _is_base64_encoded

# ``_is_base64_encoded`` is not public: it is surfaced here only so the legacy
# ``pyoaev.helpers._is_base64_encoded`` path keeps resolving.
__all__ = ["OpenAEVDetectionHelper", "_is_base64_encoded"]
