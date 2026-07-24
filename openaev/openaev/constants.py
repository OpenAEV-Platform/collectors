# OpenAEV native payloads are endpoint command execution / file drops: the
# detecting/preventing security platforms are endpoint agents (EDR/XDR) and the
# SIEM that ingests their telemetry. Applied per expectation type declared on
# the payload, only when the source repo JSON does not declare
# payload_expected_security_platforms itself (an explicit value always wins).
# Empty would mean "any platform".
DEFAULT_EXPECTED_SECURITY_PLATFORMS = {
    "DETECTION": ["EDR", "XDR", "SIEM"],
    "PREVENTION": ["EDR", "XDR"],
}
