"""Write values into SPL searches safely."""


def spl_string(value: str) -> str:
    r"""Write a value as a double-quoted SPL string.

    Backslashes are escaped first, then double quotes, so a value cannot
    close the string and inject SPL (``a"b\c`` becomes ``"a\"b\\c"``).
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def spl_list(values: list[str], empty: str) -> str:
    """Write values as a quoted, comma-separated list for SPL ``IN (...)``.

    ``empty`` is written instead when there is no value: ``"*"`` matches
    anything, ``'""'`` matches nothing.
    """
    return ",".join(spl_string(value) for value in values) if values else empty
