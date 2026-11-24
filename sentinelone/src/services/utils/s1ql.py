"""Write values into S1QL filters safely."""


def s1ql_string(value: str) -> str:
    r"""Write a value as a single-quoted S1QL 2.0 string (SDL, SaaS).

    Backslashes are escaped first, then single quotes, so a value cannot
    close the string and add conditions (``a'b\c`` becomes ``'a\'b\\c'``).
    """
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def s1ql_list(values: list[str]) -> str:
    """Write values as a comma-separated list of S1QL 2.0 strings."""
    return ",".join(s1ql_string(value) for value in values)


def dv_string(value: str) -> str:
    r"""Write a value as a double-quoted S1QL 1.0 string (Deep Visibility).

    Backslashes are escaped first, then double quotes, so a value cannot
    close the string and add conditions (``a"b\c`` becomes ``"a\"b\\c"``).
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def dv_list(values: list[str]) -> str:
    """Write values as a comma-separated list of S1QL 1.0 strings."""
    return ",".join(dv_string(value) for value in values)
