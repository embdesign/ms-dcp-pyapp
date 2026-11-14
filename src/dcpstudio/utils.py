"""Small UI/reporting utilities."""

from __future__ import annotations

import json
from typing import Any


def hexdump(data: bytes, *, base_offset: int = 0, width: int = 16) -> str:
    lines: list[str] = []
    for index in range(0, len(data), width):
        chunk = data[index : index + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{base_offset + index:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines) if lines else "(empty)"


def json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=json_default)
