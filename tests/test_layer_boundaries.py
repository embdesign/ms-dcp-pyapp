"""Architecture guard: enforce the layer rules recorded in ``AGENTS.md``.

The module graph is read from the source with ``ast`` — no import of the
package, no Qt, no Scapy, no network. A new dependency that points the wrong way
fails here instead of being discovered during a later refactor.

``KNOWN_DEBT`` lists any remaining violations. Each entry names the module and
the target; a stale entry fails the test, so remove it with the fix. Adding a
*new* violation is what this test refuses.
"""

from __future__ import annotations

import ast
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "dcpstudio"

# Pure modules: no Qt, no Scapy, no services, no transport implementation, no
# adapter. They may import each other, `constants`, `model` and the codec.
PURE_MODULES = frozenset(
    {
        "dcpstudio.codec",
        "dcpstudio.model",
        "dcpstudio.constants",
        "dcpstudio.operations",
        "dcpstudio.safety",
        "dcpstudio.validation",
        "dcpstudio.config",
        "dcpstudio.utils",
        "dcpstudio.logging_setup",
        "dcpstudio.pcap_io",
        "dcpstudio.reporting",
        "dcpstudio.fixtures",
        "dcpstudio.html_render",
        "dcpstudio.outcomes",
        "dcpstudio.interfaces",
        "dcpstudio.monitor",
        "dcpstudio.inventory",
    }
)

# Modules that must stay free of Qt, Scapy and the service/adapter layers.
FORBIDDEN_FROM_PURE = (
    "dcpstudio.services",
    "dcpstudio.transport",
    "dcpstudio.gui",
    "dcpstudio.cli",
    "dcpstudio.testrunner",
    "dcpstudio.session",
    "dcpstudio.mock",
    "PySide6",
    "scapy",
)

# The adapters that must stay Qt-free and must not depend on each other.
TEXT_ADAPTERS = ("dcpstudio.cli", "dcpstudio.testrunner")

# Modules outside the transport package that may name the in-memory mock
# transport. The shipped offline protocol tests use it deliberately; nothing
# else may, so a GUI or CLI module cannot silently pick a mock interface.
MOCK_ALLOWED_MODULES = frozenset(
    {
        "dcpstudio.session",
        "dcpstudio.testrunner.handlers.protocol",
    }
)

KNOWN_DEBT: dict[tuple[str, str], str] = {}
"""No known violations remain. Add an entry only with a plan to remove it."""


def _is(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _is_any(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(_is(module, prefix) for prefix in prefixes)


def _module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT.parent)
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_parts(path: Path) -> list[str]:
    relative = path.relative_to(SOURCE_ROOT.parent)
    parts = list(relative.with_suffix("").parts)
    if parts[-1] != "__init__":
        parts.pop()
    return parts


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _package_parts(path)
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - (node.level - 1)]
                if node.module:
                    base = base + node.module.split(".")
                target = ".".join(base)
            else:
                target = node.module or ""
            if target:
                targets.add(target)
    return targets


def _source_files() -> list[Path]:
    return sorted(SOURCE_ROOT.rglob("*.py"))


def _violations() -> set[tuple[str, str, str]]:
    found: set[tuple[str, str, str]] = set()
    for path in _source_files():
        module = _module_name(path)
        for target in _imports(path):
            reason = _reason(module, target)
            if reason is not None:
                found.add((module, target, reason))
    return found


def _reason(module: str, target: str) -> str | None:
    if module in PURE_MODULES and _is_any(target, FORBIDDEN_FROM_PURE):
        return "a pure module must not depend on the service, transport or adapter layer"

    if not _is(module, "dcpstudio.gui") and _is(target, "PySide6"):
        return "Qt is only allowed under dcpstudio.gui"

    if _is(module, "dcpstudio.gui.presentation") and _is(target, "PySide6"):
        return "gui.presentation is the Qt-free rendering layer"

    if not _is(module, "dcpstudio.transport") and _is(target, "scapy"):
        return "Scapy is only allowed under dcpstudio.transport"

    if _is(module, "dcpstudio.gui") and _is(target, "dcpstudio.codec"):
        return "the GUI must use operations/services, not the wire codec"

    if (
        not _is(module, "dcpstudio.transport")
        and module not in MOCK_ALLOWED_MODULES
        and _is(target, "dcpstudio.mock")
    ):
        return (
            "only the transport factory, the composition root and the offline "
            "protocol tests may pick a mock transport"
        )

    if _is(module, "dcpstudio.services") and _is_any(
        target,
        (
            "dcpstudio.gui",
            "dcpstudio.cli",
            "dcpstudio.testrunner",
            "dcpstudio.session",
            "PySide6",
            "scapy",
        ),
    ):
        return "a service must not depend on an adapter, the composition root or Qt/Scapy"

    if _is(module, "dcpstudio.transport") and _is_any(
        target,
        (
            "dcpstudio.services",
            "dcpstudio.gui",
            "dcpstudio.cli",
            "dcpstudio.testrunner",
            "dcpstudio.session",
        ),
    ):
        return "the transport layer must not depend on services, adapters or composition"

    if target == "dcpstudio.transport.factory" and module != "dcpstudio.session":
        return "only session.py may construct a transport"

    if _is(module, "dcpstudio.session") and _is_any(
        target, ("dcpstudio.gui", "dcpstudio.cli", "dcpstudio.testrunner")
    ):
        return "the composition root must not depend on an adapter"

    if _is_any(module, TEXT_ADAPTERS) and _is(target, "dcpstudio.gui"):
        return "headless adapters must not depend on the Qt GUI"

    return None


def test_scanner_sees_the_package() -> None:
    files = _source_files()
    assert len(files) > 40, f"expected the package to be scanned, found {len(files)} files"
    assert "dcpstudio.codec" in {_module_name(path) for path in files}


def test_import_resolution_handles_relative_imports() -> None:
    # gui/tabs/capture.py uses `from ...constants import DCP_BPF_FILTER`.
    capture = SOURCE_ROOT / "gui" / "tabs" / "capture.py"
    assert "dcpstudio.constants" in _imports(capture)
    # services/write.py uses `from ..codec import ...`.
    write = SOURCE_ROOT / "services" / "write.py"
    assert "dcpstudio.codec" in _imports(write)
    # model.py uses `from . import APP_NAME`.
    model = SOURCE_ROOT / "model.py"
    assert "dcpstudio" in _imports(model)


def test_no_new_layering_violations() -> None:
    violations = _violations()
    unexpected = {
        (module, target, reason)
        for module, target, reason in violations
        if (module, target) not in KNOWN_DEBT
    }
    assert not unexpected, "new layering violation(s):\n" + "\n".join(
        f"  {module} -> {target}: {reason}"
        for module, target, reason in sorted(unexpected)
    )


def test_known_debt_is_real_and_documented() -> None:
    violations = {(module, target) for module, target, _ in _violations()}
    stale = set(KNOWN_DEBT) - violations
    assert not stale, (
        "KNOWN_DEBT entries no longer occur; remove them from the allowlist: "
        f"{sorted(stale)}"
    )
