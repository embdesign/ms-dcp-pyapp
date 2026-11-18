"""The test-ID ↔ handler invariant across the namespace mixins."""

from __future__ import annotations

import inspect

from dcpstudio.config import AppConfig
from dcpstudio.mock import MockNetwork, MockTransport
from dcpstudio.testrunner.cases import TEST_CASES
from dcpstudio.testrunner.runner import TestRunner


def _runner() -> TestRunner:
    return TestRunner(MockTransport(MockNetwork()), AppConfig(timeout_s=0.5))


def test_every_implemented_case_resolves_to_a_handler():
    runner = _runner()
    for case in TEST_CASES:
        if not case.implemented:
            continue
        handler = getattr(runner, f"_test_{case.test_id.replace('.', '_')}", None)
        assert callable(handler), f"no handler for {case.test_id}"


def test_each_handler_lives_in_its_namespace_module():
    runner = _runner()
    for case in TEST_CASES:
        if not case.implemented:
            continue
        namespace = case.test_id.split(".", 1)[0]
        handler = getattr(runner, f"_test_{case.test_id.replace('.', '_')}")
        module = inspect.getmodule(handler)
        assert module is not None
        assert module.__name__ == f"dcpstudio.testrunner.handlers.{namespace}", case.test_id


def test_runner_lists_the_same_catalogue():
    runner = _runner()
    assert [case.test_id for case in runner.list_tests()] == [
        case.test_id for case in TEST_CASES
    ]
