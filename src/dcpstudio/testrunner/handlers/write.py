"""Handlers for the ``write.*`` functional-test namespace and their helpers."""

from __future__ import annotations

from ...constants import DEFAULT_POST_CHECK_WINDOW_S
from ...model import TestResult
from ...operations import (
    OperationSpec,
    confirmation_for,
    reset_mode_spec,
    set_ip_spec,
    set_name_spec,
)
from ...services.write import (
    WriteConfig,
    WriteRequest,
    identity_text,
    probe_target,
)
from ..cases import TestCase


class WriteHandlersMixin:
    def _write_config(self) -> WriteConfig:
        timeout_s = max(0.5, float(self.config.timeout_s))
        return WriteConfig(
            timeout_s=timeout_s,
            revalidate_timeout_s=timeout_s,
            verify_timeout_s=timeout_s,
            vlan_id=self.config.vlan_id,
            min_request_interval_s=self.config.min_request_interval_s,
            verify_after_set=True,
        )

    def _prepare_guarded_write(
        self,
        case: TestCase,
        *,
        kind: str,
        params: dict,
        spec: OperationSpec,
    ) -> tuple[WriteRequest | None, str]:
        if self.target is None:
            return None, "No target device was passed to the test runner."
        authorization = self.write_authorizations.get(case.test_id)
        if authorization is None:
            return None, "No per-operation confirmation was supplied for this test."
        confirmation = confirmation_for(
            spec,
            interface_id=self.transport.interface.id,
            interface_name=self.transport.interface.display_name,
            target_mac=self.target.mac,
            target_identity=identity_text(self.target),
            operation_id=case.test_id,
        )
        request = WriteRequest(
            kind=kind,
            target_mac=self.target.mac,
            confirmation=confirmation,
            authorization=authorization,
            config=self._write_config(),
            target_name=self.target.name_of_station,
            **params,
        )
        return request, ""

    def _refresh_declared_target(self) -> None:
        """Refresh the declared DUT identity with one read-only unicast Identify.

        A verified Set changes the very fields the next step revalidates against,
        and an acknowledgement (or a read-back Get) is not the full Identify
        identity. Only a fresh Identify is used, and only after a verified
        Set-to-same-device; no state-changing frame is sent here.
        """
        if self.target is None:
            return
        mac = self.target.mac
        try:
            probe = probe_target(
                self._discovery(),
                target_mac=mac,
                target_name=self.target.name_of_station,
                timeout_s=min(self.config.timeout_s, 3.0),
                vlan_id=self.config.vlan_id,
                response_delay_factor=self.config.response_delay_factor,
                min_request_interval_s=self.config.min_request_interval_s,
            )
        except Exception:
            return
        if probe.device is not None:
            self.target = probe.device

    def _write_outcome(self, case, result, *, reset: bool = False) -> TestResult:
        # The next state-changing step must revalidate against the *current*
        # identity, so refresh it with one read-only Identify after a verified Set.
        if (
            not reset
            and case.test_id in ("write.set_name", "write.set_ip")
            and result.state == "acknowledged"
            and result.verification == "verified"
        ):
            self._refresh_declared_target()
        evidence = {"target": result.target_mac, "write": result.to_dict()}
        if result.state == "cancelled":
            if result.transmitted:
                return self._result(
                    case,
                    "inconclusive",
                    "Cancelled after the state-changing frame was transmitted; outcome unknown.",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            return self._result(case, "skipped", "Cancelled by user", evidence=evidence)
        if result.state in ("blocked", "target_unverified"):
            return self._result(
                case,
                "skipped",
                result.error or "Safety checks blocked transmission.",
                evidence=evidence,
                warnings=result.warnings,
            )
        if result.state == "acknowledged":
            if reset:
                warnings = list(result.warnings)
                if result.post_check_detail:
                    warnings.append(result.post_check_detail)
                return self._result(
                    case,
                    "inconclusive",
                    "Reset was acknowledged, but acknowledgement is not proof of completion. "
                    "The post-check proves reachability only; erased scope is vendor-dependent.",
                    evidence=evidence,
                    warnings=warnings,
                )
            if result.verification == "verified":
                return self._result(
                    case,
                    "passed",
                    f"{result.operation_text} acknowledged and independently read back",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            if result.verification == "mismatch":
                return self._result(
                    case,
                    "failed",
                    f"{result.operation_text} was acknowledged, but read-back did not match.",
                    evidence=evidence,
                    warnings=result.warnings,
                )
            return self._result(
                case,
                "inconclusive",
                f"{result.operation_text} was acknowledged, but independent verification "
                "was inconclusive.",
                evidence=evidence,
                warnings=result.warnings,
            )
        return self._result(
            case,
            "inconclusive",
            f"{result.operation_text}: {result.outcome_text}",
            evidence=evidence,
            warnings=result.warnings,
        )

    def _test_write_set_name(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        name = params.get("name")
        if name is None:
            return self._result(
                case, "skipped", "No NameOfStation test value was supplied by the caller."
            )
        permanent = bool(params.get("permanent", False))
        request, reason = self._prepare_guarded_write(
            case,
            kind="set_name",
            params={"name": name, "permanent": permanent},
            spec=set_name_spec(
                name,
                permanent=permanent,
                previous_name=self.target.name_of_station if self.target else None,
            ),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        result = self._writer().execute(request, cancel_event=cancel_event)
        return self._write_outcome(case, result)

    def _test_write_set_ip(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        ip = params.get("ip_address")
        mask = params.get("subnet_mask")
        if not ip or not mask:
            return self._result(
                case, "skipped", "No IPv4 test values were supplied by the caller."
            )
        gateway = params.get("gateway", "")
        permanent = bool(params.get("permanent", False))
        request, reason = self._prepare_guarded_write(
            case,
            kind="set_ip",
            params={
                "ip_address": ip,
                "subnet_mask": mask,
                "gateway": gateway,
                "permanent": permanent,
            },
            spec=set_ip_spec(
                ip,
                mask,
                gateway,
                permanent=permanent,
                previous_ip=self.target.ip_text if self.target else None,
            ),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        result = self._writer().execute(request, cancel_event=cancel_event)
        return self._write_outcome(case, result)

    def _test_write_reset(self, case, cancel_event) -> TestResult:
        ok, message = self._ensure_capture()
        if not ok:
            return self._result(case, "failed", message)
        params = self.write_parameters.get(case.test_id, {})
        mode = int(params.get("reset_mode", 8))
        if mode not in (1, 2, 4, 8):
            return self._result(
                case, "skipped", f"Reset mode {mode} is not implemented by this build."
            )
        request, reason = self._prepare_guarded_write(
            case,
            kind="reset",
            params={"reset_mode": mode},
            spec=reset_mode_spec(mode),
        )
        if request is None:
            return self._result(case, "skipped", reason)
        writer = self._writer()
        result = writer.execute(request, cancel_event=cancel_event)
        if result.state == "acknowledged" and not cancel_event.is_set():
            writer.post_check(
                result,
                timeout_s=max(0.5, min(float(self.config.timeout_s), 3.0)),
                recheck_window_s=DEFAULT_POST_CHECK_WINDOW_S,
                cancel_event=cancel_event,
            )
        return self._write_outcome(case, result, reset=True)
