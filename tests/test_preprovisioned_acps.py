from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from call_safety_review.acps_service import AcpsSettings, build_partner_runtime
from call_safety_review.agent import build_engine
from call_safety_review.preprovisioned_acps import PreprovisionedAcpsMaterial
from tests.support import ScriptedModel


AIC = "1.2.156.3088.1.TEST.AGENT"
ENDPOINT = "https://203.0.113.10:45043/acps/aip/v1/rpc"


class PreprovisionedAcpsMaterialTests(unittest.TestCase):
    def test_mode_is_disabled_by_default(self) -> None:
        self.assertIsNone(PreprovisionedAcpsMaterial.from_env({}))

    def test_invalid_boolean_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "ACPS_PREPROVISIONED"):
            PreprovisionedAcpsMaterial.from_env({"ACPS_PREPROVISIONED": "maybe"})

    def test_final_acs_drives_aic_and_certificate_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="csr-preprovisioned-") as tmp:
            root = Path(tmp)
            material = PreprovisionedAcpsMaterial(root=root)
            (root / "acps" / "certs").mkdir(parents=True)
            (root / "acps" / "private").mkdir(parents=True)
            material.acs_path.write_text(
                json.dumps(
                    {
                        "aic": AIC,
                        "active": True,
                        "skills": [{"id": "safety.review_call"}],
                        "endPoints": [{"url": ENDPOINT}],
                    }
                ),
                encoding="utf-8",
            )
            expected_files = [
                root / "acps" / "certs" / f"{AIC}.client.pem",
                root / "acps" / "private" / f"{AIC}.client.key",
                root / "acps" / "certs" / f"{AIC}.pem",
                root / "acps" / "private" / f"{AIC}.key",
                root / "acps" / "trust-bundle.pem",
            ]
            for path in expected_files:
                path.write_text("test-only", encoding="utf-8")

            with (
                patch(
                    "call_safety_review.preprovisioned_acps.version",
                    return_value="2.1.0",
                ),
                patch(
                    "wit.acps.certificate_validation.validate_certificate_paths"
                ) as validate,
            ):
                aic, paths, _acs = material.validate(
                    public_endpoint=ENDPOINT.removesuffix("/rpc")
                )

            self.assertEqual(aic, AIC)
            self.assertEqual(paths.server_certificate, expected_files[2])
            validate.assert_called_once()

    def test_endpoint_mismatch_is_rejected_before_certificate_loading(self) -> None:
        with tempfile.TemporaryDirectory(prefix="csr-preprovisioned-") as tmp:
            root = Path(tmp)
            material = PreprovisionedAcpsMaterial(root=root)
            material.acs_path.write_text(
                json.dumps(
                    {
                        "aic": AIC,
                        "active": True,
                        "skills": [{"id": "safety.review_call"}],
                        "endPoints": [{"url": ENDPOINT}],
                    }
                ),
                encoding="utf-8",
            )
            with patch(
                "call_safety_review.preprovisioned_acps.version",
                return_value="2.1.0",
            ):
                with self.assertRaisesRegex(RuntimeError, "端点"):
                    material.validate(public_endpoint="https://wrong.example/acps/aip/v1")

    def test_runtime_receives_validated_in_memory_identity(self) -> None:
        from wit import ModelResponse

        with tempfile.TemporaryDirectory(prefix="csr-preprovisioned-") as tmp:
            root = Path(tmp)
            material = PreprovisionedAcpsMaterial(root=root / "material")
            (material.root / "acps" / "certs").mkdir(parents=True)
            (material.root / "acps" / "private").mkdir(parents=True)
            material.acs_path.write_text(
                json.dumps(
                    {
                        "aic": AIC,
                        "active": True,
                        "skills": [{"id": "safety.review_call"}],
                        "endPoints": [{"url": ENDPOINT}],
                    }
                ),
                encoding="utf-8",
            )
            for path in (
                material.root / "acps" / "certs" / f"{AIC}.client.pem",
                material.root / "acps" / "private" / f"{AIC}.client.key",
                material.root / "acps" / "certs" / f"{AIC}.pem",
                material.root / "acps" / "private" / f"{AIC}.key",
                material.root / "acps" / "trust-bundle.pem",
            ):
                path.write_text("test-only", encoding="utf-8")
            settings = AcpsSettings(
                registry_url="https://registry.example.com",
                registry_mtls_url="https://registry-mtls.example.com",
                ca_url="https://ca.example.com",
                discovery_url="https://discovery.example.com/acps-adp-v2/discover",
                public_endpoint=ENDPOINT.removesuffix("/rpc"),
                organization="Example Org",
                country_code="CN",
                workspace=str(root / "state"),
                preprovisioned=material,
            )
            with (
                patch(
                    "call_safety_review.preprovisioned_acps.version",
                    return_value="2.1.0",
                ),
                patch("wit.acps.certificate_validation.validate_certificate_paths"),
            ):
                runtime = build_partner_runtime(
                    model=ScriptedModel(ModelResponse.final("ok")),
                    settings=settings,
                    engine=build_engine(),
                )
            state = runtime._acps_provisioner().state()  # noqa: SLF001 - adapter contract
            self.assertEqual(state["status"], "active")
            self.assertEqual(state["identity"]["ref"]["aic"], AIC)
            self.assertFalse((root / "state" / "acps" / "enrollment.json").exists())


if __name__ == "__main__":
    unittest.main()
