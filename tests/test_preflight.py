"""部署前自检（`acps --check`）的契约测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from call_safety_review.acps_service import REQUIRED_ENV_VARS, AcpsSettings, preflight
from call_safety_review.engine import ReviewEngine

from .support import ScriptedModel


def _env(**overrides: str) -> dict[str, str]:
    base = {
        "ACPS_REGISTRY_URL": "https://registry.example.com",
        "ACPS_CA_URL": "https://ca.example.com",
        "ACPS_DISCOVERY_URL": "https://discovery.example.com/acps-adp-v2/discover",
        "ACPS_PUBLIC_ENDPOINT": "https://review.example.com/acps/aip/v1",
        "ACPS_ORGANIZATION": "Example Org",
        "ACPS_COUNTRY_CODE": "CN",
    }
    base.update(overrides)
    return base


class PreflightTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="csr-preflight-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _settings(self, workspace: Path | None = None) -> AcpsSettings:
        return AcpsSettings(
            registry_url="https://registry.example.com",
            ca_url="https://ca.example.com",
            discovery_url="https://discovery.example.com/acps-adp-v2/discover",
            public_endpoint="https://review.example.com/acps/aip/v1",
            organization="Example Org",
            country_code="CN",
            workspace=str(workspace or (self.root / "state")),
        )

    async def test_preflight_passes_with_complete_config(self) -> None:
        from wit import ModelResponse

        report = await preflight(
            settings=self._settings(),
            model=ScriptedModel(ModelResponse.final("ok")),
            engine=ReviewEngine(),
            env=_env(),
        )
        self.assertTrue(report["ok"], msg=report)
        names = {item["name"] for item in report["checks"]}
        self.assertEqual(
            names,
            {"acps_env_vars", "state_dir_writable", "model_provider", "agent_assembly", "acs_projection"},
        )
        self.assertEqual(report["acs_skills"], ["safety.review_call"])
        self.assertTrue(all(item["ok"] for item in report["checks"]))

    async def test_preflight_reports_missing_env_vars(self) -> None:
        report = await preflight(env={})
        self.assertFalse(report["ok"])
        self.assertIn("ACPS_REGISTRY_URL", report["error"])
        self.assertFalse(report["checks"][0]["ok"])

    async def test_preflight_reports_unwritable_state_dir(self) -> None:
        from wit import ModelResponse

        blocker = self.root / "not-a-dir"
        blocker.write_text("file, not a directory", encoding="utf-8")
        report = await preflight(
            settings=self._settings(workspace=blocker),
            model=ScriptedModel(ModelResponse.final("ok")),
            env=_env(),
        )
        self.assertFalse(report["ok"])
        state_check = next(item for item in report["checks"] if item["name"] == "state_dir_writable")
        self.assertFalse(state_check["ok"])
        self.assertIn("不可写", state_check["detail"])

    async def test_preflight_flags_missing_model_provider(self) -> None:
        report = await preflight(settings=self._settings(), engine=ReviewEngine(), env=_env())
        model_check = next(item for item in report["checks"] if item["name"] == "model_provider")
        self.assertFalse(model_check["ok"])
        self.assertFalse(report["ok"])

    async def test_required_env_var_list_is_stable(self) -> None:
        self.assertEqual(
            set(REQUIRED_ENV_VARS),
            {
                "ACPS_REGISTRY_URL",
                "ACPS_CA_URL",
                "ACPS_DISCOVERY_URL",
                "ACPS_PUBLIC_ENDPOINT",
                "ACPS_ORGANIZATION",
                "ACPS_COUNTRY_CODE",
            },
        )


if __name__ == "__main__":
    unittest.main()
