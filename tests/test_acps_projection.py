"""ACPs 能力名片（ACS）投影：证明审查能力可被其它智能体调用。

这里只验证**本地可验证的部分**：Agent 声明 → `compile()` → ACS candidate。
它不证明 Registry 注册、CA 签发、Discovery 与跨主机 mTLS——那些属于
需要外部基础设施的互操作用例（参考手册「测试验证边界」）。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from call_safety_review.acps_service import AcpsSettings, build_acps_config, build_partner_agent
from call_safety_review.agent import build_engine
from call_safety_review.integrations import build_protected_caller

from .support import ScriptedModel


def _settings() -> AcpsSettings:
    return AcpsSettings(
        registry_url="https://registry.example.com",
        registry_mtls_url="https://registry-mtls.example.com",
        ca_url="https://ca.example.com",
        discovery_url="https://discovery.example.com/acps-adp-v2/discover",
        public_endpoint="https://review.example.com/acps/aip/v1",
        organization="Example Org",
        country_code="CN",
    )


class AcpsProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        from wit import ModelResponse

        self.model = ScriptedModel(ModelResponse.final("ok"))
        self._tmp = tempfile.TemporaryDirectory(prefix="csr-acps-")
        self.workspace = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_settings_require_env(self) -> None:
        with self.assertRaises(RuntimeError):
            AcpsSettings.from_env({})

    def test_direct_binding_projects_acs_with_review_skill(self) -> None:
        from wit import WitRuntime

        agent = build_partner_agent(
            model=self.model,
            engine=build_engine(),
            modes=("rpc", "stream"),
        )
        runtime = WitRuntime(
            agent, workspace=self.workspace / "partner", acps=build_acps_config(_settings())
        )
        diagnostics = [item.to_dict() for item in runtime.compiled.diagnostics]
        errors = [item for item in diagnostics if item["level"] == "error"]
        self.assertEqual(errors, [], msg=diagnostics)

        draft = runtime.acs_draft()
        skill_ids = {item["id"] for item in draft["skills"]}
        self.assertEqual(skill_ids, {"safety.review_call"})
        self.assertEqual(draft["endPoints"][0]["transport"], "JSONRPC")
        self.assertTrue(draft["endPoints"][0]["url"].endswith("/rpc"))
        self.assertEqual(draft["capabilities"]["streaming"], True)
        self.assertEqual(draft["provider"]["organization"], "Example Org")
        aip_hook_types = {type(hook).__name__ for hook in runtime.compiled.aip_hooks}
        amp_hook_types = {type(hook).__name__ for hook in runtime.compiled.amp_hooks}
        self.assertIn("TaskCorrelatedAmpAccessHooks", aip_hook_types)
        self.assertNotIn("AmpAccessLoggingHooks", amp_hook_types)

    def test_without_acps_binding_there_is_no_acs_draft(self) -> None:
        from wit import WitRuntime

        from call_safety_review import build_review_agent

        runtime = WitRuntime(
            build_review_agent(model=self.model), workspace=self.workspace / "no-acps"
        )
        with self.assertRaises(Exception):
            runtime.acs_draft()

    def test_protected_caller_uses_same_engine_policy(self) -> None:
        caller = build_protected_caller(model=self.model, engine=build_engine())
        self.assertEqual(caller.agent.id, "protected-caller")
        hook_ids = {hook.id for hook in caller.agent.hooks}
        self.assertIn("safety.pre-send-guard", hook_ids)


if __name__ == "__main__":
    unittest.main()
