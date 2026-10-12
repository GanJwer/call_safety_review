"""模型 Provider 的环境变量解析（DeepSeek / OpenAI / 通用命名）。

全部用例通过显式传入 env 映射完成，不依赖也不污染真实环境变量。
"""

from __future__ import annotations

import os
import unittest

from call_safety_review.agent import (
    DEEPSEEK_DEFAULT_BASE_URL,
    DEEPSEEK_DEFAULT_MODEL,
    openai_model_from_env,
    resolve_model_settings,
)

class ModelSettingsTests(unittest.TestCase):
    # -- 解析规则 --------------------------------------------------------
    def test_deepseek_key_alone_fills_defaults(self) -> None:
        settings = resolve_model_settings({"DEEPSEEK_API_KEY": "sk-deepseek-demo"})
        self.assertEqual(settings["model"], DEEPSEEK_DEFAULT_MODEL)
        self.assertEqual(settings["base_url"], DEEPSEEK_DEFAULT_BASE_URL)
        self.assertEqual(settings["api_key"], "sk-deepseek-demo")

    def test_deepseek_model_and_base_can_be_overridden(self) -> None:
        settings = resolve_model_settings(
            {
                "DEEPSEEK_API_KEY": "sk-deepseek-demo",
                "DEEPSEEK_MODEL": "deepseek-reasoner",
                "DEEPSEEK_BASE_URL": "https://api.deepseek.com/v1",
            }
        )
        self.assertEqual(settings["model"], "deepseek-reasoner")
        self.assertEqual(settings["base_url"], "https://api.deepseek.com/v1")

    def test_openai_naming_wins_over_deepseek_defaults(self) -> None:
        settings = resolve_model_settings(
            {
                "OPENAI_MODEL": "gpt-4o-mini",
                "OPENAI_API_KEY": "sk-openai-demo",
                "OPENAI_BASE_URL": "https://gateway.example.com/v1",
                "DEEPSEEK_API_KEY": "sk-deepseek-demo",
            }
        )
        self.assertEqual(settings["model"], "gpt-4o-mini")
        self.assertEqual(settings["base_url"], "https://gateway.example.com/v1")
        self.assertEqual(settings["api_key"], "sk-openai-demo")

    def test_generic_naming_has_highest_priority(self) -> None:
        settings = resolve_model_settings(
            {
                "LLM_MODEL": "llm-primary",
                "LLM_API_KEY": "sk-llm-demo",
                "LLM_BASE_URL": "https://llm.example.com/v1",
                "OPENAI_MODEL": "gpt-4o-mini",
                "OPENAI_API_KEY": "sk-openai-demo",
            }
        )
        self.assertEqual(settings["model"], "llm-primary")
        self.assertEqual(settings["api_key"], "sk-llm-demo")
        self.assertEqual(settings["base_url"], "https://llm.example.com/v1")

    def test_custom_gateway_without_model_still_requires_a_model(self) -> None:
        """给了自建网关地址但没给模型名时，不能瞎猜模型，必须报错。"""

        env = {"OPENAI_BASE_URL": "https://gateway.example.com/v1", "DEEPSEEK_API_KEY": "sk-deepseek-demo"}
        settings = resolve_model_settings(env)
        self.assertEqual(settings["model"], "")
        with self.assertRaises(RuntimeError):
            openai_model_from_env(env=env)

    def test_missing_configuration_error_lists_accepted_names(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            openai_model_from_env(env={})
        message = str(ctx.exception)
        for name in ("LLM_MODEL", "OPENAI_MODEL", "DEEPSEEK_MODEL", "DEEPSEEK_API_KEY"):
            self.assertIn(name, message)

    # -- Provider 构造 ---------------------------------------------------
    def test_provider_uses_deepseek_endpoint(self) -> None:
        provider = openai_model_from_env(temperature=0, env={"DEEPSEEK_API_KEY": "sk-deepseek-demo"})
        self.assertEqual(provider.model, DEEPSEEK_DEFAULT_MODEL)
        self.assertEqual(provider.base_url, DEEPSEEK_DEFAULT_BASE_URL)
        self.assertEqual(provider.api_key, "sk-deepseek-demo")

    def test_preflight_reports_resolved_model_and_endpoint(self) -> None:
        import asyncio
        import tempfile
        from pathlib import Path

        from call_safety_review.acps_service import AcpsSettings, preflight

        with tempfile.TemporaryDirectory(prefix="csr-model-") as tmp:
            settings = AcpsSettings(
                registry_url="https://wt.ioa.pub/registry-server",
                ca_url="https://wt.ioa.pub/ca-server",
                discovery_url="https://wt.ioa.pub/discovery",
                public_endpoint="https://review.example.com/acps/aip/v1",
                organization="Example Org",
                country_code="CN",
                workspace=str(Path(tmp) / "state"),
            )
            env = {**dict(os.environ), "DEEPSEEK_API_KEY": "sk-deepseek-demo"}
            for key in ("LLM_API_KEY", "OPENAI_API_KEY", "LLM_BASE_URL", "OPENAI_BASE_URL"):
                env.pop(key, None)
            report = asyncio.run(preflight(settings=settings, env=env))

        model_check = next(item for item in report["checks"] if item["name"] == "model_provider")
        self.assertTrue(model_check["ok"])
        self.assertIn(DEEPSEEK_DEFAULT_MODEL, model_check["detail"])
        self.assertIn(DEEPSEEK_DEFAULT_BASE_URL, model_check["detail"])
        self.assertNotIn("sk-deepseek-demo", model_check["detail"])  # 详情里绝不回显密钥


if __name__ == "__main__":
    unittest.main()
