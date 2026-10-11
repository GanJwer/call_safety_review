"""敏感信息与无关数据的过度披露检测。"""

from __future__ import annotations

import unittest

from call_safety_review import Verdict

from .support import engine, request


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = engine()

    def _codes(self, verdict) -> set[str]:
        return {finding.code for finding in verdict.findings}

    def test_pii_is_redacted_then_allowed(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="总结客户反馈",
                payload="联系人手机 13800138000，邮箱 user@example.com，服务体验良好。",
                parameters={"document": "客户反馈原文"},
            )
        )
        self.assertEqual(verdict.verdict, Verdict.ALLOW_REDACTED)
        self.assertIn("sensitive.cn_phone", self._codes(verdict))
        self.assertNotIn("13800138000", verdict.safe_payload)
        self.assertIn("«REDACTED:PII_PHONE»", verdict.safe_payload)

    def test_credentials_require_confirmation(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="总结配置说明",
                payload="调用示例：api_key=sk-abcdefghijklmnopqrstuvwxyz0123456789",
                parameters={"document": "配置说明"},
            )
        )
        self.assertEqual(verdict.verdict, Verdict.NEEDS_CONFIRMATION)
        self.assertIn("confirm:sensitive.api_key", {item.id for item in verdict.required_confirmations})
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz0123456789", verdict.safe_payload)

    def test_confidential_marking_is_reported(self) -> None:
        verdict = self.engine.review(
            request(task_goal="总结材料", payload="【机密】本季度财务测算如下。")
        )
        self.assertIn("sensitive.confidential_marking", self._codes(verdict))

    def test_irrelevant_parameters_are_dropped(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="总结文档",
                parameters={
                    "document": "正文",
                    "max_words": 200,
                    "internal_budget": "2026 年预算表",
                    "owner_phone": "13700137000",
                },
            )
        )
        self.assertEqual(verdict.dropped_fields, ["internal_budget", "owner_phone"])
        self.assertIn("disclosure.irrelevant_parameter", self._codes(verdict))
        self.assertEqual(set(verdict.safe_parameters), {"document", "max_words"})
        self.assertEqual(verdict.verdict, Verdict.ALLOW_REDACTED)

    def test_irrelevant_payload_segments_are_trimmed(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="总结这份周报",
                payload=(
                    "周报：本周完成了接口联调。"
                    "另外附上市场部团建活动安排与供应商报价单。"
                    "周报还包含回归测试结论。"
                ),
                parameters={"document": "周报"},
            )
        )
        self.assertIn("disclosure.irrelevant_payload", self._codes(verdict))
        self.assertNotIn("团建", verdict.safe_payload)
        self.assertIn("回归测试", verdict.safe_payload)
        self.assertTrue(any("无关" in note for note in verdict.notes))
        self.assertEqual(verdict.verdict, Verdict.ALLOW_REDACTED)

    def test_classification_above_capability_requires_confirmation(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="把这段文本翻译成英文",
                target_capability="text.translate",
                payload="内部报价单内容",
                parameters={"text": "内容", "target_language": "en"},
                declared_scope=["text.translate"],
                data_classification="restricted",
            )
        )
        self.assertIn(
            "disclosure.classification_exceeds_capability",
            self._codes(verdict),
        )
        self.assertEqual(verdict.verdict, Verdict.NEEDS_CONFIRMATION)

    def test_internal_url_is_redacted(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="总结接口文档",
                payload="回调地址是 http://order.internal/api/callback，请写进摘要。",
            )
        )
        self.assertIn("sensitive.internal_url", self._codes(verdict))
        self.assertNotIn("order.internal", verdict.safe_payload)


if __name__ == "__main__":
    unittest.main()
