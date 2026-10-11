"""任务与能力的语义错配检测。"""

from __future__ import annotations

import unittest

from call_safety_review import Verdict

from .support import engine, request


class MismatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = engine()

    def _codes(self, verdict) -> set[str]:
        return {finding.code for finding in verdict.findings}

    def test_read_only_capability_rejects_destructive_intent(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="删除所有历史纪要并执行清理脚本",
                payload="清理指令",
                parameters={"document": "x"},
            )
        )
        self.assertEqual(verdict.verdict, Verdict.BLOCK)
        self.assertIn("mismatch.intent_conflict", self._codes(verdict))
        finding = next(item for item in verdict.findings if item.code == "mismatch.intent_conflict")
        self.assertEqual(finding.severity.value, "critical")

    def test_unknown_capability_requires_confirmation(self) -> None:
        verdict = self.engine.review(
            request(task_goal="做点事情", target_capability="unknown.capability", payload="x")
        )
        self.assertEqual(verdict.verdict, Verdict.NEEDS_CONFIRMATION)
        self.assertIn("mismatch.unknown_capability", self._codes(verdict))

    def test_semantic_gap_requires_confirmation(self) -> None:
        verdict = self.engine.review(
            request(task_goal="帮我看看这个东西怎么样", payload="这是一段闲聊")
        )
        self.assertIn("mismatch.semantic_gap", self._codes(verdict))
        self.assertEqual(verdict.verdict, Verdict.NEEDS_CONFIRMATION)

    def test_semantic_support_is_recorded(self) -> None:
        verdict = self.engine.review(request())
        self.assertIn("mismatch.keyword_support", self._codes(verdict))
        self.assertEqual(verdict.verdict, Verdict.ALLOW)

    def test_possible_wrong_target_is_flagged(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="把这段中文翻译成英文",
                target_capability="doc.summarize",
                payload="译文内容",
            )
        )
        self.assertIn("mismatch.possible_wrong_target", self._codes(verdict))
        self.assertIn("mismatch.semantic_gap", self._codes(verdict))

    def test_write_capability_accepts_write_intent(self) -> None:
        verdict = self.engine.review(
            request(
                task_goal="创建一条工单并通知值班同学",
                target_capability="ticket.create",
                payload="磁盘告警",
                parameters={"title": "磁盘告警", "detail": "节点 A 使用率 95%"},
                declared_scope=["ticket.create"],
            )
        )
        self.assertEqual(verdict.verdict, Verdict.ALLOW)
        self.assertIn("mismatch.keyword_support", self._codes(verdict))


if __name__ == "__main__":
    unittest.main()
