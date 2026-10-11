"""测试公共设施：脚本化 Provider 与便捷构造。"""

from __future__ import annotations

from typing import Any

from wit import ModelRequest, ModelResponse

from call_safety_review import CallReviewRequest, ReviewEngine


class ScriptedModel:
    """按脚本返回响应的确定性 Provider（手册推荐的 Agent 循环测试方式）。"""

    model = "scripted"

    def __init__(self, *responses: ModelResponse) -> None:
        self.responses = list(responses)
        self.requests: list[ModelRequest] = []
        self.tool_names: list[list[str]] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        self.tool_names.append([getattr(tool, "name", "") for tool in request.tools])
        if not self.responses:
            raise AssertionError("model received more steps than scripted")
        return self.responses.pop(0)


def engine() -> ReviewEngine:
    from call_safety_review import default_catalog

    return ReviewEngine(catalog=default_catalog())


def request(**overrides: Any) -> CallReviewRequest:
    base: dict[str, Any] = {
        "task_goal": "把这份周报总结成要点",
        "target_capability": "doc.summarize",
        "target_agent": "partner.summarizer",
        "payload": "本周完成了接口联调与回归测试。",
        "parameters": {"document": "本周完成了接口联调与回归测试。"},
        "declared_scope": ["doc.summarize"],
    }
    base.update(overrides)
    return CallReviewRequest(**base)
