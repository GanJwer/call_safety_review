"""出站调用闸门：在 ``wrap_tool_call`` 中于调用发出前完成审查与改写。

这是本智能体「做什么」的落点——审查不是事后审计，而是发送前的强制关卡：

* 结论为 ``block`` / ``needs_confirmation`` 时短路，返回结构化错误观察；
* 结论为 ``allow_redacted`` 时用安全载荷替换原始参数后再放行；
* 所有审查记录写入本次 run 的私有状态，并在 run 结束时挂到结果元数据上。
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any, Awaitable, Callable, Mapping, Sequence

from wit import (
    ContextBlock,
    HookContext,
    RunEndEvent,
    StateSlot,
    Tool,
    ToolCall,
    ToolManager,
    WitHooks,
)

from .contracts import CallReviewRequest, Verdict
from .engine import ReviewEngine


class PreSendGuardHooks(WitHooks):
    """对标记为 ``outbound`` 的工具做发送前审查。"""

    id = "safety.pre-send-guard"
    priority = 5

    def __init__(
        self,
        engine: ReviewEngine | None = None,
        *,
        outbound_flag: str = "outbound",
        state_field: str = "call_safety_reviews",
        block_unconfirmed: bool = True,
    ) -> None:
        self.engine = engine or ReviewEngine()
        self.outbound_flag = outbound_flag
        self.state_field = state_field
        self.block_unconfirmed = block_unconfirmed

    # -- 编译期贡献 ------------------------------------------------------
    def state(self, ctx: Any) -> dict[str, StateSlot]:
        return {
            self.state_field: StateSlot(
                default=list,
                description="本次 run 中每次出站调用的发送前审查记录。",
            )
        }

    def context(self, ctx: HookContext) -> list[ContextBlock]:
        reviews = self._reviews(ctx)
        last = reviews[-1]["review"] if reviews else None
        summary = {
            "policy_version": self.engine.policy.policy_version,
            "reviewed_calls": len(reviews),
            "last_verdict": last["verdict"] if last else None,
            "last_review_id": last["review_id"] if last else None,
            "verdicts": ["allow", "allow_redacted", "needs_confirmation", "block"],
        }
        return [
            ContextBlock.state(
                title="调用内容安全审查",
                value=summary,
                trusted=True,
            )
        ]

    # -- 发送前闸门 ------------------------------------------------------
    async def wrap_tool_call(
        self,
        ctx: HookContext,
        tool_call: ToolCall,
        handler: Callable[[ToolCall], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        tool = self._resolve_tool(ctx, tool_call.name)
        if tool is None or not bool(tool.metadata.get(self.outbound_flag)):
            return await handler(tool_call)

        started = time.perf_counter()
        request = CallReviewRequest.from_arguments(tool_call.arguments)
        verdict = self.engine.review(request)
        record = {
            "tool": tool.name,
            "model_tool_name": tool_call.name,
            "review": verdict.to_dict(),
        }
        self._reviews(ctx).append(record)

        if verdict.verdict is Verdict.BLOCK:
            return self._short_circuit(
                tool_call,
                tool,
                code="call_blocked_by_content_review",
                message="调用前内容安全审查结论为 block，载荷未下发。",
                verdict=record["review"],
                started=started,
            )
        if verdict.verdict is Verdict.NEEDS_CONFIRMATION and self.block_unconfirmed:
            return self._short_circuit(
                tool_call,
                tool,
                code="call_requires_confirmation",
                message="调用前内容安全审查结论为 needs_confirmation，需先完成确认项。",
                verdict=record["review"],
                started=started,
            )

        safe_arguments = verdict.forward_arguments(tool_call.arguments)
        if self._declares_field(tool, "safety_review_id"):
            safe_arguments["safety_review_id"] = verdict.review_id
        record["dispatched_verdict"] = verdict.verdict.value
        return await handler(replace(tool_call, arguments=safe_arguments))

    async def on_run_end(self, event: RunEndEvent) -> None:
        reviews = self._reviews(event.context)
        if not reviews:
            return
        event.result = replace(
            event.result,
            metadata={
                **event.result.metadata,
                self.state_field: list(reviews),
                "call_safety_summary": {
                    "reviewed_calls": len(reviews),
                    "verdicts": [item["review"]["verdict"] for item in reviews],
                },
            },
        )

    # -- 辅助 ------------------------------------------------------------
    def _reviews(self, ctx: HookContext) -> list[dict[str, Any]]:
        bucket = ctx.private_state.get(self.state_field)
        if not isinstance(bucket, list):
            bucket = []
            ctx.private_state[self.state_field] = bucket
        return bucket

    def _resolve_tool(self, ctx: HookContext, name: str) -> Tool | None:
        tools = self._tool_map(ctx)
        tool = tools.get(name)
        if tool is not None:
            return tool
        for candidate in tools.values():
            if ToolManager.safe_model_tool_name(candidate.name) == name:
                return candidate
        return None

    @staticmethod
    def _tool_map(ctx: HookContext) -> Mapping[str, Tool]:
        lookup = getattr(ctx.tool_manager, "lookup", None)
        if callable(lookup):
            return lookup()
        tools = getattr(ctx.tool_manager, "tools", ())
        return {tool.name: tool for tool in tools}

    @staticmethod
    def _declares_field(tool: Tool, field: str) -> bool:
        schema = tool.input_schema or {}
        properties = schema.get("properties") if isinstance(schema, Mapping) else None
        return bool(properties) and field in properties  # type: ignore[operator]

    @staticmethod
    def _short_circuit(
        tool_call: ToolCall,
        tool: Tool,
        *,
        code: str,
        message: str,
        verdict: Mapping[str, Any],
        started: float,
    ) -> dict[str, Any]:
        """短路仍返回符合工具 observation 约定的 dict。"""

        return {
            "toolCallId": tool_call.id,
            "tool": tool.name,
            "capabilityId": tool.capability_id or tool.name,
            "modelToolName": ToolManager.safe_model_tool_name(tool.name),
            "status": "error",
            "result": None,
            "error": {
                "type": "CallSafetyReviewError",
                "code": code,
                "message": message,
                "details": dict(verdict),
            },
            "durationMs": int((time.perf_counter() - started) * 1000),
            "metadata": {"source": "safety.pre-send-guard", "gate": "pre-send"},
        }


class ReviewAuditHooks(WitHooks):
    """把审查结论镜像到 run 元数据，便于调用链观测（不做任何外部写入）。"""

    id = "safety.review-audit"
    priority = 60

    def __init__(self, *, state_field: str = "call_safety_reviews") -> None:
        self.state_field = state_field

    async def on_run_end(self, event: RunEndEvent) -> None:
        reviews: Sequence[Mapping[str, Any]] = event.context.private_state.get(self.state_field) or ()
        if not reviews:
            return
        codes = sorted(
            {
                finding["code"]
                for item in reviews
                for finding in item.get("review", {}).get("risk_reasons", [])
                if finding.get("severity") in {"high", "critical"}
            }
        )
        event.result = replace(
            event.result,
            metadata={
                **event.result.metadata,
                "call_safety_high_risk_codes": codes,
            },
        )
