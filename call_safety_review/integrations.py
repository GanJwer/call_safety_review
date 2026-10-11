"""把审查闸门接到真实调用路径：出站委派工具 + 受保护的调用方智能体。

生产环境中「调用」通常由 ACPs 的 AIP 委派工具承载（``AipDelegationHooks``）。
本模块用一个同形态的示例工具演示闸门如何工作：只要工具声明
``metadata={"outbound": True}``，:class:`~call_safety_review.hooks.PreSendGuardHooks`
就会在它发出前完成审查与改写。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from .engine import ReviewEngine
from .hooks import PreSendGuardHooks

DELEGATE_TASK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_agent": {"type": "string", "description": "被委派的智能体标识（如 AIC）。"},
        "target_capability": {"type": "string", "description": "被委派的能力 id。"},
        "task_goal": {"type": "string", "description": "任务目标。"},
        "payload": {"type": "string", "description": "随任务下发的文本。"},
        "parameters": {"type": "object", "description": "随任务下发的结构化参数。"},
        "declared_scope": {"type": "array", "items": {"type": "string"}},
        "data_classification": {
            "type": "string",
            "enum": ["public", "internal", "confidential", "restricted"],
        },
        "confirmations": {"type": "array", "items": {"type": "string"}},
        "safety_review_id": {
            "type": "string",
            "description": "由发送前审查闸门回填的审查编号，用于调用链溯源。",
        },
    },
    "required": ["target_agent", "target_capability", "task_goal"],
    "additionalProperties": False,
}

DelegateHandler = Callable[[Mapping[str, Any], Any], Awaitable[dict[str, Any]] | dict[str, Any]]


@dataclass
class DelegateTaskTool:
    """示例出站委派工具；``dispatched`` 保留真正被下发出去的安全载荷。"""

    tool: Any
    dispatched: list[dict[str, Any]] = field(default_factory=list)
    handler: DelegateHandler | None = None

    def build(self, handler: DelegateHandler | None = None) -> Any:
        from wit import Tool

        async def default_handler(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
            self.dispatched.append(dict(arguments))
            return {
                "status": "dispatched",
                "target_agent": arguments.get("target_agent"),
                "target_capability": arguments.get("target_capability"),
                "safety_review_id": arguments.get("safety_review_id"),
            }

        self.handler = handler or default_handler
        self.tool = Tool(
            name="agent.delegate_task",
            description=(
                "把任务与载荷委派给下游智能体执行。该工具属于出站调用，"
                "会在发送前经过内容安全审查。"
            ),
            input_schema=DELEGATE_TASK_SCHEMA,
            handler=self.handler,
            capability_id="agent.delegate_task",
            source="integration",
            metadata={"outbound": True},
        )
        return self.tool


def build_protected_caller(
    *,
    model: Any,
    engine: ReviewEngine | None = None,
    instructions: str | None = None,
    delegate: DelegateTaskTool | None = None,
    workspace: str | Path | None = None,
) -> ProtectedCaller:
    """构造一个「出站调用必须过审查」的调用方智能体。

    通过 :meth:`ProtectedCaller.run` 发起对话即可观察：
    阻断 / 待确认的调用不会到达 handler，脱敏后的调用以安全载荷下发。
    """

    from wit import WitAgent

    engine = engine or ReviewEngine()
    delegate = delegate or DelegateTaskTool(tool=None)
    tool = delegate.build()
    agent = WitAgent(
        id="protected-caller",
        instructions=instructions
        or (
            "你是任务编排智能体。需要跨智能体协作时调用 agent_delegate_task。"
            "如果调用被安全审查阻断或要求确认，不要改写参数绕过，改为向用户说明风险与确认项。"
        ),
        model=model,
        hooks=[PreSendGuardHooks(engine)],
    )
    return ProtectedCaller(agent=agent, delegate=delegate, workspace=workspace)


@dataclass
class ProtectedCaller:
    """调用方智能体 + 出站委派工具 + 运行时便捷封装。"""

    agent: Any
    delegate: DelegateTaskTool
    workspace: str | Path | None = None

    def runtime(self) -> Any:
        from wit import WitRuntime

        return WitRuntime(self.agent, workspace=self.workspace)

    async def run(self, prompt: str) -> Any:
        """跑一次对话，并把出站委派工具注入本次 run。"""

        from wit import RunConfig

        runtime = self.runtime()
        return await runtime.run(prompt, RunConfig(tools=[self.delegate.tool]))
