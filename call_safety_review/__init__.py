"""内容安全预检智能体（wit 2.1.0 / acps-sdk 2.2.0）。

对外入口：

* :func:`review` —— 不依赖模型的直接审查（可嵌入任何调用前路径）；
* :func:`build_review_agent` / :func:`build_runtime` —— wit 智能体装配；
* :class:`PreSendGuardHooks` —— 出站调用闸门。
"""

from __future__ import annotations

from .agent import AGENT_ID, DEFAULT_INSTRUCTIONS, build_engine, build_review_agent, build_runtime
from .catalog import CapabilityCatalog, CapabilityProfile, default_catalog
from .contracts import (
    POLICY_VERSION,
    CallReviewRequest,
    ConfirmationItem,
    Disposition,
    Redaction,
    ReviewVerdict,
    RiskCategory,
    RiskFinding,
    Severity,
    Verdict,
)
from .engine import PolicyConfig, ReviewEngine
from .hooks import PreSendGuardHooks, ReviewAuditHooks
from .integrations import DelegateTaskTool, ProtectedCaller, build_protected_caller

__all__ = [
    "AGENT_ID",
    "POLICY_VERSION",
    "CallReviewRequest",
    "CapabilityCatalog",
    "CapabilityProfile",
    "ConfirmationItem",
    "DelegateTaskTool",
    "Disposition",
    "PolicyConfig",
    "PreSendGuardHooks",
    "ProtectedCaller",
    "Redaction",
    "ReviewAuditHooks",
    "ReviewEngine",
    "ReviewVerdict",
    "RiskCategory",
    "RiskFinding",
    "Severity",
    "Verdict",
    "build_engine",
    "build_protected_caller",
    "build_review_agent",
    "build_runtime",
    "default_catalog",
    "review",
]


def review(request: CallReviewRequest, *, engine: ReviewEngine | None = None) -> ReviewVerdict:
    """对一次待下发调用做审查（无模型依赖的便捷入口）。"""

    return (engine or ReviewEngine()).review(request)
