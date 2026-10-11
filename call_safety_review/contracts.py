"""调用内容安全审查的数据契约。

这些 dataclass 定义「审查什么、判定什么、下发什么」三个边界：

* :class:`CallReviewRequest` —— 一次出站调用的任务目标、参数与待传递文本；
* :class:`RiskFinding` —— 单条风险发现（类别 / 严重度 / 处置 / 证据）；
* :class:`ReviewVerdict` —— 允许 / 脱敏后允许 / 需要确认 / 阻断的结论，
  以及风险原因、必要确认项、可继续下发的安全任务文本与参数。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

POLICY_VERSION = "csr-1.0"


class Verdict(str, Enum):
    """审查结论。取值顺序即严重度顺序，便于聚合比较。"""

    ALLOW = "allow"
    ALLOW_REDACTED = "allow_redacted"
    NEEDS_CONFIRMATION = "needs_confirmation"
    BLOCK = "block"


class RiskCategory(str, Enum):
    """平台缺口对应的四类载荷层风险，外加一个可用性兜底类别。"""

    PROMPT_INJECTION = "prompt_injection"
    UNAUTHORIZED_REQUEST = "unauthorized_request"
    CAPABILITY_MISMATCH = "task_capability_mismatch"
    OVER_DISCLOSURE = "over_disclosure"
    REVIEW_AVAILABILITY = "review_availability"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Disposition(str, Enum):
    """单条发现建议的处置动作，聚合后映射为 :class:`Verdict`。"""

    ALLOW = "allow"
    REDACT = "redact"
    CONFIRM = "confirm"
    BLOCK = "block"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CLASSIFICATION_ORDER: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


@dataclass(frozen=True, slots=True)
class RiskFinding:
    """单条风险发现。``code`` 是稳定的规则标识，便于告警与回归断言。"""

    category: RiskCategory
    code: str
    severity: Severity
    disposition: Disposition
    message: str
    field_path: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    confirmation_id: str | None = None
    resolved_by: str | None = None

    @property
    def effective_disposition(self) -> Disposition:
        """已被上游确认的发现降级为 allow。"""

        return Disposition.ALLOW if self.resolved_by else self.disposition

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        data["disposition"] = self.disposition.value
        data["effective_disposition"] = self.effective_disposition.value
        return data


@dataclass(frozen=True, slots=True)
class ConfirmationItem:
    """必要确认项：下发前需要人工（或上游策略）明确回答的问题。"""

    id: str
    question: str
    code: str
    severity: Severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "code": self.code,
            "severity": self.severity.value,
        }


@dataclass(frozen=True, slots=True)
class Redaction:
    """一处脱敏 / 裁剪记录，用于审计「改了什么」。"""

    field_path: str
    rule: str
    kind: str
    replacement: str
    preview: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CallReviewRequest:
    """一次待下发调用的载荷。所有字段都可从模型工具参数直接构造。"""

    task_goal: str
    target_capability: str
    payload: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    caller_id: str = ""
    caller_capabilities: list[str] = field(default_factory=list)
    target_agent: str = ""
    declared_scope: list[str] = field(default_factory=list)
    data_classification: str = "internal"
    confirmations: list[str] = field(default_factory=list)
    allow_rewrite: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> CallReviewRequest:
        """从工具参数构造；忽略未知键，缺失键用默认值，保证审查本身不会因载荷缺字段而失败。"""

        def _str(key: str, default: str = "") -> str:
            value = arguments.get(key, default)
            return default if value is None else str(value)

        def _list(key: str) -> list[str]:
            value = arguments.get(key) or []
            if isinstance(value, str):
                return [item.strip() for item in value.split(",") if item.strip()]
            return [str(item) for item in value]

        parameters = arguments.get("parameters") or {}
        if not isinstance(parameters, Mapping):
            parameters = {"value": parameters}

        return cls(
            task_goal=_str("task_goal"),
            target_capability=_str("target_capability"),
            payload=_str("payload"),
            parameters=dict(parameters),
            caller_id=_str("caller_id"),
            caller_capabilities=_list("caller_capabilities"),
            target_agent=_str("target_agent"),
            declared_scope=_list("declared_scope"),
            data_classification=_str("data_classification", "internal") or "internal",
            confirmations=_list("confirmations"),
            allow_rewrite=bool(arguments.get("allow_rewrite", True)),
            metadata=dict(arguments.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReviewVerdict:
    """审查结论及其证据、确认项与安全载荷。"""

    review_id: str
    verdict: Verdict
    findings: list[RiskFinding] = field(default_factory=list)
    required_confirmations: list[ConfirmationItem] = field(default_factory=list)
    redactions: list[Redaction] = field(default_factory=list)
    dropped_fields: list[str] = field(default_factory=list)
    safe_task_goal: str = ""
    safe_payload: str = ""
    safe_task_text: str = ""
    safe_parameters: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    category_decisions: dict[str, str] = field(default_factory=dict)
    target_capability: str = ""
    target_agent: str = ""
    policy_version: str = POLICY_VERSION
    error: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.ALLOW_REDACTED)

    def forward_arguments(self, original: Mapping[str, Any]) -> dict[str, Any]:
        """以原始参数键集合为准，替换为安全值。

        只覆盖原载荷中已存在的键，避免给下游工具引入 schema 之外的新字段
        （``additionalProperties: false`` 的工具会把未知字段判为参数错误）。
        """

        safe = dict(original)
        if "task_goal" in safe:
            safe["task_goal"] = self.safe_task_goal or self.safe_task_text
        if "payload" in safe:
            safe["payload"] = self.safe_payload
        if "parameters" in safe:
            safe["parameters"] = self.safe_parameters
        return safe

    def to_forward_frame(self) -> dict[str, Any]:
        """可继续下发的安全调用骨架（智能体 / 能力 / 任务文本 / 参数）。"""

        return {
            "target_agent": self.target_agent,
            "target_capability": self.target_capability,
            "task_text": self.safe_task_text,
            "parameters": self.safe_parameters,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "verdict": self.verdict.value,
            "target_agent": self.target_agent,
            "target_capability": self.target_capability,
            "risk_reasons": [item.to_dict() for item in self.findings],
            "category_decisions": dict(self.category_decisions),
            "required_confirmations": [item.to_dict() for item in self.required_confirmations],
            "redactions": [item.to_dict() for item in self.redactions],
            "dropped_fields": list(self.dropped_fields),
            "safe_task_goal": self.safe_task_goal,
            "safe_payload": self.safe_payload,
            "safe_task_text": self.safe_task_text,
            "safe_parameters": self.safe_parameters,
            "safe_call": self.to_forward_frame(),
            "notes": list(self.notes),
            "policy_version": self.policy_version,
            "error": self.error,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def summarize_findings(findings: Sequence[RiskFinding]) -> dict[str, str]:
    """把发现集合归并成「每类风险的最终处置」。"""

    rank = {
        Disposition.ALLOW: 0,
        Disposition.REDACT: 1,
        Disposition.CONFIRM: 2,
        Disposition.BLOCK: 3,
    }
    decisions: dict[str, str] = {}
    for finding in findings:
        category = finding.category.value
        current = decisions.get(category)
        action = finding.effective_disposition.value
        if current is None or rank[Disposition(action)] > rank[Disposition(current)]:
            decisions[category] = action
    return decisions
