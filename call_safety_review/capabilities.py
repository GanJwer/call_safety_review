"""把审查引擎投影为模型可调用、可经 ACPs 暴露的能力（Capability）。"""

from __future__ import annotations

from typing import Any, Mapping

from .catalog import CapabilityCatalog
from .contracts import CallReviewRequest
from .engine import ReviewEngine

CALL_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task_goal": {"type": "string", "description": "调用方希望被调用智能体完成的任务目标。"},
        "target_capability": {"type": "string", "description": "被调用的能力 id，例如 doc.summarize。"},
        "target_agent": {"type": "string", "description": "被调用智能体的标识（如 AIC）。"},
        "payload": {"type": "string", "description": "待传递给下游的文本内容。"},
        "parameters": {"type": "object", "description": "待传递给下游的结构化参数。"},
        "caller_id": {"type": "string", "description": "发起调用的智能体标识。"},
        "caller_capabilities": {"type": "array", "items": {"type": "string"}},
        "declared_scope": {
            "type": "array",
            "items": {"type": "string"},
            "description": "调用方声明本次任务被授权的能力范围。",
        },
        "data_classification": {
            "type": "string",
            "enum": ["public", "internal", "confidential", "restricted"],
            "description": "本次载荷的数据分级，默认 internal。",
        },
        "confirmations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "上游已获得的确认项 id（如 confirm:scope.cross_tenant）。",
        },
        "allow_rewrite": {
            "type": "boolean",
            "description": "是否允许引擎重写为最小化披露的安全载荷，默认 true。",
        },
    },
    "required": ["task_goal", "target_capability"],
    "additionalProperties": False,
}

TEXT_SCAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {"type": "string", "description": "待扫描的文本。"},
        "field_path": {
            "type": "string",
            "description": "该文本在调用载荷中的字段路径，默认 payload。",
        },
    },
    "required": ["text"],
    "additionalProperties": False,
}

REWRITE_SCHEMA: dict[str, Any] = dict(CALL_REVIEW_SCHEMA)

REVIEW_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "review_id": {"type": "string"},
        "verdict": {
            "type": "string",
            "enum": ["allow", "allow_redacted", "needs_confirmation", "block"],
        },
        "risk_reasons": {"type": "array", "items": {"type": "object"}},
        "required_confirmations": {"type": "array", "items": {"type": "object"}},
        "safe_task_text": {"type": "string"},
        "safe_parameters": {"type": "object"},
        "safe_call": {"type": "object"},
    },
    "required": ["review_id", "verdict"],
}


def build_capabilities(
    engine: ReviewEngine,
    *,
    expose_over_acps: bool = True,
    tags: tuple[str, ...] = ("content-safety", "call-review", "risk-assessment"),
) -> list[Any]:
    """构造审查智能体的能力集合。

    ``safety.review_call`` 是主能力，也是经 ACPs 对外公开的技能；
    其余能力用于取证与重写，便于模型分步解释结论。
    """

    from wit import Capability

    async def review_call(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        request = CallReviewRequest.from_arguments(arguments)
        return engine.review(request).to_dict()

    async def scan_injection(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        text = str(arguments.get("text") or "")
        path = str(arguments.get("field_path") or "payload")
        findings = engine.scan_injection(text, field_path=path)
        plan = engine.rewrite(
            CallReviewRequest(
                task_goal="",
                target_capability="",
                payload=text,
                allow_rewrite=True,
            )
        )
        return {
            "findings": [item.to_dict() for item in findings],
            "neutralized_text": plan["safe_payload"],
            "matched_rules": sorted({item.code for item in findings}),
        }

    async def scan_sensitive(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        text = str(arguments.get("text") or "")
        path = str(arguments.get("field_path") or "payload")
        findings = engine.scan_sensitive(text, field_path=path)
        plan = engine.rewrite(
            CallReviewRequest(task_goal="", target_capability="", payload=text)
        )
        return {
            "findings": [item.to_dict() for item in findings],
            "redacted_text": plan["safe_payload"],
            "redactions": plan["redactions"],
            "matched_rules": sorted({item.code for item in findings}),
        }

    async def check_scope(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        request = CallReviewRequest.from_arguments(arguments)
        findings = engine.check_scope(request)
        fit = engine.check_capability_fit(request)
        profile = engine.catalog.get(request.target_capability)
        return {
            "scope_findings": [item.to_dict() for item in findings],
            "capability_findings": [item.to_dict() for item in fit],
            "capability_profile": profile.to_dict() if profile else None,
        }

    async def rewrite_payload(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        request = CallReviewRequest.from_arguments(arguments)
        request.allow_rewrite = True
        return engine.rewrite(request)

    async def policy_info(arguments: Mapping[str, Any], runtime: Any) -> dict[str, Any]:
        return {
            "policy": engine.policy.to_dict(),
            "verdicts": ["allow", "allow_redacted", "needs_confirmation", "block"],
            "risk_categories": [
                "prompt_injection",
                "unauthorized_request",
                "task_capability_mismatch",
                "over_disclosure",
            ],
            "confirmation_ids": sorted(
                {
                    f"confirm:{rule.code}"
                    for rule in _all_rules()
                    if rule.disposition.value == "confirm"
                }
            ),
            "capability_catalog": [item.to_dict() for item in engine.catalog.profiles()],
        }

    capabilities = [
        Capability.tool(
            id="safety.review_call",
            description=(
                "发起外部调用前，对任务、参数和待传递内容进行安全检查，"
                "识别潜在风险，并返回审查结论和安全处理建议。"
            ),
            handler=review_call,
            input_schema=CALL_REVIEW_SCHEMA,
            output_schema=REVIEW_OUTPUT_SCHEMA,
            public=expose_over_acps,
            model_callable=True,
            acps_skill=expose_over_acps,
            version="1.0.0",
            tags=list(tags),
            examples=["检查一次外部调用是否存在安全风险"],
        ),
        Capability.tool(
            id="safety.scan_injection",
            description="扫描一段文本中的提示注入特征（指令覆盖、提示词窃取、身份改写、编码载荷等）。",
            handler=scan_injection,
            input_schema=TEXT_SCAN_SCHEMA,
            tags=list(tags),
        ),
        Capability.tool(
            id="safety.scan_sensitive",
            description="扫描一段文本中的敏感信息（凭据、个人信息、内网资产、密级标记）并给出脱敏结果。",
            handler=scan_sensitive,
            input_schema=TEXT_SCAN_SCHEMA,
            tags=list(tags),
        ),
        Capability.tool(
            id="safety.check_scope",
            description="校验任务意图是否越权、目标能力是否与任务语义匹配。",
            handler=check_scope,
            input_schema=CALL_REVIEW_SCHEMA,
            tags=list(tags),
        ),
        Capability.tool(
            id="safety.rewrite_payload",
            description="按最小化披露重写载荷：脱敏敏感信息、剔除无关参数与无关片段、围栏化不可信数据。",
            handler=rewrite_payload,
            input_schema=REWRITE_SCHEMA,
            tags=list(tags),
        ),
        Capability.tool(
            id="safety.policy_info",
            description="返回当前审查策略版本、风险类别、结论取值与能力目录。",
            handler=policy_info,
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            tags=list(tags),
        ),
    ]
    return capabilities


def _all_rules() -> tuple[Any, ...]:
    from .patterns import INJECTION_RULES, SCOPE_RULES, SENSITIVE_RULES

    return (*INJECTION_RULES, *SCOPE_RULES, *SENSITIVE_RULES)


def catalog_document(catalog: CapabilityCatalog) -> dict[str, Any]:
    """把能力目录导出为可下发给模型 / 调用方的字典。"""

    return {"profiles": [profile.to_dict() for profile in catalog.profiles()]}
