"""载荷层风险的规则库：提示注入、越权请求、敏感信息与意图词表。

规则只负责「发现 + 分级 + 建议处置」，判决聚合在 :mod:`engine` 中完成，
这样单条规则可以独立测试与回归。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .contracts import Disposition, RiskCategory, Severity


@dataclass(frozen=True, slots=True)
class PatternRule:
    """一条可解释的检测规则。"""

    code: str
    category: RiskCategory
    severity: Severity
    disposition: Disposition
    message: str
    pattern: re.Pattern[str]
    redact_kind: str | None = None
    confirmation: str | None = None
    max_findings_per_field: int = 2


def _rule(
    code: str,
    category: RiskCategory,
    severity: Severity,
    disposition: Disposition,
    message: str,
    pattern: str,
    *,
    redact_kind: str | None = None,
    confirmation: str | None = None,
    flags: int = re.IGNORECASE,
    max_findings_per_field: int = 2,
) -> PatternRule:
    return PatternRule(
        code=code,
        category=category,
        severity=severity,
        disposition=disposition,
        message=message,
        pattern=re.compile(pattern, flags),
        redact_kind=redact_kind,
        confirmation=confirmation,
        max_findings_per_field=max_findings_per_field,
    )


# --------------------------------------------------------------------------
# 1. 提示注入：试图改写下游智能体的指令、身份、安全策略，或隐式夹带指令。
# --------------------------------------------------------------------------
INJECTION_RULES: tuple[PatternRule, ...] = (
    _rule(
        "injection.instruction_override",
        RiskCategory.PROMPT_INJECTION,
        Severity.CRITICAL,
        Disposition.BLOCK,
        "载荷包含覆盖下游指令的语句（如「忽略上面所有指令」），属于典型提示注入。",
        r"(?:忽略|无视|忘掉|忘记|略过|跳过|抛开|不要遵守|不必遵守)[^。！？!?\n]{0,10}"
        r"(?:上述|上面|以上|之前|此前|前面|所有|全部|既定)?[^。！？!?\n]{0,8}"
        r"(?:指令|提示|规则|约束|要求|设定|策略)"
        r"|(?:ignore|disregard|forget|override|bypass|discard)\s+(?:all\s+|any\s+)?"
        r"(?:previous|prior|above|earlier|these|the)\s+"
        r"(?:instruction|prompt|rule|guideline|constraint|direction)s?",
    ),
    _rule(
        "injection.system_prompt_exfil",
        RiskCategory.PROMPT_INJECTION,
        Severity.CRITICAL,
        Disposition.BLOCK,
        "载荷试图诱导下游智能体泄露系统提示词或隐藏指令。",
        r"(?:输出|打印|复述|重复|泄露|泄漏|展示|告诉我|贴出|dump|reveal|print|repeat|show|leak)"
        r"[^。！？!?\n]{0,12}"
        r"(?:系统提示词?|系统指令|初始提示|开发者消息|隐藏指令|你的提示词|你的设定|"
        r"system\s*prompt|your\s+(?:system\s+)?(?:instructions?|prompt)|initial\s+prompt)",
    ),
    _rule(
        "injection.policy_disable",
        RiskCategory.PROMPT_INJECTION,
        Severity.CRITICAL,
        Disposition.BLOCK,
        "载荷要求关闭或绕过安全审查、内容过滤或审计，属于对安全控制面的攻击。",
        r"(?:关闭|禁用|绕过|跳过|移除|停用|不要|无需)[^。！？!?\n]{0,8}"
        r"(?:安全审查|内容审查|安全策略|安全过滤|安全校验|风控|护栏|"
        r"safety|moderation|guardrail|filter)"
        r"|(?:disable|bypass|turn\s+off|skip|without|no)\s+"
        r"(?:the\s+)?(?:safety|security|content|moderation|guardrail|filter)"
        r"(?:\s+checks?|\s+filters?|\s+rules?|\s+logging)?",
    ),
    _rule(
        "injection.exfil_instruction",
        RiskCategory.PROMPT_INJECTION,
        Severity.CRITICAL,
        Disposition.BLOCK,
        "载荷要求把内容外发到外部地址或第三方，具有数据外带特征。",
        r"(?:把|将|请把|并将)[^。！？!?\n]{0,24}"
        r"(?:发送|转发|上传|回传|外发|投递|send|forward|upload|post)"
        r"[^。！？!?\n]{0,24}"
        r"(?:外部|第三方|公网|邮箱|云端|网盘|http|@|external|third[-\s]?party)",
    ),
    _rule(
        "injection.identity_override",
        RiskCategory.PROMPT_INJECTION,
        Severity.HIGH,
        Disposition.REDACT,
        "载荷试图重设下游智能体的身份或角色，改写后可保留业务语义但需去除该语句。",
        r"(?:你现在是|从现在开始你是|从现在起你是|你不再是|你的新身份是|"
        r"you\s+are\s+now|from\s+now\s+on\s+you\s+are|your\s+new\s+(?:identity|role)\s+is)",
        redact_kind="INJECTION",
    ),
    _rule(
        "injection.jailbreak",
        RiskCategory.PROMPT_INJECTION,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷出现越狱 / 无限制模式等关键词，需确认是否为正常业务内容。",
        r"jailbreak|越狱|开发者模式|developer\s+mode|\bDAN\b|"
        r"不受(?:任何)?限制|无(?:任何)?限制|解除(?:所有)?限制",
        confirmation="载荷中出现越狱 / 无限制模式关键词，请确认这是否为业务必需内容。",
    ),
    _rule(
        "injection.tool_smuggling",
        RiskCategory.PROMPT_INJECTION,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷诱导下游执行命令、下载或访问外部资源，可能形成工具滥用链。",
        r"(?:访问|打开|请求|下载|抓取|执行|运行|安装|调用|fetch|visit|open|download|execute|run|install|curl|wget)"
        r"[^。！？!?\n]{0,16}"
        r"(?:https?://|www\.|命令|脚本|shell|bash|cmd|powershell|python\s+-c|npm\s+install|pip\s+install)",
        confirmation="载荷要求下游智能体执行命令或访问外部地址，请确认该动作在授权范围内。",
    ),
    _rule(
        "injection.delimiter_breakout",
        RiskCategory.PROMPT_INJECTION,
        Severity.HIGH,
        Disposition.REDACT,
        "载荷包含对话模板分隔符或角色标记，可能突破消息边界。",
        r"<\|?\s*(?:im_start|im_end|system|assistant|user|endoftext)\s*\|?>"
        r"|\[/?INST\]"
        r"|</?(?:system|assistant|developer|tool)>"
        r"|#{3,}\s*(?:system|指令|instructions?)",
        redact_kind="INJECTION",
    ),
    _rule(
        "injection.encoded_payload",
        RiskCategory.PROMPT_INJECTION,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷包含长编码块（Base64 / Hex），可能隐藏指令或外带内容。",
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])"
        r"|(?<![0-9A-Fa-f])[0-9A-Fa-f]{80,}(?![0-9A-Fa-f])",
        redact_kind="ENCODED_BLOB",
        max_findings_per_field=1,
    ),
)


# --------------------------------------------------------------------------
# 2. 越权请求：超出声明范围的动作、凭据索取、跨租户、审计规避等。
# --------------------------------------------------------------------------
SCOPE_RULES: tuple[PatternRule, ...] = (
    _rule(
        "scope.credential_request",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.CRITICAL,
        Disposition.CONFIRM,
        "载荷索取密码 / 密钥 / 凭据，属于凭据类越权请求。",
        r"(?:提供|给出|发给我|发送|返回|导出|提交|告知|send|provide|give|return|export|share)"
        r"[^。！？!?\n]{0,10}"
        r"(?:密码|口令|密钥|私钥|凭据|凭证|令牌|token|api[_-]?key|secret|credential|private\s+key)"
        r"|(?:密码|口令|密钥|私钥|凭据|凭证|令牌|token|api[_-]?key|secret|credential)"
        r"[^。！？!?\n]{0,12}"
        r"(?:提供|给出|发给我|发送|返回|导出|提交|告知|发来|给我|send|provide|give|return|export|share)",
        confirmation="载荷向下游索取密码 / 密钥 / 凭据，请确认是否为已授权的必要动作。",
    ),
    _rule(
        "scope.privilege_escalation",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.CRITICAL,
        Disposition.CONFIRM,
        "载荷要求提权或绕过鉴权，属于越权请求。",
        r"提权|越权|以管理员(?:身份)?" r"|管理员权限|超级用户|root\s*权限|最高权限|"
        r"绕过(?:鉴权|认证|登录|权限|审批|风控)|跳过(?:鉴权|认证|登录|审批)|"
        r"(?:elevate|escalate)\s+privilege|sudo\s+|bypass\s+(?:auth|login|permission)|"
        r"disable\s+(?:auth|authentication)|skip\s+approval",
        confirmation="载荷要求提权或绕过鉴权，请确认目标能力与授权边界是否允许该动作。",
    ),
    _rule(
        "scope.cross_tenant",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷涉及其他用户 / 其他租户的数据，可能超出数据边界。",
        r"其他用户|别的用户|他人|其他租户|跨租户|其他部门|其他公司|其他客户|"
        r"所有用户|全量用户|other\s+users?|another\s+tenant|cross[-\s]?tenant|"
        r"all\s+users|every\s+customer",
        confirmation="载荷涉及其他用户 / 租户的数据访问，请确认数据边界与授权依据。",
    ),
    _rule(
        "scope.audit_disable",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷要求关闭审计或删除日志，属于规避留痕。",
        r"(?:关闭|禁用|删除|清空|清除|不要|跳过)[^。！？!?\n]{0,6}"
        r"(?:审计|日志|记录|留痕|告警|logging|audit|logs?|trace)"
        r"|(?:disable|delete|clear|erase|without|no)\s+(?:the\s+)?(?:audit|logs?|logging|traces?)",
        confirmation="载荷要求关闭审计或删除日志，请确认是否具备合规依据。",
    ),
    _rule(
        "scope.destructive_write",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷包含破坏性写操作（删除 / 清空 / 格式化 / 覆盖）。",
        r"删除|清空|格式化|覆盖全部|drop\s+table|truncate\s+table|rm\s+-rf|"
        r"delete\s+all|wipe\s+(?:all|out)|purge\s+all",
        confirmation="载荷包含破坏性写操作，请确认影响范围与回滚方案。",
    ),
    _rule(
        "scope.external_transfer",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷要求把数据外发到外部系统，需确认数据出境 / 外发授权。",
        r"(?:外发|导出到|上传到|同步到|发送到)[^。！？!?\n]{0,12}"
        r"(?:外部|第三方|公网|邮箱|云端|对象存储|oss|s3|drive|外部系统|external|third[-\s]?party)",
        confirmation="载荷要求把数据外发到外部系统，请确认外发授权与合规要求。",
    ),
    _rule(
        "scope.mass_change",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.MEDIUM,
        Disposition.CONFIRM,
        "载荷涉及批量 / 全量变更，影响面超出单次调用惯例。",
        r"批量(?:修改|更新|删除|写入)|全量(?:更新|覆盖|修改|替换)|"
        r"对(?:所有|全部|全量)[^。！？!?\n]{0,8}(?:执行|修改|更新|删除)|"
        r"mass\s+(?:update|delete)|bulk\s+(?:update|delete)",
        confirmation="载荷涉及批量 / 全量变更，请确认影响面与审批记录。",
    ),
    _rule(
        "scope.persist_instruction",
        RiskCategory.UNAUTHORIZED_REQUEST,
        Severity.MEDIUM,
        Disposition.CONFIRM,
        "载荷要求下游长期保存规则或记忆，可能造成持续越权。",
        r"永久(?:记住|保存|生效)|写入(?:长期)?记忆|长期记住|下次(?:也要|同样)|"
        r"always\s+remember|persist\s+this\s+(?:rule|instruction)",
        confirmation="载荷要求下游长期保存规则 / 记忆，请确认是否属于预期行为。",
    ),
)


# --------------------------------------------------------------------------
# 3. 敏感信息：凭据、个人信息、内部资产与密级标记。
# --------------------------------------------------------------------------
SENSITIVE_RULES: tuple[PatternRule, ...] = (
    _rule(
        "sensitive.private_key",
        RiskCategory.OVER_DISCLOSURE,
        Severity.CRITICAL,
        Disposition.CONFIRM,
        "载荷包含私钥材料，属于高敏感凭据。",
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----",
        redact_kind="PRIVATE_KEY",
        confirmation="载荷包含私钥材料，请确认是否必须下发；建议改为密钥句柄或引用。",
        max_findings_per_field=1,
    ),
    _rule(
        "sensitive.api_key",
        RiskCategory.OVER_DISCLOSURE,
        Severity.CRITICAL,
        Disposition.CONFIRM,
        "载荷包含 API Key / 云厂商访问密钥等长期凭据。",
        r"\bsk-[A-Za-z0-9_\-]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b",
        redact_kind="API_KEY",
        confirmation="载荷包含 API Key / 云访问密钥，请确认是否必须下发；建议改用短期凭据或密钥引用。",
        max_findings_per_field=2,
    ),
    _rule(
        "sensitive.token",
        RiskCategory.OVER_DISCLOSURE,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷包含访问令牌（JWT / Bearer / 平台 token）。",
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"
        r"|\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"
        r"|\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        redact_kind="TOKEN",
        confirmation="载荷包含访问令牌，请确认令牌的必要性与有效期。",
    ),
    _rule(
        "sensitive.assigned_secret",
        RiskCategory.OVER_DISCLOSURE,
        Severity.HIGH,
        Disposition.CONFIRM,
        "载荷以键值形式携带密码 / 密钥赋值。",
        r"(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|client[_-]?secret)"
        r"\s*[:=：]\s*['\"]?[^\s'\",;，。]{6,}",
        redact_kind="SECRET",
        confirmation="载荷以键值形式携带密码 / 密钥，请确认是否必须下发。",
    ),
    _rule(
        "sensitive.cn_id",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷包含身份证号等强个人标识。",
        r"(?<!\d)\d{17}[\dXx](?!\d)",
        redact_kind="PII_ID",
    ),
    _rule(
        "sensitive.cn_phone",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷包含手机号等个人联系方式。",
        r"(?<!\d)1[3-9]\d{9}(?!\d)",
        redact_kind="PII_PHONE",
    ),
    _rule(
        "sensitive.email",
        RiskCategory.OVER_DISCLOSURE,
        Severity.LOW,
        Disposition.REDACT,
        "载荷包含邮箱地址等个人联系方式。",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        redact_kind="PII_EMAIL",
    ),
    _rule(
        "sensitive.private_network",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷包含内网地址，泄露内部拓扑信息。",
        r"(?<!\d)(?:10\.\d{1,3}|192\.168\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3})"
        r"(?:\.\d{1,3}){1,2}(?!\d)",
        redact_kind="PRIVATE_IP",
    ),
    _rule(
        "sensitive.internal_url",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷包含内部 / 本地服务地址。",
        r"https?://[^\s\"'<>]*(?:internal|corp|\.lan|intranet|localhost|127\.0\.0\.1)[^\s\"'<>]*",
        redact_kind="INTERNAL_URL",
    ),
    _rule(
        "sensitive.confidential_marking",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷带有密级 / 禁止外传标记，说明其披露范围受限。",
        r"绝密|机密|内部资料|仅限内部|内部使用|禁止外传|不得外传|"
        r"CONFIDENTIAL|TOP\s+SECRET|INTERNAL\s+ONLY|DO\s+NOT\s+DISTRIBUTE",
        redact_kind="CLASSIFICATION",
    ),
    _rule(
        "sensitive.credential_path",
        RiskCategory.OVER_DISCLOSURE,
        Severity.MEDIUM,
        Disposition.REDACT,
        "载荷暴露凭据文件路径。",
        r"[A-Za-z]:\\[^\s\"'<>]*\.(?:pem|key|pfx|p12|jks)\b"
        r"|(?:/[\w.\-]+){2,}\.(?:pem|key|pfx|p12|jks)\b",
        redact_kind="CRED_PATH",
    ),
)


# --------------------------------------------------------------------------
# 4. 任务意图识别：用于「任务与能力语义错配」判定。
# --------------------------------------------------------------------------
INTENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "read": (
        "查询", "检索", "搜索", "读取", "获取", "查看", "统计", "摘要", "总结", "概括",
        "翻译", "分类", "提取", "分析", "解释", "parse", "query", "search", "read",
        "list", "get", "summarize", "summary", "translate", "classify", "extract",
    ),
    "write": (
        "创建", "新建", "新增", "写入", "更新", "修改", "保存", "提交", "录入", "登记",
        "create", "update", "insert", "write", "save", "upsert", "patch",
    ),
    "delete": (
        "删除", "清空", "移除", "注销", "销毁", "delete", "remove", "purge", "wipe",
    ),
    "execute": (
        "执行", "运行", "脚本", "命令", "编译", "安装", "部署", "调试",
        "shell", "bash", "exec", "run", "command", "deploy", "install",
    ),
    "network": (
        "抓取", "爬取", "下载", "访问链接", "请求接口", "联网",
        "crawl", "scrape", "download", "http", "fetch", "url",
    ),
    "export": (
        "导出", "外发", "上传", "同步到", "发送到", "分享",
        "export", "upload", "share", "sync",
    ),
    "admin": (
        "管理员", "权限", "审批", "提权", "策略配置", "角色配置",
        "admin", "permission", "role", "policy",
    ),
    "credential": (
        "密码", "密钥", "凭据", "凭证", "令牌", "证书",
        "password", "secret", "credential", "token", "key",
    ),
    "notify": (
        "通知", "告知", "邮件", "短信", "推送", "webhook",
        "notify", "email", "sms", "push",
    ),
}

#: 只读类能力上出现这些意图即视为方向冲突。
DANGEROUS_INTENTS: frozenset[str] = frozenset(
    {"write", "delete", "execute", "export", "admin", "credential"}
)

#: 只读能力上出现这些意图时直接阻断（破坏性 / 可执行动作）。
BLOCKING_INTENTS: frozenset[str] = frozenset({"delete", "execute"})

INTENT_LABELS: dict[str, str] = {
    "read": "读取 / 分析",
    "write": "写入 / 修改",
    "delete": "删除 / 清空",
    "execute": "执行代码或命令",
    "network": "联网抓取 / 访问",
    "export": "导出 / 外发",
    "admin": "权限与策略管理",
    "credential": "凭据操作",
    "notify": "通知触达",
}


def detect_intents(text: str) -> dict[str, int]:
    """返回文本中命中的意图及其命中次数。"""

    lowered = (text or "").lower()
    scores: dict[str, int] = {}
    for intent, keywords in INTENT_KEYWORDS.items():
        hits = sum(1 for keyword in keywords if keyword.lower() in lowered)
        if hits:
            scores[intent] = hits
    return scores
