"""能力目录：描述目标能力「能做什么、允许什么意图、接收哪些字段、可承受什么数据分级」。

真实部署中这份目录可以从 ACPs 的 ACS 能力名片（``Capability.to_acps_skill()``）
或内部能力注册表构建；本地默认目录只用于开箱即用的自检与演示。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .textutil import overlap_ratio, tokenize


@dataclass(frozen=True, slots=True)
class CapabilityProfile:
    """一个目标能力的语义与披露边界。"""

    capability_id: str
    description: str
    keywords: tuple[str, ...] = ()
    intents: tuple[str, ...] = ("read",)
    read_only: bool = True
    input_fields: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    owner_agent: str | None = None
    max_classification: str = "internal"

    @property
    def haystack(self) -> str:
        return " ".join((self.capability_id, self.description, *self.keywords))

    def to_dict(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "description": self.description,
            "keywords": list(self.keywords),
            "intents": list(self.intents),
            "read_only": self.read_only,
            "input_fields": list(self.input_fields),
            "required_fields": list(self.required_fields),
            "owner_agent": self.owner_agent,
            "max_classification": self.max_classification,
        }


class CapabilityCatalog:
    """按能力 id 索引的目录，支持从 ``ACS`` 投影或字典构建。"""

    def __init__(self, profiles: Iterable[CapabilityProfile] = ()) -> None:
        self._profiles: dict[str, CapabilityProfile] = {}
        for profile in profiles:
            self._profiles[profile.capability_id] = profile

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, capability_id: object) -> bool:
        return capability_id in self._profiles

    def get(self, capability_id: str) -> CapabilityProfile | None:
        return self._profiles.get(capability_id)

    def profiles(self) -> list[CapabilityProfile]:
        return list(self._profiles.values())

    def with_profile(self, profile: CapabilityProfile) -> CapabilityCatalog:
        merged = CapabilityCatalog(self._profiles.values())
        merged._profiles[profile.capability_id] = profile
        return merged

    def merge(self, other: CapabilityCatalog) -> CapabilityCatalog:
        merged = CapabilityCatalog(self._profiles.values())
        merged._profiles.update(other._profiles)
        return merged

    def best_match(self, text: str, *, exclude: str | None = None) -> tuple[str, int, float] | None:
        """返回与该文本最贴近的其它能力：``(能力 id, 命中关键词数, 命中比例)``。

        用于发现「任务语义更像应该调另一个能力」的错配。
        """

        lowered = (text or "").lower()
        tokens = tokenize(text)
        best: tuple[str, int, float] | None = None
        for profile in self._profiles.values():
            if profile.capability_id == exclude or not profile.keywords:
                continue
            hits = sum(1 for keyword in profile.keywords if keyword.lower() in lowered)
            if not hits:
                continue
            semantic = overlap_ratio(tokens, tokenize(profile.haystack))
            score = hits + semantic
            if best is None or score > best[1] + best[2]:
                best = (profile.capability_id, hits, hits / len(profile.keywords))
        return best

    def to_dict(self) -> dict[str, object]:
        return {"profiles": [profile.to_dict() for profile in self._profiles.values()]}

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> CapabilityCatalog:
        """从 ACS / 注册表风格的字典构建目录。"""

        raw = payload.get("profiles") if "profiles" in payload else payload
        profiles: list[CapabilityProfile] = []
        if isinstance(raw, Mapping):
            iterable: Iterable[tuple[str, object]] = raw.items()
        else:
            iterable = ((str(item.get("capability_id", "")), item) for item in raw or [])  # type: ignore[union-attr]
        for key, item in iterable:
            if not isinstance(item, Mapping):
                continue
            profiles.append(
                CapabilityProfile(
                    capability_id=str(item.get("capability_id") or key),
                    description=str(item.get("description") or ""),
                    keywords=tuple(str(value) for value in item.get("keywords", ())),
                    intents=tuple(str(value) for value in item.get("intents", ("read",))),
                    read_only=bool(item.get("read_only", True)),
                    input_fields=tuple(str(value) for value in item.get("input_fields", ())),
                    required_fields=tuple(str(value) for value in item.get("required_fields", ())),
                    owner_agent=item.get("owner_agent"),  # type: ignore[arg-type]
                    max_classification=str(item.get("max_classification", "internal")),
                )
            )
        return cls(profiles)


def default_catalog() -> CapabilityCatalog:
    """开箱即用的示例能力目录（覆盖只读、写入、执行、导出等典型能力）。"""

    return CapabilityCatalog(
        [
            CapabilityProfile(
                capability_id="doc.summarize",
                description="对给定文档正文生成结构化摘要，只读，不修改源文档。",
                keywords=("摘要", "总结", "概括", "提炼", "要点", "summarize", "summary"),
                intents=("read",),
                read_only=True,
                input_fields=("document", "max_words", "language"),
                required_fields=("document",),
                max_classification="confidential",
            ),
            CapabilityProfile(
                capability_id="text.translate",
                description="把一段文本翻译成目标语言，只读。",
                keywords=("翻译", "translate", "语种", "目标语言"),
                intents=("read",),
                read_only=True,
                input_fields=("text", "target_language"),
                required_fields=("text", "target_language"),
            ),
            CapabilityProfile(
                capability_id="kb.search",
                description="在内网知识库中检索条目并返回命中的片段，只读。",
                keywords=("检索", "搜索", "知识库", "问答", "search", "knowledge", "faq"),
                intents=("read",),
                read_only=True,
                input_fields=("query", "top_k", "filters"),
                required_fields=("query",),
            ),
            CapabilityProfile(
                capability_id="data.query",
                description="按只读 SQL 口径查询业务数据集的聚合指标。",
                keywords=("查询", "统计", "指标", "口径", "数据集", "query", "metrics"),
                intents=("read",),
                read_only=True,
                input_fields=("dataset", "metrics", "time_range", "filters"),
                required_fields=("dataset", "metrics"),
                max_classification="confidential",
            ),
            CapabilityProfile(
                capability_id="ticket.create",
                description="创建工单并通知值班同学，写入型能力。",
                keywords=("工单", "提单", "创建", "报障", "ticket", "issue"),
                intents=("write", "notify"),
                read_only=False,
                input_fields=("title", "detail", "priority", "assignee"),
                required_fields=("title", "detail"),
            ),
            CapabilityProfile(
                capability_id="report.export",
                description="把报表导出为文件并投递到指定位置，具备导出能力。",
                keywords=("报表", "导出", "下载", "export", "report", "下载链接"),
                intents=("read", "export"),
                read_only=False,
                input_fields=("report_id", "format", "destination"),
                required_fields=("report_id", "format"),
                max_classification="confidential",
            ),
            CapabilityProfile(
                capability_id="infra.shell",
                description="在受控沙箱内执行 shell 命令，具备执行能力，仅限运维白名单。",
                keywords=("命令", "执行", "脚本", "shell", "运维"),
                intents=("execute", "admin"),
                read_only=False,
                input_fields=("command", "timeout_seconds"),
                required_fields=("command",),
                max_classification="restricted",
            ),
            CapabilityProfile(
                capability_id="hr.employee.profile",
                description="查询员工基础档案信息，只读，属于受限人力数据。",
                keywords=("员工", "档案", "人力", "在职", "employee", "profile", "hr"),
                intents=("read",),
                read_only=True,
                input_fields=("employee_id", "fields"),
                required_fields=("employee_id",),
                max_classification="restricted",
            ),
        ]
    )


