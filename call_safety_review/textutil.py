"""载荷文本的轻量工具：不可见字符清理、分词、相关度与片段切分。"""

from __future__ import annotations

import re
from typing import Iterable, Sequence

_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
_ASCII_WORD_RE = re.compile(r"[a-z0-9]{2,}")
_SEGMENT_RE = re.compile(r"[^。！？!?；;\n]*[。！？!?；;\n]|[^。！？!?；;\n]+")

_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "please",
        "you",
        "your",
        "我们",
        "你们",
        "请",
        "麻烦",
        "帮我",
        "一下",
        "这个",
        "那个",
        "然后",
        "以及",
        "并且",
        "如果",
        "需要",
    }
)


def strip_invisible(text: str) -> tuple[str, int]:
    """移除零宽 / 双向控制字符，返回 (清理后文本, 移除数量)。"""

    matches = _INVISIBLE_RE.findall(text or "")
    if not matches:
        return text or "", 0
    return _INVISIBLE_RE.sub("", text), len(matches)


def tokenize(text: str) -> set[str]:
    """中英混排分词：ASCII 词 + 中文二元组，够用且不引入外部依赖。"""

    lowered = (text or "").lower()
    tokens: set[str] = {word for word in _ASCII_WORD_RE.findall(lowered) if word not in _STOPWORDS}
    for run in _CJK_RE.findall(lowered):
        if len(run) == 1:
            tokens.add(run)
            continue
        tokens.update(run[index : index + 2] for index in range(len(run) - 1))
    return tokens


def overlap_ratio(source: Iterable[str], reference: Iterable[str]) -> float:
    """``source`` 中落在 ``reference`` 里的比例。"""

    left = set(source)
    if not left:
        return 0.0
    right = set(reference)
    if not right:
        return 0.0
    return len(left & right) / len(left)


def split_segments(text: str) -> list[str]:
    """按行与句末标点切分，保留标点，便于按片段裁剪。"""

    if not text:
        return []
    return [segment for segment in _SEGMENT_RE.findall(text) if segment.strip()]


def preview(span: str, *, keep: int = 2) -> str:
    """给审计留一个不泄露内容的证据预览。"""

    cleaned = (span or "").strip()
    if len(cleaned) <= keep * 2:
        return "*" * len(cleaned)
    return f"{cleaned[:keep]}{'*' * min(len(cleaned) - keep * 2, 8)}{cleaned[-keep:]}"


def as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def collect_string_leaves(value: object, prefix: str) -> list[tuple[str, str]]:
    """递归收集 dict / list 中的字符串值（键名也计入路径，用于定位）。"""

    leaves: list[tuple[str, str]] = []
    if isinstance(value, str):
        leaves.append((prefix, value))
    elif isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, str):
                leaves.append((path, item))
            elif isinstance(item, (dict, list, tuple)):
                leaves.extend(collect_string_leaves(item, path))
            elif item is not None:
                leaves.append((path, as_text(item)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]"
            if isinstance(item, str):
                leaves.append((path, item))
            elif isinstance(item, (dict, list, tuple)):
                leaves.extend(collect_string_leaves(item, path))
            elif item is not None:
                leaves.append((path, as_text(item)))
    return leaves


def replace_spans(text: str, spans: Sequence[tuple[int, int, str]]) -> str:
    """按 (start, end, replacement) 原地替换，重叠区间取并集优先。"""

    if not spans:
        return text
    ordered = sorted(spans, key=lambda item: (item[0], -item[1]))
    pieces: list[str] = []
    cursor = 0
    for start, end, replacement in ordered:
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
