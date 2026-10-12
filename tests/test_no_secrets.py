"""防止凭据误入库：扫描所有已跟踪文件里的密钥样式。

这条用例是为此前一次真实事故加的守卫：一个本地调试脚本把 API Key 硬编码在其中，
被 `git add -A` 连带提交并推送到公开仓库。凡是**已跟踪**文件里出现密钥样式，本用例即失败。

未跟踪的本地脚本不会让它失败（那也是本用例的设计：只要不进版本库就不算事故），
但一旦被 `git add`，它就会在本地与 CI 第一时间报出来。
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: 密钥样式（覆盖本项目会用到的几类）
SECRET_PATTERNS = {
    "openai/deepseek 风格 key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),
    "私钥": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Bearer 长串": re.compile(r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{24,}=*"),
}

#: 明确的测试夹具（假值），不算泄露
ALLOWED_LITERALS = {
    "sk-abcdefghijklmnopqrstuvwxyz0123456789",  # tests/test_disclosure.py 用的演示值
}

SKIP_SUFFIXES = {".whl", ".png", ".jpg", ".jpeg", ".ico", ".pdf", ".pyc"}
MAX_SCAN_BYTES = 2_000_000


def tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover - 非 git 环境
        raise unittest.SkipTest("当前目录不是 git 仓库，跳过密钥扫描")
    return [ROOT / line.strip() for line in out.splitlines() if line.strip()]


class NoSecretsInTrackedFilesTests(unittest.TestCase):
    def test_tracked_files_contain_no_secret_material(self) -> None:
        files = tracked_files()
        self.assertTrue(files, "未读到任何已跟踪文件")

        findings: list[str] = []
        for path in files:
            if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
                continue
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):  # 二进制或不可读文件跳过
                continue
            for label, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(text):
                    if match.group(0) in ALLOWED_LITERALS:
                        continue
                    line_no = text.count("\n", 0, match.start()) + 1
                    findings.append(f"{path.relative_to(ROOT)}:{line_no} 命中「{label}」")

        self.assertEqual(
            findings,
            [],
            "已跟踪文件中发现疑似密钥，请移出仓库并轮换凭据：\n" + "\n".join(findings),
        )

    def test_gitignore_blocks_root_level_scratch_scripts(self) -> None:
        """根目录临时脚本/输出必须被忽略，避免再次被 git add -A 连带提交。"""

        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in ("/test_*.py", "/test_output*.txt"):
            self.assertIn(entry, ignore)


if __name__ == "__main__":
    unittest.main()
