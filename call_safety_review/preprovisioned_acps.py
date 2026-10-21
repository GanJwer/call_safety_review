"""Use an already approved ACPs identity without repeating ATR enrollment.

This adapter is intentionally pinned to Wit 2.1.0.  Wit does not expose a
public pre-provisioned registration mode in that release, so the adapter only
supplies the validated in-memory identity state needed by the Direct listener;
it never creates or forges ``enrollment.json``.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping


EXPECTED_WIT_VERSION = "2.1.0"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})


@dataclass(frozen=True)
class PreprovisionedAcpsMaterial:
    """Read-only ACS/certificate bundle created by the official ACPs tools."""

    root: Path

    @classmethod
    def from_env(
        cls, env: Mapping[str, str]
    ) -> PreprovisionedAcpsMaterial | None:
        raw = env.get("ACPS_PREPROVISIONED", "").strip().lower()
        if raw in _FALSE_VALUES:
            return None
        if raw not in _TRUE_VALUES:
            raise RuntimeError(
                "ACPS_PREPROVISIONED 只能取 true/false、1/0、yes/no 或 on/off"
            )
        root = Path(env.get("ACPS_PREPROVISIONED_DIR", "/run/call-safety-review"))
        return cls(root=root)

    @property
    def acs_path(self) -> Path:
        return self.root / "acs-draft.json"

    def validate(self, *, public_endpoint: str) -> tuple[str, Any, dict[str, Any]]:
        """Validate the final ACS and all five certificate files.

        Returns ``(aic, CertificatePaths, acs)``.  Private-key bytes are only
        read by the SDK validator and are never logged or returned.
        """

        try:
            installed_wit = version("wit-framework")
        except PackageNotFoundError as exc:  # pragma: no cover - broken image
            raise RuntimeError("未安装 wit-framework，无法启动 ACPs") from exc
        if installed_wit != EXPECTED_WIT_VERSION:
            raise RuntimeError(
                f"已有证书模式只验证过 wit-framework {EXPECTED_WIT_VERSION}，"
                f"当前为 {installed_wit}"
            )

        acs_path = self._require_file(self.acs_path, label="正式 ACS")
        try:
            acs = json.loads(acs_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"正式 ACS 无法读取或不是有效 JSON：{acs_path}") from exc
        if not isinstance(acs, dict):
            raise RuntimeError("正式 ACS 顶层必须是 JSON 对象")

        aic = acs.get("aic")
        if not isinstance(aic, str) or not aic.strip():
            raise RuntimeError("正式 ACS 缺少平台分配的 aic")
        if acs.get("active") is not True:
            raise RuntimeError("正式 ACS 的 active 不是 true")

        skill_ids = {
            item.get("id")
            for item in acs.get("skills", [])
            if isinstance(item, dict)
        }
        if "safety.review_call" not in skill_ids:
            raise RuntimeError("正式 ACS 未声明 safety.review_call 技能")

        endpoint_urls = {
            str(item.get("url", "")).rstrip("/")
            for item in acs.get("endPoints", [])
            if isinstance(item, dict)
        }
        configured = public_endpoint.rstrip("/")
        accepted = {configured, f"{configured}/rpc"}
        if not endpoint_urls.intersection(accepted):
            raise RuntimeError(
                "正式 ACS 的 JSON-RPC 端点与 ACPS_PUBLIC_ENDPOINT 不一致："
                f"{sorted(endpoint_urls)}"
            )

        from wit.acps.certificate_validation import validate_certificate_paths
        from wit.acps.identity import CertificatePaths

        paths = CertificatePaths(
            client_certificate=self._require_file(
                self.root / "acps" / "certs" / f"{aic}.client.pem",
                label="客户端证书",
            ),
            client_private_key=self._require_file(
                self.root / "acps" / "private" / f"{aic}.client.key",
                label="客户端私钥",
            ),
            server_certificate=self._require_file(
                self.root / "acps" / "certs" / f"{aic}.pem",
                label="服务端证书",
            ),
            server_private_key=self._require_file(
                self.root / "acps" / "private" / f"{aic}.key",
                label="服务端私钥",
            ),
            trust_bundle=self._require_file(
                self.root / "acps" / "trust-bundle.pem",
                label="信任链",
            ),
        )
        validate_certificate_paths(
            aic=aic,
            paths=paths,
            public_endpoint=public_endpoint,
        )
        return aic, paths, acs

    @staticmethod
    def _require_file(path: Path, *, label: str) -> Path:
        if not path.is_file():
            raise RuntimeError(f"{label}不存在：{path}")
        return path


class _PreprovisionedProvisioner:
    """Small compatibility object consumed by WitRuntime 2.1.0."""

    def __init__(self, *, runtime: Any, aic: str, paths: Any, acs_path: Path) -> None:
        from wit.acps.identity import IdentityRef, ResolvedAcpsIdentity
        from wit.acps.infrastructure import AcpsEnrollmentConfig

        if runtime.acps_config is None:  # pragma: no cover - guarded by construction
            raise RuntimeError("WitRuntime 缺少 ACPs 配置")
        self.compiled = runtime.compiled
        self.workspace = runtime.workspace
        self.acps_config = runtime.acps_config
        self.config = AcpsEnrollmentConfig.for_workspace(
            workspace=runtime.workspace,
            acps=runtime.acps_config,
        )
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        identity = ResolvedAcpsIdentity(
            ref=IdentityRef(aic=aic, provenance="preprovisioned"),
            status="active",
            certificate_paths=paths,
            metadata={"acsPath": str(acs_path)},
        )
        self._state = {"status": "active", "identity": identity.to_dict()}

    def state(self) -> dict[str, Any]:
        return deepcopy(self._state)


def attach_preprovisioned_identity(
    runtime: Any,
    material: PreprovisionedAcpsMaterial,
    *,
    public_endpoint: str,
) -> dict[str, Any]:
    """Validate material and attach a non-persistent identity to WitRuntime."""

    aic, paths, _acs = material.validate(public_endpoint=public_endpoint)
    if not hasattr(runtime, "_provisioner"):
        raise RuntimeError("当前 WitRuntime 不兼容已有证书适配器")
    runtime._provisioner = _PreprovisionedProvisioner(  # noqa: SLF001 - pinned adapter
        runtime=runtime,
        aic=aic,
        paths=paths,
        acs_path=material.acs_path,
    )
    return {"aic": aic, "acs_path": str(material.acs_path)}
