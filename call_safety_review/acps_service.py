"""把审查智能体作为 ACPs Partner 对外提供 ``safety.review_call`` 技能。

其它智能体即可通过 AIP Direct（JSON-RPC / mTLS）调用本审查服务，这与任务书
「内容安全预检智能体」的形态一致：审查方是 Partner，调用方是 Leader。

> [!WARNING]
> 本模块需要真实的 ACPs 基础设施（Registry、CA、Discovery、证书与 mTLS 监听地址），
> 因此**不在本地单元测试覆盖范围内**：本地测试只验证 Agent 声明、能力投影与
> ACS 草稿（见 ``tests/test_acps_projection.py``），不证明真实注册、签发与跨主机调用。
"""

from __future__ import annotations

import os
import asyncio
import logging
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .agent import build_engine, build_review_agent
from .amp_observability import TaskCorrelatedAmpAccessHooks
from .engine import ReviewEngine
from .preprovisioned_acps import (
    PreprovisionedAcpsMaterial,
    attach_preprovisioned_identity,
)

REQUIRED_ENV_VARS: tuple[str, ...] = (
    "ACPS_REGISTRY_URL",
    "ACPS_CA_URL",
    "ACPS_DISCOVERY_URL",
    "ACPS_PUBLIC_ENDPOINT",
    "ACPS_ORGANIZATION",
    "ACPS_COUNTRY_CODE",
)


@dataclass
class AcpsSettings:
    """部署配置：全部来自环境变量，避免把地址与机构信息写进代码。"""

    registry_url: str
    ca_url: str
    discovery_url: str
    public_endpoint: str
    organization: str
    country_code: str
    registry_mtls_url: str | None = None
    workspace: str = ".wit/content-safety-review"
    serve_host: str = "0.0.0.0"
    serve_port: int = 8443
    requested_validity: int = 365
    strict_interop: bool = True
    request_timeout_seconds: float = 90.0
    preprovisioned: PreprovisionedAcpsMaterial | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> AcpsSettings:
        values = env if env is not None else os.environ
        missing = [name for name in REQUIRED_ENV_VARS if not values.get(name)]
        if missing:
            raise RuntimeError("缺少 ACPs 部署所需的环境变量：" + "、".join(missing))
        return cls(
            registry_url=values["ACPS_REGISTRY_URL"],
            ca_url=values["ACPS_CA_URL"],
            discovery_url=values["ACPS_DISCOVERY_URL"],
            public_endpoint=values["ACPS_PUBLIC_ENDPOINT"],
            organization=values["ACPS_ORGANIZATION"],
            country_code=values["ACPS_COUNTRY_CODE"],
            registry_mtls_url=values.get("ACPS_REGISTRY_MTLS_URL") or None,
            workspace=values.get("ACPS_WORKSPACE", cls.workspace),
            serve_host=values.get("ACPS_SERVE_HOST", cls.serve_host),
            serve_port=int(values.get("ACPS_SERVE_PORT", cls.serve_port)),
            requested_validity=int(values.get("ACPS_CERT_VALIDITY", cls.requested_validity)),
            preprovisioned=PreprovisionedAcpsMaterial.from_env(values),
        )


def build_acps_config(settings: AcpsSettings, *, registration: Any = None) -> Any:
    """按手册要求构造 ``AcpsConfig``（ACPs 的唯一部署配置源）。"""

    from wit import (
        AcpsConfig,
        AcpsRegistration,
        AgentCertificateRequest,
        AgentProviderProfile,
    )

    return AcpsConfig.custom(
        registry_url=settings.registry_url,
        registry_mtls_url=settings.registry_mtls_url,
        ca_url=settings.ca_url,
        discovery_url=settings.discovery_url,
        public_endpoint=settings.public_endpoint,
        provider=AgentProviderProfile(
            organization=settings.organization,
            country_code=settings.country_code,
        ),
        certificate=AgentCertificateRequest(requested_validity=settings.requested_validity),
        registration=registration or AcpsRegistration.integrated(),
        strict_interop=settings.strict_interop,
        request_timeout_seconds=settings.request_timeout_seconds,
    )


def build_partner_agent(
    *,
    model: Any,
    engine: ReviewEngine | None = None,
    modes: Sequence[str] = ("rpc", "stream"),
    **agent_kwargs: Any,
) -> Any:
    """构造声明了 ``AcpsDirect`` 绑定的审查 Partner。"""

    from wit import AcpsDirect

    agent = build_review_agent(
        model=model,
        engine=engine or build_engine(),
        expose_over_acps=True,
        **agent_kwargs,
    )
    agent.protocols = [AcpsDirect(modes=tuple(modes))]
    agent.aip_hooks = [*agent.aip_hooks, TaskCorrelatedAmpAccessHooks()]
    return agent


def build_partner_runtime(
    *,
    model: Any,
    settings: AcpsSettings,
    engine: ReviewEngine | None = None,
    **agent_kwargs: Any,
) -> Any:
    from wit import WitRuntime

    agent = build_partner_agent(model=model, engine=engine, **agent_kwargs)
    workspace = Path(settings.workspace)
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"ACPs 状态目录不可写：{workspace}（{exc.strerror}）。"
            "只读根文件系统下需要挂载可写卷，例如 "
            "-v csr-acps-state:/var/lib/content-safety-review"
        ) from exc
    runtime = WitRuntime(agent, workspace=workspace, acps=build_acps_config(settings))
    if settings.preprovisioned is not None:
        attach_preprovisioned_identity(
            runtime,
            settings.preprovisioned,
            public_endpoint=settings.public_endpoint,
        )
    for hook in agent.aip_hooks:
        if isinstance(hook, TaskCorrelatedAmpAccessHooks):
            hook.bind_runtime(runtime)
    return runtime


class _PreflightModel:
    """自检用的占位 Provider：只参与 compile，不会真正调用模型。"""

    model = "preflight-stub"

    async def complete(self, request: Any) -> Any:  # pragma: no cover - 自检不会调用
        raise RuntimeError("preflight stub cannot call models")


async def preflight(
    *,
    settings: AcpsSettings | None = None,
    model: Any = None,
    engine: ReviewEngine | None = None,
    env: dict[str, str] | None = None,
    **agent_kwargs: Any,
) -> dict[str, Any]:
    """部署前自检：环境变量、状态目录、Agent 装配、ACS 投影与模型 Provider。"""

    from wit import WitRuntime

    from .agent import openai_model_from_env

    values = env if env is not None else os.environ
    checks: list[dict[str, Any]] = []

    missing = [name for name in REQUIRED_ENV_VARS if not values.get(name)]
    checks.append(
        {
            "name": "acps_env_vars",
            "ok": not missing,
            "detail": "必需变量齐全" if not missing else "缺少：" + "、".join(missing),
        }
    )

    if settings is None:
        try:
            settings = AcpsSettings.from_env(values)
        except RuntimeError as exc:
            return {
                "ok": False,
                "service": "content-safety-review",
                "checks": checks,
                "error": str(exc),
                "next": "补齐上面缺少的环境变量后重新执行 `acps --check`。",
            }

    workspace = Path(settings.workspace)
    state_dir_ok = False
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        probe = workspace / ".write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        state_dir_ok = True
        checks.append({"name": "state_dir_writable", "ok": True, "detail": str(workspace)})
    except OSError as exc:
        checks.append(
            {
                "name": "state_dir_writable",
                "ok": False,
                "detail": f"{workspace} 不可写（{exc.strerror}）；只读根文件系统请挂载可写卷",
            }
        )

    if model is None:
        try:
            from .agent import resolve_model_settings

            resolved = resolve_model_settings(values)
            model = openai_model_from_env(env=values)
            checks.append(
                {
                    "name": "model_provider",
                    "ok": True,
                    "detail": f"{resolved['model']} @ {resolved['base_url']}",
                }
            )
        except RuntimeError as exc:
            model = _PreflightModel()
            checks.append({"name": "model_provider", "ok": False, "detail": str(exc)})
    else:
        checks.append({"name": "model_provider", "ok": True, "detail": type(model).__name__})

    if settings.preprovisioned is not None:
        try:
            aic, _paths, _acs = settings.preprovisioned.validate(
                public_endpoint=settings.public_endpoint
            )
            checks.append(
                {
                    "name": "preprovisioned_identity",
                    "ok": True,
                    "detail": {"aic": aic, "acs": str(settings.preprovisioned.acs_path)},
                }
            )
        except RuntimeError as exc:
            checks.append(
                {"name": "preprovisioned_identity", "ok": False, "detail": str(exc)}
            )

    # 状态目录不可写时，装配与 ACS 投影检查改用临时目录，避免自检本身崩溃。
    import tempfile

    assembly_workspace = workspace if state_dir_ok else Path(tempfile.mkdtemp(prefix="csr-preflight-"))
    agent = build_partner_agent(model=model, engine=engine or build_engine(), **agent_kwargs)
    runtime = WitRuntime(agent, workspace=assembly_workspace, acps=build_acps_config(settings))
    errors = [item.to_dict() for item in runtime.compiled.diagnostics if item.level == "error"]
    checks.append(
        {
            "name": "agent_assembly",
            "ok": not errors,
            "detail": "无 error 级诊断" if not errors else errors,
        }
    )

    draft: dict[str, Any] | None = None
    try:
        draft = runtime.acs_draft()
        skills = sorted(item["id"] for item in draft.get("skills", []))
        endpoints = [item.get("url") for item in draft.get("endPoints", [])]
        checks.append(
            {
                "name": "acs_projection",
                "ok": "safety.review_call" in skills,
                "detail": {"skills": skills, "endpoints": endpoints},
            }
        )
    except Exception as exc:  # noqa: BLE001 - 自检要如实报告而不是抛出
        checks.append(
            {"name": "acs_projection", "ok": False, "detail": f"{type(exc).__name__}: {exc}"}
        )

    ok = all(item["ok"] for item in checks)
    return {
        "ok": ok,
        "service": "content-safety-review",
        "workspace": str(workspace),
        "public_endpoint": settings.public_endpoint,
        "checks": checks,
        "acs_skills": sorted(item["id"] for item in (draft or {}).get("skills", [])),
        "next": (
            "自检通过：可执行 `acps` 启动长期服务（未配置凭据时会按注册状态轮询）。"
            if ok
            else "按上面未通过的检查项修正后重新自检。"
        ),
    }


#: 注册状态机中不需要人工干预、可以继续推进的状态（网络抖动、审核中等）。
RETRYABLE_STATUSES: frozenset[str] = frozenset(
    {
        "needs_login",
        "draft_ready",
        "submitted",
        "entity_registered",
        "issuing_certificates",
        "finalizing",
        "needs_renewal",
        "blocked",
        "unknown",
    }
)

#: 终止状态：重试没有意义，应当退出让人处理。
TERMINAL_STATUSES: frozenset[str] = frozenset({"rejected", "failed"})


async def serve(
    *,
    model: Any = None,
    settings: AcpsSettings | None = None,
    engine: ReviewEngine | None = None,
    credentials: Any = None,
    http_host: str = "0.0.0.0",
    http_port: int = 8080,
    auth_token: str | None = None,
    max_body_bytes: int = 1_048_576,
    wait_for_approval: bool = True,
    approval_poll_seconds: float = 60.0,
    **agent_kwargs: Any,
) -> dict[str, Any]:
    """推进 ATR 注册并启动 Direct Partner listener（需要真实基础设施）。

    同时会在 ``http_port`` 上启动审查 HTTP 服务，让健康检查与旁路调用在注册期间就可用；
    ``/readyz`` 会带上 ACPs 注册状态（未就绪 → 503），``/healthz`` 只反映进程存活。

    状态推进策略：``ready`` 后开始服务；``rejected`` / ``failed`` 立即返回（退出让人处理）；
    其余非就绪状态（待审核、网络抖动、材料签发中）默认每 ``approval_poll_seconds`` 重试一次，
    容器保持运行并持续上报状态；``wait_for_approval=False``（CLI 的 ``--once``）则立即返回。
    服务运行到收到 SIGTERM / SIGINT，然后 ``stop_serving()`` 并返回 ``status="stopped"``。
    """

    from .agent import openai_model_from_env
    from .http_service import ReviewService, start_in_thread

    settings = settings or AcpsSettings.from_env()
    model = model or openai_model_from_env()
    runtime = build_partner_runtime(model=model, settings=settings, engine=engine, **agent_kwargs)

    validation = await runtime.validate()
    if not validation.get("valid", False):
        raise RuntimeError(f"Agent 装配校验失败：{validation.get('diagnostics')}")
    draft_path = runtime.save_acs()

    # 注册期间就让健康检查与旁路审查可用；/readyz 带上 ACPs 状态。
    state: dict[str, Any] = {"ready": False, "acps_status": "starting"}
    service = ReviewService(
        engine or build_engine(),
        auth_token=auth_token,
        max_body_bytes=max_body_bytes,
        readiness=lambda: dict(state),
    )
    server = None
    if http_port:
        server, _thread = start_in_thread(service, host=http_host, port=http_port)

    stop = asyncio.Event()
    _install_stop_handlers(stop)

    enrollment = None
    try:
        if settings.preprovisioned is not None:
            serving = await runtime.serve_direct_partner(
                host=settings.serve_host,
                port=settings.serve_port,
                amp=True,
                amp_periodic_logs=("heartbeat",),
            )
            serving_status = str(getattr(serving, "status", "unknown"))
            serving_details = serving.to_dict()
            state["acps_status"] = serving_status
            state["summary"] = serving_details
            if serving_status != "serving":
                raise RuntimeError(f"已有证书模式启动失败：{serving_details}")
            state["ready"] = True
            logging.getLogger("call_safety_review.acps").info(
                "ACPs Partner 使用已审核身份在 %s:%s 提供服务；AIC=%s",
                settings.serve_host,
                settings.serve_port,
                settings.preprovisioned.validate(
                    public_endpoint=settings.public_endpoint
                )[0],
            )
            await stop.wait()
            return {
                "status": "stopped",
                "acs": str(settings.preprovisioned.acs_path),
                "summary": serving_details,
                "http_port": http_port or None,
            }

        from wit import RegistryPasswordCredentials

        credentials = credentials or RegistryPasswordCredentials.from_env()
        while True:
            enrollment = await runtime.up_until_ready(
                serve=True,
                host=settings.serve_host,
                port=settings.serve_port,
                credentials=credentials,
            )
            summary = enrollment.summary()
            waiting = bool(getattr(enrollment, "waiting_for_review", False))
            status = str(getattr(enrollment, "status", "unknown"))
            state["acps_status"] = status
            state["summary"] = summary
            if getattr(enrollment, "ready", False):
                state["ready"] = True
                break
            if wait_for_approval and status not in TERMINAL_STATUSES:
                if status in RETRYABLE_STATUSES:
                    reason = "Registry 正在审核" if waiting else f"注册未就绪（{status}）"
                else:
                    reason = f"出现未知注册状态（{status}），按可恢复处理"
                logging.getLogger("call_safety_review.acps").warning(
                    "%s，%s 秒后重试：%s", reason, approval_poll_seconds, summary
                )
                try:
                    await asyncio.wait_for(stop.wait(), timeout=approval_poll_seconds)
                except asyncio.TimeoutError:
                    continue
                return {
                    "status": "stopped",
                    "acs_draft": str(draft_path),
                    "summary": summary,
                    "detail": "等待注册就绪期间收到停止信号。",
                }
            return {
                "status": "pending_review" if waiting else getattr(enrollment, "status", "unknown"),
                "acs_draft": str(draft_path),
                "summary": summary,
                "operator_hint": (
                    "状态为终态或使用了 --once：请按 summary 的 Next 提示处理后重启容器。"
                ),
            }

        logging.getLogger("call_safety_review.acps").info(
            "ACPs Partner 已在 %s:%s 提供服务；%s",
            settings.serve_host,
            settings.serve_port,
            enrollment.summary(),
        )
        await stop.wait()
        return {
            "status": "stopped",
            "acs_draft": str(draft_path),
            "summary": enrollment.summary(),
            "http_port": http_port or None,
        }
    finally:
        try:
            await runtime.stop_serving()
        except Exception:  # noqa: BLE001 - 停机路径不应掩盖主流程异常
            logging.getLogger("call_safety_review.acps").exception("停止 ACPs 服务时出错")
        if server is not None:
            server.shutdown()
            server.server_close()


def _install_stop_handlers(stop: "asyncio.Event") -> None:
    """把 SIGTERM / SIGINT 接到停止事件上（Windows 上退化为 signal.signal）。"""

    loop = asyncio.get_event_loop()
    for name in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            loop.add_signal_handler(signum, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):
            try:
                signal.signal(signum, lambda *_: loop.call_soon_threadsafe(stop.set))
            except (ValueError, OSError):  # pragma: no cover - 非主线程
                continue
