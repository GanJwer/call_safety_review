"""调用内容安全审查的 HTTP 服务层（只用标准库，便于容器化部署）。

容器默认以 ``python -m call_safety_review serve-http`` 启动本服务；同一份镜像也可以用
``acps`` 子命令作为 ACPs Partner 部署，此时本服务会作为健康检查 / 旁路入口一并启动。

端点：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | ``/healthz`` | 存活探针（无需鉴权） |
| GET | ``/readyz`` | 就绪探针（无需鉴权；ACPs 模式会带上注册状态） |
| GET | ``/version`` | 服务版本与已安装的 wit / acps-sdk 版本 |
| GET | ``/policy`` | 当前策略与规则清单（code / 类别 / 严重度 / 建议处置） |
| GET | ``/catalog`` | 能力目录（任务-能力语义错配的判定依据） |
| GET | ``/metrics`` | Prometheus 文本格式计数 |
| POST | ``/review`` | 审查一次待下发调用，返回结论与安全载荷 |
| POST | ``/rewrite`` | 只做最小化披露与脱敏重写 |

``/review`` 默认**镜像结论到 HTTP 状态码**：``allow`` / ``allow_redacted`` → 200、
``needs_confirmation`` → 409、``block`` → 403；响应体始终是完整结论，客户端也可以只分支于
响应头 ``X-CSR-Verdict``。需要"永远 200、只看 body"时传 ``?always_200=1`` 或启动时
``--always-200``。
"""

from __future__ import annotations

import hmac
import json
import logging
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from .contracts import CallReviewRequest, Verdict
from .engine import ReviewEngine

LOGGER = logging.getLogger("call_safety_review.service")

SERVICE_NAME = "content-safety-review"
SERVICE_VERSION = "1.0.0"

#: 结论 → HTTP 状态码（``--always-200`` / ``?always_200=1`` 时全部返回 200）。
VERDICT_STATUS: dict[str, int] = {
    Verdict.ALLOW.value: 200,
    Verdict.ALLOW_REDACTED.value: 200,
    Verdict.NEEDS_CONFIRMATION.value: 409,
    Verdict.BLOCK.value: 403,
}

#: 无需鉴权的路径（探针）。
PUBLIC_PATHS = frozenset({"/healthz", "/readyz"})

#: 超过上限时仍愿意丢弃读取的额外字节数：先读完客户端已发出的内容再回 413，
#: 避免客户端在写入过程中被连接重置。（超过「上限 + 本值」则立即断开。）
DRAIN_OVERHEAD_BYTES = 262_144


def configure_logging(level: str | int = "INFO") -> None:
    """统一的日志格式；容器里收集 stdout 即可。"""

    resolved = level if isinstance(level, int) else getattr(logging, str(level).upper(), logging.INFO)
    logging.basicConfig(
        level=resolved,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _installed_versions() -> dict[str, str]:
    from importlib.metadata import PackageNotFoundError, version

    found: dict[str, str] = {}
    for distribution in ("wit-framework", "acps-sdk"):
        try:
            found[distribution] = version(distribution)
        except PackageNotFoundError:  # pragma: no cover - 未安装时才会走到
            found[distribution] = "not-installed"
    return found


class ReviewService:
    """无状态审查服务：把 :class:`~call_safety_review.engine.ReviewEngine` 包装成可部署的 API。"""

    def __init__(
        self,
        engine: ReviewEngine | None = None,
        *,
        auth_token: str | None = None,
        max_body_bytes: int = 1_048_576,
        mirror_status: bool = True,
        readiness: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self.engine = engine or ReviewEngine()
        self.auth_token = auth_token or None
        self.max_body_bytes = int(max_body_bytes)
        self.mirror_status = mirror_status
        self._readiness = readiness
        self.started_at = time.monotonic()
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}

    # ------------------------------------------------------------------
    # 运行期信息
    # ------------------------------------------------------------------
    def set_readiness(self, probe: Callable[[], Mapping[str, Any]] | None) -> None:
        """注入就绪探针（ACPs 模式用它上报注册状态）。"""

        self._readiness = probe

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def healthz(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "policy_version": self.engine.policy.policy_version,
            "uptime_seconds": round(self.uptime_seconds, 3),
        }

    def readyz(self) -> tuple[int, dict[str, Any]]:
        body: dict[str, Any] = {
            "ready": True,
            **self.healthz(),
            "capabilities": len(self.engine.catalog),
        }
        if self._readiness is not None:
            extra = dict(self._readiness())
            body.update(extra)
            if not extra.get("ready", True):
                body["ready"] = False
        return (200 if body["ready"] else 503), body

    def version_document(self) -> dict[str, Any]:
        return {
            "service": SERVICE_NAME,
            "version": SERVICE_VERSION,
            "policy_version": self.engine.policy.policy_version,
            "dependencies": _installed_versions(),
        }

    def policy_document(self) -> dict[str, Any]:
        from .capabilities import _all_rules

        return {
            "policy": self.engine.policy.to_dict(),
            "verdicts": [item.value for item in Verdict],
            "risk_categories": [
                "prompt_injection",
                "unauthorized_request",
                "task_capability_mismatch",
                "over_disclosure",
            ],
            "rules": [
                {
                    "code": rule.code,
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "disposition": rule.disposition.value,
                }
                for rule in _all_rules()
            ],
        }

    def catalog_document(self) -> dict[str, Any]:
        return {"profiles": [profile.to_dict() for profile in self.engine.catalog.profiles()]}

    def metrics_text(self) -> str:
        with self._lock:
            counters = dict(self._counters)
        lines = [
            "# HELP csr_reviews_total 审查次数（按结论）",
            "# TYPE csr_reviews_total counter",
        ]
        for verdict in VERDICT_STATUS:
            lines.append(
                f'csr_reviews_total{{verdict="{verdict}"}} {counters.get("verdict_" + verdict, 0)}'
            )
        lines.extend(
            [
                "# HELP csr_errors_total 请求层错误次数（按类别）",
                "# TYPE csr_errors_total counter",
            ]
        )
        for key in sorted(name for name in counters if name.startswith("error_")):
            kind = key[len("error_") :]
            lines.append(f'csr_errors_total{{kind="{kind}"}} {counters[key]}')
        lines.extend(
            [
                "# HELP csr_http_requests_total HTTP 请求次数",
                "# TYPE csr_http_requests_total counter",
                f'csr_http_requests_total{{service="{SERVICE_NAME}"}} {counters.get("http_requests", 0)}',
                "# HELP csr_uptime_seconds 进程运行时长",
                "# TYPE csr_uptime_seconds gauge",
                f"csr_uptime_seconds {self.uptime_seconds:.3f}",
                "# HELP csr_capabilities 能力目录条目数",
                "# TYPE csr_capabilities gauge",
                f"csr_capabilities {len(self.engine.catalog)}",
                "",
            ]
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 业务端点
    # ------------------------------------------------------------------
    def review(
        self,
        payload: Mapping[str, Any],
        *,
        mirror_status: bool | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """返回 ``(http_status, body, verdict)``。"""

        request = CallReviewRequest.from_arguments(payload)
        verdict = self.engine.review(request)
        name = verdict.verdict.value
        self._bump(f"verdict_{name}")
        mirror = self.mirror_status if mirror_status is None else mirror_status
        status = VERDICT_STATUS.get(name, 200) if mirror else 200
        return status, verdict.to_dict(), name

    def rewrite(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        request = CallReviewRequest.from_arguments(payload)
        request.allow_rewrite = True
        return self.engine.rewrite(request)

    # ------------------------------------------------------------------
    # 计数
    # ------------------------------------------------------------------
    def _bump(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount


def _validate_review_payload(payload: Any) -> str | None:
    """返回错误说明；``None`` 表示载荷可用。"""

    if not isinstance(payload, Mapping):
        return "请求体必须是 JSON 对象。"
    for field in ("task_goal", "target_capability"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return f"缺少必填字段或类型不正确：{field} 必须是非空字符串。"
    return None


class _RequestError(Exception):
    """请求层错误：由处理器统一转成一次 HTTP 响应。"""

    def __init__(self, status: int, code: str, message: str, *, close_connection: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.close_connection = close_connection


def make_handler(service: ReviewService) -> type[BaseHTTPRequestHandler]:
    """构造绑定到具体服务的请求处理器。"""

    class ReviewRequestHandler(BaseHTTPRequestHandler):
        server_version = f"{SERVICE_NAME}/{SERVICE_VERSION}"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        # 防止慢客户端长期占用连接线程（读写超时后按连接关闭处理）。
        timeout = 60

        # -- 路由 ------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
            self._dispatch("POST")

        def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
            self._dispatch("HEAD")

        def log_message(self, fmt: str, *args: Any) -> None:
            LOGGER.info("%s - %s", self.address_string(), fmt % args)

        # -- 实现 ------------------------------------------------------
        def _dispatch(self, method: str) -> None:
            parts = urlsplit(self.path)
            path = parts.path.rstrip("/") or "/"
            query = parse_qs(parts.query)
            # 记录声明长度：任何"没读完请求体就响应"的路径都必须关闭连接，
            # 否则残留字节会被当成下一个请求解析（keep-alive 上的协议违规）。
            try:
                self._unread_body = max(int(self.headers.get("Content-Length") or 0), 0)
            except ValueError:
                self._unread_body = 0
            self._drained_bytes = 0
            service._bump("http_requests")

            if not self._authorized(path):
                self._respond(
                    401,
                    {"error": {"code": "unauthorized", "message": "缺少或无效的 Bearer 令牌。"}},
                    headers={"WWW-Authenticate": "Bearer"},
                )
                return

            if method in ("GET", "HEAD"):
                if path == "/healthz":
                    self._respond(200, service.healthz())
                    return
                if path == "/readyz":
                    status, body = service.readyz()
                    self._respond(status, body)
                    return
                if path == "/version":
                    self._respond(200, service.version_document())
                    return
                if path == "/policy":
                    self._respond(200, service.policy_document())
                    return
                if path == "/catalog":
                    self._respond(200, service.catalog_document())
                    return
                if path == "/metrics":
                    self._respond(
                        200, service.metrics_text(), content_type="text/plain; charset=utf-8"
                    )
                    return
                self._not_found(path)
                return

            if method != "POST":
                self._fail(405, "method_not_allowed", f"{method} 不受支持。")
                return

            if path == "/review":
                self._handle_review(query)
                return
            if path == "/rewrite":
                self._handle_rewrite()
                return
            self._not_found(path)

        def _handle_review(self, query: Mapping[str, list[str]]) -> None:
            try:
                payload = self._read_json()
            except _RequestError as exc:
                self._reject(exc)
                return
            problem = _validate_review_payload(payload)
            if problem is not None:
                self._fail(400, "invalid_request", problem)
                return
            always_ok = query.get("always_200", ["0"])[0].lower() in ("1", "true", "yes")
            status, body, verdict_name = service.review(payload, mirror_status=False if always_ok else None)
            self._respond(
                status,
                body,
                headers={
                    "X-CSR-Verdict": verdict_name,
                    "X-CSR-Review-Id": str(body.get("review_id", "")),
                },
            )

        def _handle_rewrite(self) -> None:
            try:
                payload = self._read_json()
            except _RequestError as exc:
                self._reject(exc)
                return
            if not isinstance(payload, Mapping):
                self._fail(400, "invalid_request", "请求体必须是 JSON 对象。")
                return
            self._respond(200, service.rewrite(payload))

        # -- 工具 ------------------------------------------------------
        def _authorized(self, path: str) -> bool:
            token = service.auth_token
            if not token or path in PUBLIC_PATHS:
                return True
            header = self.headers.get("Authorization") or ""
            scheme, _, value = header.partition(" ")
            if scheme.lower() != "bearer":
                return False
            return hmac.compare_digest(value.strip(), token)

        def _read_json(self) -> Any:
            encoding = (self.headers.get("Transfer-Encoding") or "").lower().strip()
            if encoding == "chunked":
                raise _RequestError(
                    411, "length_required", "不支持 Transfer-Encoding: chunked，请使用 Content-Length。"
                )
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise _RequestError(411, "length_required", "缺少 Content-Length。")
            try:
                length = int(raw_length)
            except ValueError:
                raise _RequestError(400, "invalid_request", "Content-Length 不是合法整数。") from None
            if length < 0:
                raise _RequestError(400, "invalid_request", "Content-Length 不能为负。")
            if length > service.max_body_bytes:
                self._drain_pending_body()
                raise _RequestError(
                    413,
                    "payload_too_large",
                    f"请求体超过上限 {service.max_body_bytes} 字节。",
                    close_connection=self._unread_body > 0,
                )
            body = self.rfile.read(length) if length else b""
            self._unread_body = 0
            try:
                # utf-8-sig：容忍 PowerShell / 记事本等客户端写入的 BOM
                text = body.decode("utf-8-sig").strip()
                return json.loads(text or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _RequestError(400, "invalid_request", f"请求体不是合法 JSON：{exc}") from None

        def _reject(self, error: _RequestError) -> None:
            if error.close_connection:
                self.close_connection = True
            self._fail(error.status, error.code, error.message)

        def _drain_pending_body(self) -> None:
            """有界丢弃尚未读取的请求体。

            先把客户端已经发出的内容读完再回响应，避免它在写入过程中被连接重置；
            总量受「请求体上限 + DRAIN_OVERHEAD_BYTES」约束，超出部分不再读、直接断开。
            """

            allowance = max(
                (service.max_body_bytes + DRAIN_OVERHEAD_BYTES) - getattr(self, "_drained_bytes", 0),
                0,
            )
            remaining = min(getattr(self, "_unread_body", 0), allowance)
            while remaining > 0:
                try:
                    chunk = self.rfile.read(min(65_536, remaining))
                except OSError:  # pragma: no cover - 客户端中断
                    self._unread_body = 0
                    return
                if not chunk:
                    self._unread_body = 0
                    return
                remaining -= len(chunk)
                self._unread_body -= len(chunk)
                self._drained_bytes = getattr(self, "_drained_bytes", 0) + len(chunk)

        def _fail(self, status: int, code: str, message: str) -> None:
            service._bump(f"error_{code}")
            self._respond(status, {"error": {"code": code, "message": message}})

        def _not_found(self, path: str) -> None:
            service._bump("error_not_found")
            self._respond(404, {"error": {"code": "not_found", "message": f"未知路径：{path}"}})

        def _respond(
            self,
            status: int,
            body: Mapping[str, Any] | str,
            *,
            content_type: str = "application/json; charset=utf-8",
            headers: Mapping[str, str] | None = None,
        ) -> None:
            data = (
                body.encode("utf-8")
                if isinstance(body, str)
                else json.dumps(body, ensure_ascii=False).encode("utf-8")
            )
            if getattr(self, "_unread_body", 0) > 0:
                self._drain_pending_body()
            if getattr(self, "_unread_body", 0) > 0:
                # 仍没读完（请求体过大）：回完本次响应后关闭连接，避免残留字节污染后续请求。
                self.close_connection = True
            try:
                self.send_response(status)
                if self.close_connection:
                    # 明确告知客户端本连接将关闭（例如请求体未读完时）
                    self.send_header("Connection", "close")
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD" and data:
                    self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):  # pragma: no cover - 客户端提前断开
                LOGGER.warning("客户端提前断开连接：%s %s", self.command, self.path)

    return ReviewRequestHandler


def build_server(service: ReviewService, *, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """创建（但不启动）HTTP 服务。"""

    server = ThreadingHTTPServer((host, port), make_handler(service))
    server.daemon_threads = True
    server.allow_reuse_address = True
    return server


def start_in_thread(
    service: ReviewService,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """在后台线程启动服务，供 ACPs 模式与测试嵌入。"""

    server = build_server(service, host=host, port=port)
    thread = threading.Thread(target=server.serve_forever, name="csr-http", daemon=True)
    thread.start()
    LOGGER.info("HTTP 服务已启动：http://%s:%s", host, server.server_address[1])
    return server, thread


def serve(
    service: ReviewService,
    *,
    host: str = "0.0.0.0",
    port: int = 8080,
    install_signal_handlers: bool = True,
) -> None:
    """前台运行 HTTP 服务，收到 SIGTERM / SIGINT 时优雅退出。"""

    server = build_server(service, host=host, port=port)
    stop = threading.Event()

    def _request_stop(signum: int, _frame: Any) -> None:
        LOGGER.info("收到信号 %s，准备停止 HTTP 服务。", signum)
        stop.set()

    if install_signal_handlers:
        for name in ("SIGTERM", "SIGINT"):
            handler = getattr(signal, name, None)
            if handler is not None:
                try:
                    signal.signal(handler, _request_stop)
                except ValueError:  # pragma: no cover - 非主线程
                    pass

    thread = threading.Thread(target=server.serve_forever, name="csr-http", daemon=True)
    thread.start()
    LOGGER.info(
        "HTTP 服务已启动：http://%s:%s（鉴权：%s）",
        host,
        server.server_address[1],
        "已启用 Bearer 令牌" if service.auth_token else "未启用，建议仅在受信网络内暴露",
    )
    try:
        while not stop.is_set():
            stop.wait(0.5)
    except KeyboardInterrupt:  # pragma: no cover - 交互式中断
        LOGGER.info("收到键盘中断。")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        LOGGER.info("HTTP 服务已停止。")
