"""以 AIP 业务任务身份生成可关联的 AMP Access 记录。"""

from __future__ import annotations

import logging
from typing import Any

from acps_sdk.amp import AccessBody, AccessParticipant, AccessRequest, AccessResponse
from wit.hooks.acps.partner_transform import (
    AipPartnerRequestEvent,
    AipPartnerTransformHooks,
)

_logger = logging.getLogger(__name__)


class TaskCorrelatedAmpAccessHooks(AipPartnerTransformHooks):
    """为每次进入 Partner 的业务命令记录 taskId 关联的 Access。"""

    id = "content-safety-precheck.amp.task-access"
    priority = 100

    def __init__(self) -> None:
        self._runtime: Any | None = None

    def bind_runtime(self, runtime: Any) -> None:
        self._runtime = runtime

    async def on_partner_request(self, event: AipPartnerRequestEvent) -> None:
        runtime = self._runtime
        if runtime is None:
            _logger.error(
                "Task-correlated AMP Access hook is not bound; task_id=%s",
                event.task_id,
            )
            return

        try:
            await runtime.amp.emit_access(
                AccessBody(
                    request=AccessRequest(
                        method="POST",
                        route=f"acps.direct.{event.delivery}",
                    ),
                    response=AccessResponse(statusCode=200),
                    caller=AccessParticipant(aic=event.leader_aic),
                    callee=AccessParticipant(aic=event.partner_aic),
                ),
                correlation_id=event.task_id,
                attributes={
                    "acps.session_id": event.session_id,
                    "acps.command_id": event.command_id,
                    "acps.delivery": event.delivery,
                },
            )
        except Exception:
            _logger.exception(
                "Task-correlated AMP Access recording failed; task_id=%s",
                event.task_id,
            )
