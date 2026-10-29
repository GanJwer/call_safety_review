from types import SimpleNamespace
import unittest

from call_safety_review.amp_observability import TaskCorrelatedAmpAccessHooks


class _FakeAmp:
    def __init__(self) -> None:
        self.calls = []

    async def emit_access(self, body, **record_fields):
        self.calls.append((body, record_fields))
        return "log-test"


class _FakeRuntime:
    def __init__(self) -> None:
        self.amp = _FakeAmp()


class TaskCorrelatedAmpAccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_partner_request_uses_task_id_and_protocol_identities(self) -> None:
        runtime = _FakeRuntime()
        hook = TaskCorrelatedAmpAccessHooks()
        hook.bind_runtime(runtime)

        event = SimpleNamespace(
            task_id="task-amp-test-01",
            session_id="session-amp-test-01",
            command_id="command-amp-test-01",
            leader_aic="leader-aic",
            partner_aic="partner-aic",
            delivery="rpc",
        )

        await hook.on_partner_request(event)

        self.assertEqual(len(runtime.amp.calls), 1)
        body, record_fields = runtime.amp.calls[0]
        self.assertEqual(record_fields["correlation_id"], event.task_id)
        self.assertEqual(body.caller.aic, event.leader_aic)
        self.assertEqual(body.callee.aic, event.partner_aic)
        self.assertEqual(body.request.route, "acps.direct.rpc")
        self.assertEqual(body.response.status_code, 200)
