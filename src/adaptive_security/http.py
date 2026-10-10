from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_ALERT_BYTES = 1024 * 1024
MAX_TOOL_REQUEST_BYTES = 32 * 1024


class AlertBodyLimit:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or (scope["path"] != "/v1/events/wazuh"
                and not scope["path"].startswith("/v1/investigation-tools/"))
        ):
            await self.app(scope, receive, send)
            return

        tool_request = scope["path"].startswith("/v1/investigation-tools/")
        limit = MAX_TOOL_REQUEST_BYTES if tool_request else MAX_ALERT_BYTES
        detail = "Tool request exceeds 32 KiB" if tool_request else "Alert exceeds 1 MiB"

        async def reject() -> None:
            response = JSONResponse({"detail": detail}, status_code=413)
            await response(scope, receive, send)

        headers = dict(scope["headers"])
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > limit:
                    await reject()
                    return
            except ValueError:
                pass

        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                await reject()
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
