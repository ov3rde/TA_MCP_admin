import json
from typing import Any, Dict, Sequence, Tuple

import config_store


def build_json_response(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "payload": json.dumps(payload),
        "status": status,
        "headers": {"Content-Type": "application/json"},
    }


def build_json_error(status: int, message: str, code: str = "") -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "status": "error",
        "error": True,
        "message": message,
    }
    if code:
        payload["code"] = code
    return build_json_response(status, payload)


def require_request_capabilities(
    request: Dict[str, Any],
    capabilities: Sequence[str],
) -> Tuple[str, str, str, Dict[str, Any]]:
    session_info = request.get("session", {})
    session_key = session_info.get("authtoken", "")
    system_session_key = (
        request.get("system_authtoken") or request.get("systemAuthtoken") or session_key
    )
    context = config_store.require_user_capabilities(session_key, capabilities)
    username = context.get("username") or session_info.get("user") or ""
    return username, session_key, system_session_key, context
