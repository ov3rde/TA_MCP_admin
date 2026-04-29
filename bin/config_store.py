import json
import importlib
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlparse

import requests

APP_ID = "ta_mcp_admin"
SETTINGS_STANZA = "ta_mcp_admin_settings"
LOCAL_SPLUNKD_BASE_URL = "https://127.0.0.1:8089"
DEFAULT_MCP_BASE_URL = LOCAL_SPLUNKD_BASE_URL
DEFAULT_MCP_APP_ID = "Splunk_MCP_Server"
SSL_VERIFY_FIELD = "ssl_verify"
CREDENTIAL_REALM = APP_ID
SPLUNK_MGMT_TOKEN_NAME = "splunk_mgmt_token"
MCP_BEARER_TOKEN_NAME = "mcp_bearer_token"
MCP_TOOL_ADMIN_CAPABILITY = "mcp_tool_admin"
MCP_TOOL_EXECUTE_CAPABILITY = "mcp_tool_execute"

logger = logging.getLogger("splunk.ta_mcp_admin.config")
REQUEST_TIMEOUT = 30


class CurlHTTPError(Exception):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


class BackendConfigError(ValueError):
    pass


class UserCapabilityError(PermissionError):
    pass


def _default_port(parsed) -> int:
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _is_local_backend(base_url: str) -> bool:
    parsed = urlparse(base_url)
    local = urlparse(LOCAL_SPLUNKD_BASE_URL)
    if parsed.scheme not in ("http", "https"):
        return False

    return (
        (parsed.hostname or "").lower() in {"127.0.0.1", "localhost"}
        and _default_port(parsed) == _default_port(local)
    )


def _candidate_backend_bin_dirs(app_id: str) -> List[str]:
    candidates: List[str] = []

    splunk_home = Path(str(os.environ.get("SPLUNK_HOME") or "").strip() or "/opt/splunk")
    candidates.append(str(splunk_home / "etc" / "apps" / app_id / "bin"))

    repo_candidate = (Path(__file__).resolve().parent / ".." / ".." / app_id / "bin").resolve()
    candidates.append(str(repo_candidate))
    return candidates


def _ensure_backend_app_importable(app_id: str) -> None:
    for candidate in _candidate_backend_bin_dirs(app_id):
        if os.path.isdir(candidate):
            if candidate not in sys.path:
                sys.path.insert(0, candidate)
            return
    raise BackendConfigError(
        f"Lokales Backend-App-Verzeichnis fuer '{app_id}' wurde nicht gefunden."
    )


def _load_backend_module(app_id: str, module_name: str):
    _ensure_backend_app_importable(app_id)
    return importlib.import_module(module_name)


def _response_body(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload)
    except Exception:
        return str(payload)


def _is_truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_ssl_verify_setting(value: Any) -> bool:
    if value in (None, ""):
        return True
    return _is_truthy(value)


def _handle_local_response(response: Dict[str, Any]) -> Any:
    status = int(response.get("status", 500))
    payload = response.get("payload")
    if status >= 400:
        raise CurlHTTPError(status, _response_body(payload))
    return payload if payload is not None else {}


def _call_local_mcp_tools_api(
    session_key: str,
    system_session_key: str,
    app_id: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
) -> Any:
    module = _load_backend_module(app_id, "mcp_tools_handler")
    handler = module.MCPToolsRestHandler("", "")
    request = {
        "method": method,
        "query": params or {},
        "session": {"authtoken": session_key},
        "system_authtoken": system_session_key,
    }
    if json_body is not None:
        request["payload"] = json_body
    return _handle_local_response(handler.handle(json.dumps(request)))


def _call_local_mcp_api(
    session_key: str,
    system_session_key: str,
    app_id: str,
    rpc_payload: Dict[str, Any],
) -> Any:
    tool_manager_module = _load_backend_module(app_id, "tool_manager")
    message_module = _load_backend_module(app_id, "mcp_message")
    tool_manager = tool_manager_module.get_default_manager(reload=False)
    handler = message_module.MCPMessageHandler(tool_manager)

    method = str(rpc_payload.get("method") or "").strip()
    rpc_id = rpc_payload.get("id")
    params = rpc_payload.get("params") or {}

    if method == "tools/call":
        status, payload = handler._handle_tools_call(
            rpc_id, params, session_key, system_session_key
        )
    elif method == "tools/list":
        status, payload = handler._handle_tools_list(rpc_id, session_key, system_session_key)
    elif method == "ping":
        status, payload = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {}}
    else:
        raise BackendConfigError(f"Lokaler MCP-RPC-Call '{method}' wird nicht unterstuetzt.")

    return _handle_local_response({"status": status, "payload": payload})


def _settings_endpoint(stanza: str = SETTINGS_STANZA) -> str:
    return f"/servicesNS/nobody/{APP_ID}/configs/conf-app/{stanza}"


def _settings_collection_endpoint() -> str:
    return f"/servicesNS/nobody/{APP_ID}/configs/conf-app"


def _passwords_endpoint() -> str:
    return f"/servicesNS/nobody/{APP_ID}/storage/passwords"


def _app_endpoint() -> str:
    return f"/services/apps/local/{APP_ID}"


def _resolve_system_session_key(
    session_key: str, system_session_key: Optional[str] = None
) -> str:
    return (system_session_key or session_key or "").strip()


def list_installed_app_ids(
    session_key: str, system_session_key: Optional[str] = None
) -> List[str]:
    payload = _local_request(
        "/services/apps/local",
        _resolve_system_session_key(session_key, system_session_key),
        params={"output_mode": "json", "count": 0},
    )

    app_ids = []
    seen = set()
    for entry in payload.get("entry", []):
        if not isinstance(entry, dict):
            continue
        app_id = str(entry.get("name") or "").strip()
        if app_id and app_id not in seen:
            seen.add(app_id)
            app_ids.append(app_id)

    app_ids.sort(key=str.lower)
    return app_ids


def _perform_request(
    url: str,
    method: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    verify: bool = True,
) -> requests.Response:
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_body,
            verify=verify,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"requests failed: {exc}") from exc
    return response


def _local_request(
    path: str,
    session_key: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = LOCAL_SPLUNKD_BASE_URL + path

    response = _perform_request(
        url=url,
        method=method,
        headers={"Authorization": f"Splunk {session_key}"},
        params=params,
        data=data,
        verify=False,
    )
    payload = response.text or ""
    if response.status_code >= 400:
        raise CurlHTTPError(response.status_code, payload)
    return json.loads(payload) if payload else {}


def _external_request(
    base_url: str,
    path: str,
    token: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    ssl_verify: bool = True,
) -> Any:
    url = base_url.rstrip("/") + path
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    response = _perform_request(
        url=url,
        method=method,
        headers=headers,
        params=params,
        json_body=json_body,
        verify=ssl_verify,
    )
    payload = response.text or ""
    if response.status_code >= 400:
        raise CurlHTTPError(response.status_code, payload)

    if not payload.strip():
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": payload}


def validate_base_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        raise ValueError("MCP-Base-URL ist erforderlich.")

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("MCP-Base-URL muss mit http:// oder https:// beginnen.")

    return value.rstrip("/")


def validate_app_id(app_id: str) -> str:
    value = (app_id or "").strip()
    if not value:
        raise ValueError("MCP-App-ID ist erforderlich.")
    return value


def _credential_entry_name(credential_name: str) -> str:
    return f"{CREDENTIAL_REALM}:{credential_name}:"


def _secret_suppression_field(credential_name: str) -> str:
    return f"{credential_name}_suppressed"

def _is_secret_suppressed(
    settings_content: Optional[Dict[str, Any]], credential_name: str
) -> bool:
    if not settings_content:
        return False
    return _is_truthy(settings_content.get(_secret_suppression_field(credential_name)))


def _extract_error_payload(body: str) -> Tuple[Optional[str], Optional[str]]:
    raw_body = (body or "").strip()
    if not raw_body:
        return None, None

    try:
        payload = json.loads(raw_body)
    except Exception:
        return raw_body, None

    if not isinstance(payload, dict):
        return raw_body, None

    message = str(payload.get("message") or payload.get("error") or raw_body).strip() or None
    code = str(payload.get("code") or "").strip() or None
    return message, code


def error_message_from_http_error(exc: CurlHTTPError, default: str) -> str:
    message, _ = _extract_error_payload(exc.body)
    return message or default


def error_code_from_http_error(exc: CurlHTTPError, default: str) -> str:
    _, code = _extract_error_payload(exc.body)
    return code or default


def get_user_context(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise UserCapabilityError("A valid user session is required.")

    try:
        payload = _local_request(
            "/services/authentication/current-context",
            session_key,
            params={"output_mode": "json"},
        )
    except CurlHTTPError as exc:
        if exc.status in {401, 403}:
            raise UserCapabilityError("The current Splunk session is not authorized.") from exc
        raise

    entries = payload.get("entry", [])
    if not entries:
        raise UserCapabilityError("Unable to load the current Splunk user context.")

    content = entries[0].get("content", {}) or {}
    return {
        "username": content.get("username") or "",
        "email": content.get("email") or "",
        "realname": content.get("realname") or "",
        "roles": content.get("roles") or [],
        "capabilities": content.get("capabilities") or [],
    }


def require_user_capabilities(
    session_key: str,
    required_capabilities: Sequence[str],
) -> Dict[str, Any]:
    context = get_user_context(session_key)
    capabilities = set(context.get("capabilities") or [])
    for capability in required_capabilities:
        if capability not in capabilities:
            raise UserCapabilityError(f"Missing required capability: {capability}")
    return context


def _get_password_entry(session_key: str, credential_name: str) -> Optional[Dict[str, Any]]:
    entry_name = quote(_credential_entry_name(credential_name), safe="")
    try:
        payload = _local_request(
            f"{_passwords_endpoint()}/{entry_name}",
            session_key,
            params={"output_mode": "json"},
        )
    except CurlHTTPError as exc:
        if exc.status == 404:
            return None
        raise
    except Exception as exc:
        logger.warning("Could not read storage/passwords entry for %s: %s", credential_name, exc)
        return None

    entries = payload.get("entry", [])
    if not entries:
        return None
    return entries[0]


def _get_secret(session_key: str, credential_name: str) -> str:
    entry = _get_password_entry(session_key, credential_name)
    if not entry:
        return ""
    content = entry.get("content", {})
    return content.get("clear_password") or ""


def _get_effective_secret(
    session_key: str,
    credential_name: str,
    settings_content: Optional[Dict[str, Any]] = None,
) -> str:
    content = settings_content if settings_content is not None else _get_settings_content(session_key)
    if _is_secret_suppressed(content, credential_name):
        return ""
    return _get_secret(session_key, credential_name)


def _save_secret(session_key: str, credential_name: str, value: str) -> None:
    secret = (value or "").strip()
    if not secret:
        raise ValueError("Secret darf nicht leer sein.")

    existing = _get_password_entry(session_key, credential_name)
    if existing:
        key_name = quote(existing.get("name", _credential_entry_name(credential_name)), safe="")
        _local_request(
            f"{_passwords_endpoint()}/{key_name}",
            session_key,
            method="POST",
            params={"output_mode": "json"},
            data={"password": secret},
        )
        return

    _local_request(
        _passwords_endpoint(),
        session_key,
        method="POST",
        params={"output_mode": "json"},
        data={
            "name": credential_name,
            "realm": CREDENTIAL_REALM,
            "password": secret,
        },
    )


def _delete_secret(session_key: str, credential_name: str) -> None:
    existing = _get_password_entry(session_key, credential_name)
    if not existing:
        return

    key_name = quote(existing.get("name", _credential_entry_name(credential_name)), safe="")
    try:
        _local_request(
            f"{_passwords_endpoint()}/{key_name}",
            session_key,
            method="DELETE",
            params={"output_mode": "json"},
        )
    except CurlHTTPError as exc:
        if exc.status == 404:
            return
        if exc.status == 500 and "ConfPathMapper" in exc.body:
            logger.warning(
                "Could not delete storage/passwords entry for %s because Splunk reported "
                "a ConfPathMapper/local-meta error. The secret will stay suppressed at the "
                "app layer until a new value is saved. Response: %s",
                credential_name,
                exc.body,
            )
            return
        raise


def _get_settings_content(session_key: str) -> Dict[str, Any]:
    try:
        payload = _local_request(_settings_endpoint(), session_key, params={"output_mode": "json"})
    except Exception as exc:
        logger.warning("Could not read app config stanza: %s", exc)
        return {}

    entry = payload.get("entry", [])
    if not entry:
        return {}
    return entry[0].get("content", {}) or {}


def save_app_settings(
    session_key: str,
    system_session_key: Optional[str],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    base_url = validate_base_url(settings.get("mcp_base_url") or DEFAULT_MCP_BASE_URL)
    app_id = validate_app_id(settings.get("mcp_app_id") or DEFAULT_MCP_APP_ID)
    ssl_verify = _normalize_ssl_verify_setting(settings.get(SSL_VERIFY_FIELD))
    current_content = _get_settings_content(storage_session_key)
    settings_payload: Dict[str, str] = {
        "mcp_base_url": base_url,
        "mcp_app_id": app_id,
        SSL_VERIFY_FIELD: "1" if ssl_verify else "0",
    }

    for credential_name, input_key in (
        (SPLUNK_MGMT_TOKEN_NAME, "splunk_mgmt_token"),
        (MCP_BEARER_TOKEN_NAME, "mcp_bearer_token"),
    ):
        suppression_field = _secret_suppression_field(credential_name)
        token_value = (settings.get(input_key) or "").strip()
        if token_value:
            settings_payload[suppression_field] = "0"
        elif suppression_field in current_content:
            settings_payload[suppression_field] = str(current_content.get(suppression_field) or "0")

    try:
        _local_request(
            _settings_endpoint(),
            storage_session_key,
            method="POST",
            params={"output_mode": "json"},
            data=settings_payload,
        )
    except CurlHTTPError as exc:
        if exc.status != 404:
            raise
        _local_request(
            _settings_collection_endpoint(),
            storage_session_key,
            method="POST",
            params={"output_mode": "json"},
            data={"name": SETTINGS_STANZA, **settings_payload},
        )

    if settings.get("splunk_mgmt_token"):
        _save_secret(
            storage_session_key, SPLUNK_MGMT_TOKEN_NAME, settings["splunk_mgmt_token"]
        )
    if settings.get("mcp_bearer_token"):
        _save_secret(
            storage_session_key, MCP_BEARER_TOKEN_NAME, settings["mcp_bearer_token"]
        )

    _local_request(
        _app_endpoint(),
        storage_session_key,
        method="POST",
        params={"output_mode": "json"},
        data={"configured": 1},
    )

    return get_admin_settings(session_key, storage_session_key)


def reset_app_settings(session_key: str, system_session_key: Optional[str]) -> Dict[str, Any]:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    for credential_name in (SPLUNK_MGMT_TOKEN_NAME, MCP_BEARER_TOKEN_NAME):
        _delete_secret(storage_session_key, credential_name)

    reset_payload = {
        "mcp_base_url": DEFAULT_MCP_BASE_URL,
        "mcp_app_id": DEFAULT_MCP_APP_ID,
        SSL_VERIFY_FIELD: "1",
        _secret_suppression_field(SPLUNK_MGMT_TOKEN_NAME): "1",
        _secret_suppression_field(MCP_BEARER_TOKEN_NAME): "1",
    }

    try:
        _local_request(
            _settings_endpoint(),
            storage_session_key,
            method="POST",
            params={"output_mode": "json"},
            data=reset_payload,
        )
    except CurlHTTPError as exc:
        if exc.status != 404:
            raise
        _local_request(
            _settings_collection_endpoint(),
            storage_session_key,
            method="POST",
            params={"output_mode": "json"},
            data={"name": SETTINGS_STANZA, **reset_payload},
        )

    # Keep the Splunk app itself in the configured state so users stay inside
    # the app and are redirected to the React setup view instead of the generic
    # Splunk setup gate.
    _local_request(
        _app_endpoint(),
        storage_session_key,
        method="POST",
        params={"output_mode": "json"},
        data={"configured": 1},
    )

    return get_admin_settings(session_key, storage_session_key)


def get_admin_settings(session_key: str, system_session_key: Optional[str] = None) -> Dict[str, Any]:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    content = _get_settings_content(storage_session_key)
    settings = {
        "mcp_base_url": content.get("mcp_base_url") or DEFAULT_MCP_BASE_URL,
        "mcp_app_id": content.get("mcp_app_id") or DEFAULT_MCP_APP_ID,
        "ssl_verify": _normalize_ssl_verify_setting(content.get(SSL_VERIFY_FIELD)),
        "splunk_mgmt_token_configured": bool(
            _get_effective_secret(storage_session_key, SPLUNK_MGMT_TOKEN_NAME, content)
        ),
        "mcp_bearer_token_configured": bool(
            _get_effective_secret(storage_session_key, MCP_BEARER_TOKEN_NAME, content)
        ),
    }
    settings.update(_get_backend_health(session_key, storage_session_key, settings))
    return settings


def _get_backend_health(
    session_key: str,
    system_session_key: str,
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    base_url = settings.get("mcp_base_url") or DEFAULT_MCP_BASE_URL
    app_id = settings.get("mcp_app_id") or DEFAULT_MCP_APP_ID
    mgmt_ready = bool(settings.get("splunk_mgmt_token_configured"))
    mcp_ready = bool(settings.get("mcp_bearer_token_configured"))

    health = {
        "backend_mode": "local" if _is_local_backend(base_url) else "remote",
        "backend_connection_ok": False,
    }

    try:
        if health["backend_mode"] == "local":
            _call_local_mcp_tools_api(
                session_key,
                system_session_key,
                app_id,
                method="GET",
                params={"output_mode": "json"},
            )
            health["backend_connection_ok"] = True
            return health

        if not mgmt_ready or not mcp_ready:
            return health

        _external_request(
            base_url,
            "/services/mcp_tools",
            _get_secret(system_session_key, SPLUNK_MGMT_TOKEN_NAME),
            method="GET",
            params={"output_mode": "json"},
        )
        health["backend_connection_ok"] = True
        return health
    except Exception as exc:
        logger.warning(
            "Backend reachability check failed for app_id=%s base_url=%s: %s",
            app_id,
            base_url,
            exc,
        )
        return health


def get_runtime_backend_config(
    session_key: str, system_session_key: Optional[str] = None
) -> Dict[str, Any]:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    settings = get_admin_settings(session_key, storage_session_key)
    settings_content = _get_settings_content(storage_session_key)
    base_url = settings["mcp_base_url"]
    app_id = settings["mcp_app_id"]

    if _is_local_backend(base_url):
        return {
            "mode": "local",
            "mcp_base_url": base_url,
            "mcp_app_id": app_id,
        }

    mgmt_token = _get_effective_secret(
        storage_session_key, SPLUNK_MGMT_TOKEN_NAME, settings_content
    )
    mcp_bearer_token = _get_effective_secret(
        storage_session_key, MCP_BEARER_TOKEN_NAME, settings_content
    )

    if not mgmt_token:
        raise BackendConfigError("Splunk-Management-Token ist nicht konfiguriert.")
    if not mcp_bearer_token:
        raise BackendConfigError("MCP-Bearer-Token ist nicht konfiguriert.")

    return {
        "mode": "remote",
        "mcp_base_url": base_url,
        "mcp_app_id": app_id,
        "ssl_verify": bool(settings.get("ssl_verify", True)),
        "splunk_mgmt_token": mgmt_token,
        "mcp_bearer_token": mcp_bearer_token,
    }


def call_mcp_tools_api(
    session_key: str,
    system_session_key: Optional[str] = None,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
) -> Any:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    config = get_runtime_backend_config(session_key, storage_session_key)
    if config.get("mode") == "local":
        return _call_local_mcp_tools_api(
            session_key,
            storage_session_key,
            config["mcp_app_id"],
            method=method,
            params=params,
            json_body=json_body,
        )
    return _external_request(
        config["mcp_base_url"],
        "/services/mcp_tools",
        config["splunk_mgmt_token"],
        method=method,
        params=params,
        json_body=json_body,
        ssl_verify=bool(config.get("ssl_verify", True)),
    )


def call_mcp_api(session_key: str, rpc_payload: Dict[str, Any]) -> Any:
    return call_mcp_api_with_system(session_key, None, rpc_payload)


def call_mcp_api_with_system(
    session_key: str,
    system_session_key: Optional[str],
    rpc_payload: Dict[str, Any],
) -> Any:
    storage_session_key = _resolve_system_session_key(session_key, system_session_key)
    config = get_runtime_backend_config(session_key, storage_session_key)
    if config.get("mode") == "local":
        return _call_local_mcp_api(
            session_key,
            storage_session_key,
            config["mcp_app_id"],
            rpc_payload,
        )
    return _external_request(
        config["mcp_base_url"],
        "/services/mcp",
        config["mcp_bearer_token"],
        method="POST",
        json_body=rpc_payload,
        ssl_verify=bool(config.get("ssl_verify", True)),
    )


def is_user_admin(username: str, session_key: str) -> bool:
    if not session_key:
        return False
    try:
        require_user_capabilities(session_key, [MCP_TOOL_ADMIN_CAPABILITY])
    except UserCapabilityError:
        return False
    return True
