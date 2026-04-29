import json
import os
import sys
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(__file__))

from splunk.persistconn.application import PersistentServerConnectionApplication

import logging
import config_store
from handler_utils import build_json_error, build_json_response, require_request_capabilities

logger = logging.getLogger("splunk.ta_mcp_admin.settings")


class AdminSettingsHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
            method = request.get("method", "GET").upper()
            if method == "GET":
                return self._handle_get(request)
            if method == "POST":
                return self._handle_post(request)
            if method == "DELETE":
                return self._handle_delete(request)
            return build_json_error(405, "Method not allowed", code="method_not_allowed")
        except PermissionError as exc:
            return build_json_error(403, str(exc), code="forbidden")
        except ValueError as exc:
            return build_json_error(422, str(exc), code="validation_error")
        except config_store.CurlHTTPError as exc:
            logger.warning("Settings backend request failed: %s", exc)
            return build_json_error(
                exc.status if exc.status >= 400 else 502,
                config_store.error_message_from_http_error(exc, "Settings request failed."),
                code=config_store.error_code_from_http_error(exc, "backend_request_failed"),
            )
        except Exception as exc:
            logger.error("Unhandled error in AdminSettingsHandler: %s", exc, exc_info=True)
            return build_json_error(500, "Internal server error.", code="internal_error")

    def _handle_get(self, request):
        username, session_key, system_session_key = self._require_admin(request)
        logger.info("Serving settings to user=%s", username)
        return build_json_response(
            200,
            {
                "status": "ok",
                "data": config_store.get_admin_settings(session_key, system_session_key),
            },
        )

    def _handle_post(self, request):
        username, session_key, system_session_key = self._require_admin(request)
        payload = self._parse_body(request)
        if isinstance(payload, dict) and "error" in payload:
            return build_json_error(400, payload["error"], code="invalid_payload")

        if payload.get("action") == "reset":
            reset = config_store.reset_app_settings(session_key, system_session_key)
            logger.info("Reset settings by user=%s", username)
            return build_json_response(
                200,
                {
                    "status": "ok",
                    "message": "Setup reset.",
                    "data": reset,
                },
            )

        saved = config_store.save_app_settings(
            session_key,
            system_session_key,
            {
                "mcp_base_url": payload.get("mcp_base_url", ""),
                "mcp_app_id": payload.get("mcp_app_id", ""),
                "ssl_verify": payload.get("ssl_verify", ""),
                "splunk_mgmt_token": payload.get("splunk_mgmt_token", ""),
                "mcp_bearer_token": payload.get("mcp_bearer_token", ""),
            },
        )

        logger.info("Updated settings by user=%s", username)
        return build_json_response(
            200,
            {
                "status": "ok",
                "message": "Settings saved.",
                "data": saved,
            },
        )

    def _handle_delete(self, request):
        username, session_key, system_session_key = self._require_admin(request)
        reset = config_store.reset_app_settings(session_key, system_session_key)
        logger.info("Reset settings by user=%s", username)
        return build_json_response(
            200,
            {
                "status": "ok",
                "message": "Setup reset.",
                "data": reset,
            },
        )

    def _require_admin(self, request):
        username, session_key, system_session_key, _ = require_request_capabilities(
            request,
            [config_store.MCP_TOOL_ADMIN_CAPABILITY],
        )
        return username, session_key, system_session_key

    def _parse_body(self, request):
        body = request.get("payload") or request.get("body") or ""
        if not body:
            return {"error": "Empty request body"}
        if isinstance(body, list):
            result = {}
            for item in body:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    result[item[0]] = item[1]
            return result
        if isinstance(body, dict):
            return body
        if isinstance(body, str):
            body = body.strip()
            if not body:
                return {"error": "Empty request body"}
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                form = parse_qs(body, keep_blank_values=True)
                if form:
                    return {
                        key: values[-1] if isinstance(values, list) and values else ""
                        for key, values in form.items()
                    }
        return {"error": "Invalid JSON data in request body"}
