import json
import os
import re
import sys
from copy import deepcopy
from typing import Any, Dict, List
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(__file__))

from splunk.persistconn.application import PersistentServerConnectionApplication

import config_store
from handler_utils import build_json_response, require_request_capabilities


TOP_LEVEL_IMPORT_FIELDS = {
    "tool_id",
    "name",
    "title",
    "description",
    "external_app_id",
    "execution_type",
    "template",
    "row_limiter",
    "time_range",
    "guardrails",
    "tags",
    "examples",
    "properties",
    "enabled",
}

EXAMPLE_IMPORT_FIELDS = {"name", "description", "expected_use", "arguments"}
PROPERTY_IMPORT_FIELDS = {
    "key",
    "type",
    "description",
    "required",
    "default",
    "enum",
    "minimum",
    "maximum",
    "pattern",
    "validation_message",
}
SUPPORTED_PROPERTY_TYPES = {"string", "number", "integer", "boolean"}
STANDARD_PROPERTY_KEYS = {"row_limit", "earliest_time", "latest_time"}


class ToolsAdminHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
            method = request.get("method", "GET").upper()
            if method == "GET":
                return self._build_response(*self._handle_get(request))
            if method == "POST":
                return self._build_response(*self._handle_post(request))
            if method == "PUT":
                return self._build_response(*self._handle_put(request))
            if method == "DELETE":
                return self._build_response(*self._handle_delete(request))
            return self._build_response(
                405,
                {"error": True, "code": "method_not_allowed", "message": "Method not allowed"},
            )
        except PermissionError as exc:
            return self._build_response(
                403, {"error": True, "code": "forbidden", "message": str(exc)}
            )
        except ValueError as exc:
            return self._build_response(
                422, {"error": True, "code": "validation_error", "message": str(exc)}
            )
        except config_store.CurlHTTPError as exc:
            return self._build_response(
                exc.status if exc.status >= 400 else 502,
                {
                    "error": True,
                    "code": config_store.error_code_from_http_error(exc, "backend_request_failed"),
                    "message": config_store.error_message_from_http_error(
                        exc, "Backend request failed."
                    ),
                },
            )
        except Exception as exc:
            return self._build_response(
                500,
                {"error": True, "code": "internal_error", "message": "Internal server error."},
            )

    def _handle_get(self, request):
        session_key, system_session_key, _ = self._require_admin_session(request)
        query = self._normalize_query(request.get("query"))
        if self._is_truthy(query.get("llm_preview")):
            return self._handle_llm_preview_get(session_key, system_session_key)
        tool_id = query.get("tool_id")

        if tool_id:
            tool_response = config_store.call_mcp_tools_api(
                session_key,
                system_session_key,
                method="GET",
                params={"tool_id": tool_id, "output_mode": "json"},
            )
            tool = tool_response.get("tool")
            if not isinstance(tool, dict):
                return 404, {
                    "error": True,
                    "code": "tool_not_found",
                    "message": f"Tool '{tool_id}' not found.",
                }
            enabled_names = self._fetch_enabled_names(session_key, system_session_key)
            return 200, {
                "status": "ok",
                "tool": self._build_tool_detail(tool, tool.get("name") in enabled_names),
            }

        tool_response = config_store.call_mcp_tools_api(
            session_key, system_session_key, method="GET", params={"output_mode": "json"}
        )
        enabled_names = self._fetch_enabled_names(session_key, system_session_key)
        tools = tool_response.get("tools", [])
        summaries = [
            self._build_tool_summary(tool, tool.get("name") in enabled_names)
            for tool in tools
            if isinstance(tool, dict)
        ]
        summaries.sort(key=lambda item: (item["built_in"], item["title"].lower(), item["name"].lower()))
        return 200, {
            "status": "ok",
            "tools": summaries,
            "total": len(summaries),
            "app_ids": self._fetch_installed_app_ids(session_key, system_session_key),
        }

    def _handle_llm_preview_get(self, session_key, system_session_key):
        tool_response = config_store.call_mcp_tools_api(
            session_key, system_session_key, method="GET", params={"output_mode": "json"}
        )
        tools = tool_response.get("tools", [])
        tools_by_name = {}
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = str(tool.get("name") or "").strip()
            if tool_name and tool_name not in tools_by_name:
                tools_by_name[tool_name] = tool

        rpc_response = config_store.call_mcp_api_with_system(
            session_key,
            system_session_key,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            },
        )

        if isinstance(rpc_response, dict) and isinstance(rpc_response.get("error"), dict):
            raise ValueError(
                rpc_response["error"].get("message") or "Unable to load MCP tools list."
            )

        public_tools = ((rpc_response or {}).get("result") or {}).get("tools") or []
        llm_tools = []
        llm_payload_tools = []
        for public_tool in public_tools:
            if not isinstance(public_tool, dict):
                continue
            public_name = str(public_tool.get("name") or "").strip()
            if not public_name:
                continue
            llm_public = self._public_tool_payload(public_tool)
            matched_tool = tools_by_name.get(public_name)
            if matched_tool:
                summary = self._build_tool_summary(matched_tool, True)
            else:
                summary = self._build_llm_preview_fallback(public_tool)
            summary["llm_public"] = llm_public
            llm_tools.append(summary)
            llm_payload_tools.append(llm_public)
        return 200, {
            "status": "ok",
            "llm_tools": llm_tools,
            "llm_payload": {"tools": llm_payload_tools},
            "total": len(llm_tools),
        }

    def _handle_post(self, request):
        session_key, system_session_key, _ = self._require_admin_session(request)
        payload = self._parse_payload(request)
        action = payload.get("action")

        if action == "test":
            return self._handle_test(session_key, system_session_key, payload)
        if action == "enable":
            return self._handle_enable(session_key, system_session_key, payload, True)
        if action == "disable":
            return self._handle_enable(session_key, system_session_key, payload, False)
        if action == "export":
            return self._handle_export(session_key, system_session_key, payload)
        if action == "import_preview":
            return self._handle_import_preview(session_key, system_session_key, payload)
        if action == "import":
            return self._handle_import(session_key, system_session_key, payload)

        normalized_payload, desired_enabled = self._normalize_editor_payload(payload, create_mode=True)
        create_response = config_store.call_mcp_tools_api(
            session_key, system_session_key, method="POST", json_body=normalized_payload
        )
        tool_id = create_response.get("tool_id")
        if not isinstance(tool_id, str) or not tool_id:
            raise ValueError("Backend did not return a tool_id for the new tool.")

        tool_response = config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="GET",
            params={"tool_id": tool_id, "output_mode": "json"},
        )
        tool = tool_response.get("tool")
        if desired_enabled:
            self._toggle_tool(session_key, system_session_key, tool_id, tool.get("name"), True)
        enabled_names = self._fetch_enabled_names(session_key, system_session_key)
        return 201, {
            "status": "ok",
            "message": "Tool created successfully.",
            "tool": self._build_tool_detail(tool, tool.get("name") in enabled_names),
            "normalized_payload": normalized_payload,
        }

    def _handle_put(self, request):
        session_key, system_session_key, _ = self._require_admin_session(request)
        payload = self._parse_payload(request)
        tool_id = payload.get("tool_id")
        current_enabled = bool(payload.get("current_enabled"))
        if not isinstance(tool_id, str) or not tool_id.strip():
            raise ValueError("tool_id is required.")

        existing_response = config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="GET",
            params={"tool_id": tool_id, "output_mode": "json"},
        )
        existing_tool = existing_response.get("tool")
        if not isinstance(existing_tool, dict):
            raise ValueError("Existing tool could not be loaded.")

        normalized_payload, desired_enabled = self._normalize_editor_payload(
            payload, create_mode=False, existing_tool=existing_tool
        )
        update_body = {"tool_id": tool_id}
        update_body.update(normalized_payload)
        config_store.call_mcp_tools_api(
            session_key, system_session_key, method="PUT", json_body=update_body
        )

        if desired_enabled != current_enabled:
            self._toggle_tool(
                session_key,
                system_session_key,
                tool_id,
                existing_tool.get("name"),
                desired_enabled,
            )

        refreshed = config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="GET",
            params={"tool_id": tool_id, "output_mode": "json"},
        )
        tool = refreshed.get("tool")
        enabled_names = self._fetch_enabled_names(session_key, system_session_key)
        return 200, {
            "status": "ok",
            "message": "Tool updated successfully.",
            "tool": self._build_tool_detail(tool, tool.get("name") in enabled_names),
            "normalized_payload": normalized_payload,
        }

    def _handle_delete(self, request):
        session_key, system_session_key, _ = self._require_admin_session(request)
        payload = self._parse_payload(request)
        tool_id = payload.get("tool_id")
        tool_name = payload.get("tool_name")
        if not isinstance(tool_id, str) or not tool_id.strip():
            raise ValueError("tool_id is required.")

        if isinstance(tool_name, str) and tool_name.strip():
            try:
                self._toggle_tool(session_key, system_session_key, tool_id, tool_name, False)
            except Exception:
                pass

        config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="DELETE",
            json_body={"tool_id": tool_id},
        )
        return 200, {"status": "ok", "message": "Tool deleted successfully.", "tool_id": tool_id}

    def _handle_enable(self, session_key, system_session_key, payload, enabled):
        tool_id = payload.get("tool_id")
        tool_name = payload.get("tool_name")
        if not isinstance(tool_id, str) or not tool_id.strip():
            raise ValueError("tool_id is required.")
        if not isinstance(tool_name, str) or not tool_name.strip():
            detail = config_store.call_mcp_tools_api(
                session_key,
                system_session_key,
                method="GET",
                params={"tool_id": tool_id, "output_mode": "json"},
            )
            tool = detail.get("tool")
            tool_name = tool.get("name") if isinstance(tool, dict) else ""
        if not tool_name:
            raise ValueError("tool_name is required.")

        self._toggle_tool(session_key, system_session_key, tool_id, tool_name, enabled)
        return 200, {
            "status": "ok",
            "tool_id": tool_id,
            "tool_name": tool_name,
            "enabled": enabled,
            "message": "Tool enabled successfully." if enabled else "Tool disabled successfully.",
        }

    def _handle_test(self, session_key, system_session_key, payload):
        tool_name = payload.get("tool_name")
        arguments = payload.get("arguments") or {}
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name is required.")
        if not isinstance(arguments, dict):
            raise ValueError("arguments must be an object.")

        config_store.require_user_capabilities(
            session_key,
            [config_store.MCP_TOOL_EXECUTE_CAPABILITY],
        )

        rpc_response = config_store.call_mcp_api_with_system(
            session_key,
            system_session_key,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            },
        )

        summary = "Tool test completed."
        if isinstance(rpc_response, dict):
            if rpc_response.get("error"):
                summary = rpc_response["error"].get("message") or "Tool test failed."
            else:
                content = ((rpc_response.get("result") or {}).get("content") or [])
                if content and isinstance(content[0], dict):
                    summary = content[0].get("text") or summary

        return 200, {
            "status": "ok",
            "tool_name": tool_name,
            "arguments": arguments,
            "summary": summary,
            "mcp_response": rpc_response,
        }

    def _handle_export(self, session_key, system_session_key, payload):
        tool_id = str(payload.get("tool_id") or "").strip()
        if not tool_id:
            raise ValueError("tool_id ist erforderlich.")

        tool = self._load_tool(session_key, system_session_key, tool_id)
        detail = self._build_tool_detail(
            tool, tool.get("name") in self._fetch_enabled_names(session_key, system_session_key)
        )
        if detail.get("built_in"):
            raise ValueError("Built-in tools cannot be exported.")
        if detail.get("execution_type") != "spl":
            raise ValueError("Nur SPL-Tools koennen exportiert werden.")

        export_payload = self._build_export_payload(tool, detail.get("enabled"))
        filename = self._build_export_filename(export_payload)
        return 200, {
            "status": "ok",
            "message": "Tool exported.",
            "filename": filename,
            "export_payload": export_payload,
        }

    def _handle_import_preview(self, session_key, system_session_key, payload):
        import_payload = self._parse_import_payload(payload.get("raw_json"))
        normalized_payload, desired_enabled = self._normalize_editor_payload(
            import_payload, create_mode=True
        )
        conflict = self._find_import_conflict(session_key, system_session_key, import_payload)
        return 200, {
            "status": "ok",
            "message": "Import JSON is valid.",
            "import_payload": import_payload,
            "normalized_payload": normalized_payload,
            "enabled": desired_enabled,
            "conflict": self._serialize_conflict(conflict),
        }

    def _handle_import(self, session_key, system_session_key, payload):
        overwrite = bool(payload.get("overwrite"))
        import_payload = self._parse_import_payload(payload.get("raw_json"))
        normalized_payload, desired_enabled = self._normalize_editor_payload(
            import_payload, create_mode=True
        )
        conflict = self._find_import_conflict(session_key, system_session_key, import_payload)

        if conflict:
            if conflict.get("built_in"):
                raise ValueError(
                    "Import conflicts with a built-in tool. Please adjust the JSON or choose a different name."
                )
            if conflict.get("read_only"):
                raise ValueError(
                    "Import conflicts with a read-only tool definition from "
                    f"{self._source_label(conflict.get('source'))}. Please change the name or app ID."
                )
            if not overwrite:
                raise ValueError("A tool with the same identifier already exists. Please confirm overwrite.")

        if conflict:
            current_enabled = bool(conflict.get("enabled"))
            update_body = {"tool_id": conflict.get("tool_id")}
            update_body.update(normalized_payload)
            config_store.call_mcp_tools_api(
                session_key, system_session_key, method="PUT", json_body=update_body
            )
            if desired_enabled != current_enabled:
                self._toggle_tool(
                    session_key,
                    system_session_key,
                    conflict.get("tool_id"),
                    conflict.get("name"),
                    desired_enabled,
                )
            tool_id = conflict.get("tool_id")
            message = "Tool imported and overwritten successfully."
        else:
            create_response = config_store.call_mcp_tools_api(
                session_key, system_session_key, method="POST", json_body=normalized_payload
            )
            tool_id = create_response.get("tool_id")
            if not isinstance(tool_id, str) or not tool_id:
                raise ValueError("Backend did not return a tool_id for the imported tool.")
            if desired_enabled:
                self._toggle_tool(
                    session_key,
                    system_session_key,
                    tool_id,
                    normalized_payload.get("name"),
                    True,
                )
            message = "Tool imported successfully."

        tool = self._load_tool(session_key, system_session_key, tool_id)
        enabled_names = self._fetch_enabled_names(session_key, system_session_key)
        return 200, {
            "status": "ok",
            "message": message,
            "tool": self._build_tool_detail(tool, tool.get("name") in enabled_names),
            "normalized_payload": normalized_payload,
        }

    def _toggle_tool(self, session_key, system_session_key, tool_id, tool_name, enabled):
        config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="POST",
            json_body={
                "tool_id": tool_id,
                "tool_name": tool_name,
                "enabled": bool(enabled),
            },
        )

    def _load_tool(self, session_key, system_session_key, tool_id):
        tool_response = config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="GET",
            params={"tool_id": tool_id, "output_mode": "json"},
        )
        tool = tool_response.get("tool")
        if not isinstance(tool, dict):
            raise ValueError(f"Unable to load tool '{tool_id}'.")
        return tool

    def _fetch_enabled_names(self, session_key, system_session_key):
        enabled_response = config_store.call_mcp_tools_api(
            session_key,
            system_session_key,
            method="GET",
            params={"enabled_tools": 1, "output_mode": "json"},
        )
        enabled_names = set()
        for item in enabled_response.get("enabled_tools", []):
            if isinstance(item, dict) and isinstance(item.get("tool_name"), str):
                enabled_names.add(item["tool_name"])
        return enabled_names

    def _fetch_installed_app_ids(self, session_key, system_session_key):
        try:
            return config_store.list_installed_app_ids(session_key, system_session_key)
        except Exception:
            return []

    def _public_tool_payload(self, tool):
        input_schema = tool.get("inputSchema") if isinstance(tool, dict) else {}
        return {
            "name": str(tool.get("name") or "") if isinstance(tool, dict) else "",
            "description": str(tool.get("description") or "") if isinstance(tool, dict) else "",
            "inputSchema": deepcopy(input_schema if isinstance(input_schema, dict) else {}),
        }

    def _build_llm_preview_fallback(self, public_tool):
        llm_public = self._public_tool_payload(public_tool)
        tool_name = llm_public["name"]
        return {
            "tool_id": "",
            "name": tool_name,
            "display_name": tool_name,
            "title": tool_name,
            "description": llm_public["description"],
            "execution_type": "",
            "enabled": True,
            "built_in": False,
            "supported_form": False,
            "editable_form": False,
            "read_only": True,
            "source": "mcp",
            "external_app_id": "",
            "tags": [],
        }

    def _build_tool_summary(self, tool, enabled):
        meta = tool.get("_meta", {}) or {}
        execution = meta.get("execution", {}) or {}
        external_app_id = meta.get("external_app_id") or ""
        stored_name = tool.get("name", "")
        display_name = self._display_name(stored_name, external_app_id)
        built_in = bool(meta.get("built_in"))
        execution_type = execution.get("type", "spl")
        source = self._tool_source(meta, built_in)
        read_only = self._tool_read_only(meta, built_in)
        return {
            "tool_id": tool.get("tool_id") or tool.get("_key") or "",
            "name": stored_name,
            "display_name": display_name,
            "title": tool.get("title") or display_name or stored_name,
            "description": tool.get("description") or "",
            "execution_type": execution_type,
            "enabled": bool(enabled),
            "built_in": built_in,
            "supported_form": execution_type == "spl",
            "editable_form": (not read_only and execution_type == "spl"),
            "read_only": read_only,
            "source": source,
            "external_app_id": external_app_id,
            "tags": meta.get("tags") or [],
        }

    def _build_tool_detail(self, tool, enabled):
        summary = self._build_tool_summary(tool, enabled)
        editor_state = self._editor_state_from_tool(tool, enabled)
        return {
            **summary,
            "editor_state": editor_state,
            "normalized_payload": self._normalized_payload_from_tool(tool),
            "raw": tool,
        }

    def _build_export_payload(self, tool, enabled):
        meta = tool.get("_meta", {}) or {}
        execution = meta.get("execution", {}) or {}
        input_schema = tool.get("inputSchema", {}) or {}
        required_names = set(input_schema.get("required") or [])
        properties = []
        for key, definition in (input_schema.get("properties") or {}).items():
            if not isinstance(definition, dict):
                continue
            if key in STANDARD_PROPERTY_KEYS:
                continue
            properties.append(
                {
                    "key": key,
                    "type": definition.get("type", "string"),
                    "description": definition.get("description", ""),
                    "required": key in required_names,
                    "default": definition.get("default", ""),
                    "enum": definition.get("enum") or [],
                    "minimum": definition.get("minimum", ""),
                    "maximum": definition.get("maximum", ""),
                    "pattern": definition.get("pattern", ""),
                    "validation_message": definition.get("validation_message", ""),
                }
            )

        return {
            "tool_id": tool.get("tool_id") or tool.get("_key") or "",
            "name": tool.get("name") or "",
            "title": tool.get("title") or "",
            "description": tool.get("description") or "",
            "external_app_id": meta.get("external_app_id") or "",
            "execution_type": execution.get("type", "spl"),
            "template": execution.get("template", ""),
            "row_limiter": bool(execution.get("row_limiter", True)),
            "time_range": bool(execution.get("time_range", True)),
            "guardrails": bool(execution.get("guardrails", False)),
            "tags": deepcopy(meta.get("tags") or []),
            "examples": deepcopy(meta.get("examples") or []),
            "properties": properties,
            "enabled": bool(enabled),
        }

    def _build_export_filename(self, export_payload):
        name = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(export_payload.get("name") or "tool")).strip("-")
        return f"{name or 'tool'}-export.json"

    def _normalized_payload_from_tool(self, tool):
        payload = {
            "name": tool.get("name"),
            "title": tool.get("title"),
            "description": tool.get("description"),
            "inputSchema": deepcopy(tool.get("inputSchema") or {}),
            "_meta": deepcopy(tool.get("_meta") or {}),
        }
        return payload

    def _editor_state_from_tool(self, tool, enabled):
        payload = self._normalized_payload_from_tool(tool)
        meta = payload.get("_meta") or {}
        execution = meta.get("execution") or {}
        external_app_id = meta.get("external_app_id") or ""
        name = payload.get("name") or ""
        input_schema = payload.get("inputSchema") or {}
        required_names = set(input_schema.get("required") or [])
        properties = []
        for key, definition in (input_schema.get("properties") or {}).items():
            if not isinstance(definition, dict):
                continue
            if key in STANDARD_PROPERTY_KEYS:
                continue
            properties.append(
                {
                    "key": key,
                    "type": definition.get("type", "string"),
                    "description": definition.get("description", ""),
                    "required": key in required_names,
                    "default": definition.get("default", ""),
                    "enum": definition.get("enum") or [],
                    "minimum": definition.get("minimum", ""),
                    "maximum": definition.get("maximum", ""),
                    "pattern": definition.get("pattern", ""),
                    "validation_message": definition.get("validation_message", ""),
                }
            )

        return {
            "tool_id": tool.get("tool_id") or tool.get("_key") or "",
            "stored_name": name,
            "name": self._display_name(name, external_app_id),
            "title": payload.get("title") or "",
            "description": payload.get("description") or "",
            "external_app_id": external_app_id,
            "execution_type": execution.get("type", "spl"),
            "template": execution.get("template", ""),
            "row_limiter": bool(execution.get("row_limiter", True)),
            "time_range": bool(execution.get("time_range", True)),
            "guardrails": bool(execution.get("guardrails", False)),
            "tags": meta.get("tags") or [],
            "examples": meta.get("examples") or [],
            "properties": properties,
            "enabled": bool(enabled),
            "built_in": bool(meta.get("built_in")),
            "supported_form": execution.get("type", "spl") == "spl",
            "editable_form": (not self._tool_read_only(meta, bool(meta.get("built_in"))) and execution.get("type", "spl") == "spl"),
            "read_only": self._tool_read_only(meta, bool(meta.get("built_in"))),
            "source": self._tool_source(meta, bool(meta.get("built_in"))),
        }

    def _tool_source(self, meta, built_in):
        if built_in:
            return "builtin"
        source = str((meta or {}).get("source") or "").strip().lower()
        return source or "kvstore"

    def _tool_read_only(self, meta, built_in):
        if built_in:
            return True
        return bool((meta or {}).get("read_only"))

    def _source_label(self, source):
        if source == "git":
            return "Git"
        if source == "builtin":
            return "the built-in catalog"
        if source == "kvstore":
            return "KV Store"
        return str(source or "the configured source")

    def _display_name(self, stored_name, external_app_id):
        prefix = f"{external_app_id}_"
        if external_app_id and stored_name.startswith(prefix):
            return stored_name[len(prefix):]
        return stored_name

    def _normalize_editor_payload(self, payload, create_mode=True, existing_tool=None):
        name = str(payload.get("name", "")).strip()
        stored_name = str(payload.get("stored_name", "")).strip()
        existing_name = ""
        existing_external_app_id = ""
        if isinstance(existing_tool, dict):
            existing_name = str(existing_tool.get("name") or "").strip()
            existing_meta = existing_tool.get("_meta") or {}
            existing_external_app_id = str(existing_meta.get("external_app_id") or "").strip()
        if create_mode and not name:
            raise ValueError("Tool name is required.")
        if not create_mode:
            stored_name = existing_name or stored_name
        if not create_mode and not stored_name:
            raise ValueError("stored_name is required.")

        title = str(payload.get("title", "")).strip()
        description = str(payload.get("description", "")).strip()
        external_app_id = str(payload.get("external_app_id", "")).strip()
        if not create_mode and existing_external_app_id:
            external_app_id = existing_external_app_id
        if not title:
            raise ValueError("Title is required.")
        if not description:
            raise ValueError("Description is required.")
        if not external_app_id:
            raise ValueError("external_app_id is required.")

        execution_type = str(payload.get("execution_type", "spl")).strip().lower()
        if execution_type != "spl":
            raise ValueError("V1 supports only SPL tools in the form editor.")

        template = str(payload.get("template", "")).strip()
        if not template:
            raise ValueError("SPL template is required.")

        tags = self._normalize_tags(payload.get("tags"))
        examples = self._normalize_examples(payload.get("examples") or [])
        row_limiter = bool(payload.get("row_limiter", True))
        time_range = bool(payload.get("time_range", True))
        properties, required = self._normalize_properties(payload.get("properties") or [])
        properties = self._inject_standard_properties(properties, row_limiter, time_range)

        normalized = {
            "name": stored_name if not create_mode else name,
            "title": title,
            "description": description,
            "inputSchema": {"type": "object", "properties": properties},
            "_meta": {
                "external_app_id": external_app_id,
                "tags": tags,
                "examples": examples,
                "execution": {
                    "type": "spl",
                    "template": template,
                    "row_limiter": row_limiter,
                    "time_range": time_range,
                    "guardrails": bool(payload.get("guardrails", False)),
                },
            },
        }
        if required:
            normalized["inputSchema"]["required"] = required

        if existing_tool:
            meta = existing_tool.get("_meta") or {}
            if meta.get("built_in"):
                raise ValueError("Built-in tools cannot be edited.")
            if self._tool_read_only(meta, bool(meta.get("built_in"))):
                raise ValueError(
                    "This tool is managed from "
                    f"{self._source_label(self._tool_source(meta, bool(meta.get('built_in'))))} and cannot be edited here."
                )

        return normalized, bool(payload.get("enabled"))

    def _inject_standard_properties(self, properties, row_limiter, time_range):
        next_properties = dict(properties or {})

        if time_range:
            next_properties.setdefault(
                "earliest_time",
                {
                    "type": "string",
                    "description": "Start time for search (e.g., -24h, -1d)",
                    "default": "-24h",
                },
            )
            next_properties.setdefault(
                "latest_time",
                {
                    "type": "string",
                    "description": "End time for search (e.g., now, -1h)",
                    "default": "now",
                },
            )

        if row_limiter:
            next_properties.setdefault(
                "row_limit",
                {
                    "type": "integer",
                    "description": "Maximum number of rows to return",
                    "default": 100,
                    "minimum": 1.0,
                    "maximum": 1000.0,
                },
            )

        return next_properties

    def _parse_import_payload(self, raw_json):
        if isinstance(raw_json, dict):
            candidate = deepcopy(raw_json)
        else:
            raw_value = str(raw_json or "").lstrip("\ufeff").strip()
            if not raw_value:
                raise ValueError("Import JSON is required.")
            try:
                candidate = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Import JSON is invalid: {exc.msg}.")

        if not isinstance(candidate, dict) or isinstance(candidate, list):
            raise ValueError("Import erwartet genau ein JSON-Objekt.")

        unknown_fields = sorted(set(candidate.keys()) - TOP_LEVEL_IMPORT_FIELDS)
        if unknown_fields:
            raise ValueError(
                "Import JSON contains unknown fields: " + ", ".join(unknown_fields)
            )

        self._validate_import_examples(candidate.get("examples") or [])
        self._validate_import_properties(candidate.get("properties") or [])
        self._validate_import_payload_serializable(candidate)

        return {
            "tool_id": str(candidate.get("tool_id") or "").strip(),
            "name": str(candidate.get("name") or "").strip(),
            "title": str(candidate.get("title") or "").strip(),
            "description": str(candidate.get("description") or "").strip(),
            "external_app_id": str(candidate.get("external_app_id") or "").strip(),
            "execution_type": str(candidate.get("execution_type") or "spl").strip().lower(),
            "template": str(candidate.get("template") or ""),
            "row_limiter": bool(candidate.get("row_limiter", True)),
            "time_range": bool(candidate.get("time_range", True)),
            "guardrails": bool(candidate.get("guardrails", False)),
            "tags": deepcopy(candidate.get("tags") or []),
            "examples": deepcopy(candidate.get("examples") or []),
            "properties": deepcopy(candidate.get("properties") or []),
            "enabled": bool(candidate.get("enabled")),
        }

    def _validate_import_examples(self, examples):
        if not isinstance(examples, list):
            raise ValueError("examples must be a list.")

        for index, item in enumerate(examples, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"Example {index} must be an object.")
            unknown_fields = sorted(set(item.keys()) - EXAMPLE_IMPORT_FIELDS)
            if unknown_fields:
                raise ValueError(
                    f"Example {index} contains unknown fields: {', '.join(unknown_fields)}"
                )

            arguments = item.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments or "{}")
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Example {index} arguments are invalid: {exc.msg}.")
            if not isinstance(arguments, dict):
                raise ValueError(f"Example {index} arguments must be a JSON object.")

    def _validate_import_properties(self, properties):
        if not isinstance(properties, list):
            raise ValueError("properties must be a list.")

        seen = set()
        for index, item in enumerate(properties, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"Property {index} must be an object.")
            unknown_fields = sorted(set(item.keys()) - PROPERTY_IMPORT_FIELDS)
            if unknown_fields:
                raise ValueError(
                    f"Property {index} contains unknown fields: {', '.join(unknown_fields)}"
                )

            key = str(item.get("key") or "").strip()
            if not key:
                raise ValueError(f"Property {index} requires a name.")
            if key in seen:
                raise ValueError(f"Property name '{key}' is duplicated.")
            seen.add(key)

            prop_type = str(item.get("type") or "string").strip().lower()
            if prop_type not in SUPPORTED_PROPERTY_TYPES:
                raise ValueError(
                    f"Property '{key}' has an invalid type. Allowed: string, number, integer, boolean."
                )

            if item.get("pattern"):
                try:
                    re.compile(str(item.get("pattern")))
                except re.error as exc:
                    raise ValueError(f"Property '{key}' has an invalid regex pattern: {exc}.")

            if item.get("minimum") not in ("", None):
                float(str(item.get("minimum")))
            if item.get("maximum") not in ("", None):
                float(str(item.get("maximum")))

            default_value = item.get("default")
            if isinstance(default_value, (dict, list)):
                raise ValueError(f"Property '{key}' default must be a scalar value.")

            enum_values = item.get("enum", [])
            if isinstance(enum_values, list):
                for enum_value in enum_values:
                    if isinstance(enum_value, (dict, list)):
                        raise ValueError(
                            f"Property '{key}' enum may contain only scalar values."
                        )

    def _validate_import_payload_serializable(self, payload):
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Import JSON contains non-serializable values: {exc}.")

    def _find_import_conflict(self, session_key, system_session_key, import_payload):
        imported_tool_id = str(import_payload.get("tool_id") or "").strip()
        imported_name = str(import_payload.get("name") or "").strip()
        imported_external_app_id = str(import_payload.get("external_app_id") or "").strip()

        tool_response = config_store.call_mcp_tools_api(
            session_key, system_session_key, method="GET", params={"output_mode": "json"}
        )
        enabled_names = self._fetch_enabled_names(session_key, system_session_key)
        for tool in tool_response.get("tools", []):
            if not isinstance(tool, dict):
                continue
            tool_id = str(tool.get("tool_id") or tool.get("_key") or "")
            meta = tool.get("_meta", {}) or {}
            tool_name = str(tool.get("name") or "")
            external_app_id = str(meta.get("external_app_id") or "")
            if imported_tool_id and tool_id == imported_tool_id:
                return self._build_tool_summary(tool, tool_name in enabled_names)
            if tool_name == imported_name and external_app_id == imported_external_app_id:
                return self._build_tool_summary(tool, tool_name in enabled_names)
        return None

    def _serialize_conflict(self, conflict):
        if not conflict:
            return None
        return {
            "exists": True,
            "tool_id": conflict.get("tool_id") or "",
            "name": conflict.get("name") or "",
            "title": conflict.get("title") or conflict.get("name") or "",
            "display_name": conflict.get("display_name") or conflict.get("name") or "",
            "enabled": bool(conflict.get("enabled")),
            "built_in": bool(conflict.get("built_in")),
            "read_only": bool(conflict.get("read_only")),
            "source": conflict.get("source") or "kvstore",
            "external_app_id": conflict.get("external_app_id") or "",
        }

    def _normalize_tags(self, raw_tags):
        if isinstance(raw_tags, list):
            values = raw_tags
        else:
            values = str(raw_tags or "").replace("\n", ",").split(",")
        result = []
        seen = set()
        for tag in values:
            value = str(tag).strip()
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _normalize_examples(self, raw_examples):
        examples = []
        for item in raw_examples:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            description = str(item.get("description", "")).strip()
            expected_use = str(item.get("expected_use", "")).strip()
            arguments = item.get("arguments", {})
            if isinstance(arguments, str):
                arguments = json.loads(arguments or "{}")
            if not isinstance(arguments, dict):
                raise ValueError("Example arguments muessen ein JSON-Objekt sein.")
            if not (name or description or expected_use or arguments):
                continue
            example: Dict[str, Any] = {"arguments": arguments}
            if name:
                example["name"] = name
            if description:
                example["description"] = description
            if expected_use:
                example["expected_use"] = expected_use
            examples.append(example)
        return examples

    def _normalize_properties(self, raw_properties):
        properties = {}
        required = []
        for item in raw_properties:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key", "")).strip()
            if not key:
                continue
            prop_type = str(item.get("type", "string")).strip() or "string"
            definition: Dict[str, Any] = {"type": prop_type}
            description = str(item.get("description", "")).strip()
            if description:
                definition["description"] = description
            default_value = item.get("default")
            if default_value not in ("", None):
                definition["default"] = self._coerce_value(default_value, prop_type)
            enum_values = item.get("enum", [])
            if isinstance(enum_values, str):
                enum_values = [part.strip() for part in enum_values.replace("\n", ",").split(",") if part.strip()]
            if enum_values:
                definition["enum"] = [self._coerce_value(value, prop_type) for value in enum_values]
            if item.get("minimum") not in ("", None):
                definition["minimum"] = float(str(item.get("minimum")))
            if item.get("maximum") not in ("", None):
                definition["maximum"] = float(str(item.get("maximum")))
            pattern = str(item.get("pattern", "")).strip()
            if pattern:
                definition["pattern"] = pattern
            validation_message = str(item.get("validation_message", "")).strip()
            if validation_message:
                definition["validation_message"] = validation_message

            properties[key] = definition
            if bool(item.get("required")):
                required.append(key)
        return properties, required

    def _coerce_value(self, value, prop_type):
        if prop_type == "integer":
            return int(value)
        if prop_type == "number":
            return float(value)
        if prop_type == "boolean":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("1", "true", "yes", "on")
        return str(value)

    def _require_admin_session(self, request):
        _, session_key, system_session_key, context = require_request_capabilities(
            request,
            [config_store.MCP_TOOL_ADMIN_CAPABILITY],
        )
        return session_key, system_session_key, context

    def _normalize_query(self, query):
        if not query:
            return {}
        if isinstance(query, dict):
            return query
        normalized = {}
        if isinstance(query, list):
            for item in query:
                if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
                    normalized[item[0]] = item[1]
        return normalized

    def _is_truthy(self, value):
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    def _parse_payload(self, request):
        payload = request.get("payload") or request.get("body") or ""
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, list):
            data = {}
            for item in payload:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    data[item[0]] = item[1]
            return data
        if isinstance(payload, str):
            payload = payload.strip()
            if not payload:
                return {}
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                form = parse_qs(payload, keep_blank_values=True)
                parsed = {}
                for key, values in form.items():
                    parsed[key] = values[-1] if isinstance(values, list) and values else ""
                return parsed
        return {}

    def _build_response(self, status, payload):
        return build_json_response(status, payload)
