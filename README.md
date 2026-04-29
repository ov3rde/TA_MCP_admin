# TA MCP Admin

`TA MCP Admin` is the admin UI for operating MCP tools in Splunk. The app is not the MCP backend itself. Instead, it is an extension of `Splunk_MCP_Server` and provides the UI for backend connection setup, tool configuration, tool testing, and tool lifecycle actions.

## Use Case

The typical setup is:

1. `Splunk_MCP_Server` provides the MCP endpoints.
2. `TA MCP Admin` connects to that backend.
3. Administrators maintain the backend connection and tokens centrally.
4. MCP tools can then be created, edited, enabled, tested, and deleted directly in Splunk.

## Requirements

Before first use, the following components must already exist:

1. A running Splunk instance
2. The `Splunk_MCP_Server` app
3. The `TA MCP Admin` app
4. A valid Splunk management token
5. A valid MCP bearer token

For the recommended operator role and the local E2E user flow, see `../docs/HOWTO_BERECHTIGUNGEN.md`.

## Splunk Management Token Permissions

`TA MCP Admin` uses the Splunk management token to manage the `Splunk_MCP_Server` backend through `/services/mcp_tools`.

On the Splunk side, that token must have the `mcp_tool_admin` capability.

Recommended in practice:

- use a dedicated operator role with `mcp_tool_admin` and `mcp_tool_execute`
- in the local repo workflow, `Splunk_MCP_Server` defines `mcp_tool_operator` for that purpose
- `admin` and `sc_admin` still work, but they are no longer the intended day-to-day operator model

Without `mcp_tool_admin`, `TA MCP Admin` can still be opened, but it cannot load the tool list or create, update, enable, disable, or delete tools.

## Installation

1. Install `Splunk_MCP_Server` in Splunk.
2. Install `TA MCP Admin` in Splunk.
3. Make sure the MCP endpoints exposed by `Splunk_MCP_Server` are reachable.
4. Open the app in Splunk and go to the setup page.

## Initial Configuration

In `TA MCP Admin > Setup`, configure the following values:

- `MCP Base URL`
- `MCP Backend App ID`
- `Verify backend TLS certificates`
- `Splunk Management Token`
- `MCP Bearer Token`

Typical local defaults:

- `MCP Base URL`: `https://127.0.0.1:8089`
- `MCP Backend App ID`: `Splunk_MCP_Server`

The tokens are stored server-side and should not be placed in files or dashboards.

Notes:

- the `Splunk Management Token` is used for tool management against `/services/mcp_tools`
- the `MCP Bearer Token` is used for tool tests and calls against `/services/mcp`
- `Verify backend TLS certificates` is enabled by default for remote backends and should only be disabled deliberately for self-signed lab environments
- the Setup permission gate is `mcp_tool_admin`, not `admin`

## Getting Started

After initial configuration:

1. Open the tool management UI.
2. Review which tools already exist in the MCP backend.
3. Create your own tools or edit existing ones.
4. Enable or disable tools.
5. Run a tool directly from the test panel against `Splunk_MCP_Server`.

That makes `TA MCP Admin` the working interface for the main use case: managing MCP tools in Splunk in a controlled way and verifying them immediately against the real backend.

## Open Source License

- This app is prepared for publication under `Apache License 2.0`.
- The full license text is included in the package as `LICENSE.txt`.
- The app is provided without warranty. Deployment and operation in a specific Splunk environment remain the responsibility of the operator.

## Support And Security

- The corresponding GitHub repository is only the default public contact channel.
- Security reports should not disclose exploit details in public issues. See `SECURITY.md` for details.
- No SLA, warranty, managed support commitment, maintenance obligation, or duty to respond is provided unless the publisher explicitly offers one in writing on GitHub or Splunkbase.
- The published GitHub folder is expected to include `SECURITY.md`, `SUPPORT.md`, and `TRADEMARKS.md` alongside this README.

## Splunkbase Notes

- Splunkbase should use the same declared license as the GitHub repository.
- Package metadata for Splunk tooling is stored in `app.manifest`.
- Contact, support, and release details on Splunkbase should stay consistent with `README.md`, `SUPPORT.md`, and `SECURITY.md` in this app directory.
