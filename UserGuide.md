# Consul Viewer TUI User Guide

## 1. Purpose

`Consul Viewer TUI` is a read-only terminal application for inspecting a Consul cluster.

The application is designed to:

- view the most important Consul data without making changes;
- navigate sections, lists, and details entirely from the keyboard;
- inspect services, nodes, KV, ACL objects, sessions, and metrics;
- apply filtering and sorting to the current list;
- open full JSON or text payloads in a viewer popup.

The application does not perform `PUT`, `POST`, or `DELETE` requests and does not modify Consul data.

## 2. Starting the Application

Basic start:

```bash
python consul-viewer.py
```

Main command-line options:

- `--addr` - Consul HTTP API address
- `--token` - ACL token
- `--refresh` - auto-refresh interval in seconds
- `--timeout` - request timeout
- `--insecure` - disable TLS verification
- `--dc` - explicitly set datacenter
- `--ca-file` - path to CA bundle
- `--cert-file` - path to client certificate
- `--key-file` - path to client private key

Supported environment variables:

- `CONSUL_HTTP_ADDR`
- `CONSUL_HTTP_TOKEN`

Examples:

```bash
python consul-viewer.py --addr http://127.0.0.1:8500
python consul-viewer.py --addr https://consul.example.org:8501 --token <TOKEN>
python consul-viewer.py --refresh 10 --timeout 15
```

## 3. Overall Layout

The screen is split into the following areas:

- top header line: datacenter, leader, Consul address, and auth mode;
- tab bar: application sections;
- left `Items` pane: list of objects in the current section;
- right `Details` pane: details for the selected object;
- bottom status line: loading, stale/fresh, filters, sorting, and errors;
- bottom key hint line.

Popup dialogs are used for:

- help;
- viewer;
- filter input;
- status filter selection;
- instance filter selection;
- sort selection;
- filter reset selection;
- errors;
- exit confirmation.

## 4. Sections

### 4.1 Dashboard

Shows a compact summary of the local Consul agent and cluster:

- datacenter;
- local node;
- Consul version;
- leader;
- peer count;
- local and remote member counts;
- aggregated `Agent state`.

The `Details` pane includes:

- `Agent state` reasons;
- raft and serf telemetry;
- cluster member list.

### 4.2 Telemetry

This section displays metrics from:

- `/v1/agent/metrics?format=prometheus`

It shows load and health counters such as:

- overall `Cluster state`;
- `Open FDs`;
- active gRPC connections;
- `Blocking RPC`;
- `RPC errors`;
- `Raft main saturation`;
- `Raft FSM saturation`;
- thread count;
- memory usage;
- aggregated cluster object counters.

For metrics with a known limit, the section shows:

- current value;
- limit;
- usage percentage;
- color status (`passing`, `warning`, `critical`).

Example: `Open FDs` is calculated from `process_open_fds / process_max_fds`.

### 4.3 Services

Shows the aggregated services list:

- service name;
- tags;
- instance count;
- `Status` as `N/M`, where `N` is the number of passing instances and `M` is the total instance count.

When a service is selected, `Details` shows:

- health summary;
- service status;
- instance list;
- checks for each instance.

Press `Enter` on a service to open its instance list.

### 4.4 Services / Instances

In instance mode, the list shows instances of the selected service:

- instance ID;
- address;
- port;
- `Status` as `N/M`, where `N` is the number of passing checks and `M` is the total check count.

The `Details` pane for an instance shows:

- service / service ID;
- node;
- address and port;
- status;
- tags;
- service metadata;
- node metadata;
- checks.

### 4.5 Nodes

Shows the nodes list:

- name;
- address;
- datacenter;
- `Status` as `N/M`, where `N` is the number of passing instances on the node and `M` is the total instance count on the node.

Important:

- node row status is derived from node checks, not from service health on that node;
- service health is shown separately in details.

The `Details` pane shows:

- address;
- datacenter;
- metadata;
- `Node status`;
- `Services status`;
- instance list;
- node checks;
- service checks.

Press `Enter` on a node to open the list of instances registered on that node.

### 4.6 Nodes / Instances

In node instance mode, the list shows:

- instance ID;
- address;
- port;
- `Status` as `N/M` based on checks.

The `Details` pane shows:

- service;
- service ID;
- node;
- address and port;
- status;
- tags;
- service metadata;
- node metadata;
- checks.

Press `Enter` on a node instance to:

- switch to the `Services` section;
- apply an exact filter for the matching service name;
- select that service immediately;
- load the service details immediately.

### 4.7 KV

The KV section provides a read-only KV browser.

It supports:

- browsing directories and keys by prefix;
- entering a prefix;
- previewing a value;
- displaying key metadata;
- opening full content in the viewer.

Both text and binary values are supported.

### 4.8 Sessions

Shows active sessions:

- name;
- node;
- TTL;
- behavior.

The `Details` pane contains the selected session details.

### 4.9 Tokens

Shows ACL tokens if ACL endpoints are available and the current token has read access.

The list shows:

- the last block of `AccessorID`;
- `Description`.

`SecretID` is not shown automatically in the normal list or details.

Additional behavior:

- `F4` opens a popup with the selected token `SecretID`;
- `Enter` opens the linked roles and policies list.

### 4.10 Policies

Shows ACL policies:

- policy name;
- description.

The `Details` pane includes:

- `PolicyID`;
- description;
- `Rules`;
- role list;
- a token usage table.

The token usage table shows:

- `AccessorID` (last block);
- `Scope`;
- `Source` (`direct`, `via role`, `direct+role`);
- `Description`.

### 4.11 Roles

Shows ACL roles:

- role name;
- description;
- policy list.

The `Details` pane includes:

- `RoleID`;
- description;
- linked policies;
- a token usage table.

Press `Enter` to open the linked policies list.

### 4.12 Auth

Shows ACL auth methods:

- `Name`;
- `Type`;
- `Locality`.

The `Details` pane includes:

- base auth method fields;
- `TokenLocality`;
- type-specific config fields;
- `Bound audiences`;
- JWT/JWKS fields;
- `kubernetes` auth method fields;
- additional `Config` fields when present.

### 4.13 Mesh

The section is present as a placeholder but is not implemented in the current version.

## 5. Main Navigation

### 5.1 Switching Sections

- `Tab` - next section
- `Shift+Tab` - previous section
- `Ctrl+Tab` - previous section
- `0..9` - jump to a numbered section
- `T` - quick jump to `Telemetry`

Numbered sections:

- `0` - `Auth`
- `1` - `Dashboard`
- `2` - `Services`
- `3` - `Nodes`
- `4` - `KV`
- `5` - `Sessions`
- `6` - `Tokens`
- `7` - `Policies`
- `8` - `Roles`
- `9` - `Mesh`

### 5.2 Switching Panes

- `Left` / `Right` - switch focus between `Items` and `Details`

### 5.3 Moving Inside Lists

- `Up` / `Down` - move through list rows
- `PgUp` / `PgDn`, `Home`, `End` - standard `urwid` behavior for long lists

### 5.4 Drill-Down and Back Navigation

- `Enter` - open the selected object or drill down
- `Backspace` - go back

Typical flows:

- `Services -> Enter` - open service instances
- `Nodes -> Enter` - open node instances
- `Node Instance -> Enter` - switch to filtered `Services`
- `Tokens -> Enter` - open linked roles and policies
- `Roles -> Enter` - open linked policies
- `KV directory -> Enter` - enter prefix

## 6. Viewing Data and Popups

### 6.1 Help

- `F1` - open in-app help

### 6.2 Full Viewer

- `F3` - open full viewer for the current object

Examples:

- for KV: full value text or preview;
- for JSON-backed sections: full JSON;
- for `Telemetry`: raw Prometheus payload.

### 6.3 Token SecretID

- `F4` - show `SecretID` for the selected ACL token

If the current selection is not a token, or the token has no `SecretID`, the application shows a status message.

### 6.4 Exit Confirmation

- `F10` or `Esc` on the main screen opens the `Confirm Exit` dialog
- `Yes` is selected by default
- `Enter` confirms the selected option
- `Y` exits immediately
- `N`, `Esc`, or `F10` cancel exit

## 7. Filtering

Filters are applied in this order:

1. text filter;
2. status filter;
3. structured instance filter;
4. sorting is applied afterward.

### 7.1 Text Filter

- `F7` or `/`

Opens a popup for entering a text filter for the current list.

The filter matches a substring across row values.

Special case:

- `Services` uses an internal exact filter like `=service-name` when navigating from `Node Instance -> Services`

That exact filter is used for navigation and should not break service instance views.

### 7.2 Status Filter

- `F6`

Available for:

- services list;
- nodes list;
- instance lists.

Available values:

- `Passed`
- `Warning`
- `Critical`
- `No checks`

Any combination can be selected. The logic inside the filter is `OR`.

Examples:

- `Passed + Warning` - show rows with `passing` or `warning`
- `Critical` only - show only problem objects

Status filter state is stored separately for:

- `Services`
- `Nodes`
- `Instances`

### 7.3 Instance Filter

- `F9`

Available only in instance lists.

It can filter by:

- presence of tags;
- absence of tags;
- presence of metadata keys;
- absence of metadata keys;
- regex for metadata key names;
- regex for metadata values;
- case sensitivity;
- regex vs substring mode.

Fields:

- `Has tags`
- `No tags`
- `Has meta keys`
- `No meta keys`
- `Meta key regex`
- `Meta value regex`
- `Case sensitive`
- `Regex enabled`

Rules:

- tag lists and key lists are comma-separated;
- `Has ...` means all listed items must be present;
- `No ...` means listed items must be absent;
- if both key and value regex are set, at least one matching `key/value` pair must exist;
- invalid regex falls back to safe substring matching.

### 7.4 Clearing Filters

- `F8`

Opens the `Clear Filters` popup, where you can choose which filters to reset:

- `Text filter`
- `Status filter`
- `Instance filter`

All checkboxes are enabled by default.

This allows resetting only the filter layer you want, without affecting the others.

## 8. Sorting

- `F11`

Opens the `Sort` popup for the current list.

You can choose:

- sort field;
- `Descending` direction;
- `Default order` to remove custom sorting.

Sorting is stored separately for each visible list mode.

Examples:

- sort `Services` by name;
- sort `Services / instances` by address;
- sort `Telemetry` by `Usage %`;
- sort `Tokens links` by type or name.

## 9. Navigation Between Related Objects

### 9.1 From Instance to Node

- `Ctrl+N`

Works in instance lists.

Switches to the `Nodes` section and selects the matching node.

### 9.2 From Instance to Service

- `Alt+S`

Works in instance lists.

Switches to the `Services` section and selects the matching service.

### 9.3 From Node Instance to Filtered Service

- `Enter` in `Nodes / Instances`

Switches to `Services` and applies an exact filter for the selected instance service name.

## 10. Color Coding

The UI uses a Far Manager-inspired palette:

- dark blue background;
- light primary text;
- strong contrast for active elements;
- gray popups with black text.

Main color logic:

- `passing` - green
- `warning` - yellow
- `critical` - red

This is applied to:

- list rows;
- status lines in details;
- checks in service and instance details;
- `Agent state` and telemetry metrics.

## 11. Status Line

The bottom status line displays:

- current section;
- `loading/idle`;
- `fresh/stale`;
- active text filter;
- active status filter;
- active instance filter summary;
- active sorting;
- `KV` path;
- latest message;
- latest error.

This is the main diagnostic channel of the application.

## 12. Error Handling and Degraded Mode

If an endpoint is unavailable or returns an error:

- the application keeps the last good snapshot on screen;
- the section is marked as `stale`;
- the error is shown in the status bar;
- an error popup may also be shown.

For ACL:

- if ACL endpoints are unavailable, the related sections stay visible but unavailable;
- trying to open them shows a clear status message.

## 13. Current Limitations

- the `Mesh` section is not implemented yet;
- some status calculations (`Agent state`, telemetry thresholds) are heuristic;
- some metric statuses are based on local thresholds, not an official Consul health flag;
- the application is designed for keyboard-first, read-only diagnostics.

## 14. Practical Scenarios

### 14.1 Find a Failing Service

1. Go to `Services`
2. Press `F6`
3. Keep only `Critical`
4. Select the service
5. Press `Enter` to view instances
6. Inspect checks in `Details`

### 14.2 Find Instances by Tag and Metadata

1. Go to `Services`
2. Press `Enter` on the target service
3. Press `F9`
4. Fill `Has tags`
5. Optionally add `Has meta keys` or regex fields
6. Press `Enter`

### 14.3 Check Risk of File Descriptor Exhaustion

1. Go to `Telemetry` with `T`
2. Select `Open FDs`
3. Inspect:
   - current open file descriptors;
   - limit;
   - usage percentage;
   - color status

### 14.4 Return from Deep Navigation

1. Navigate deeper: `Nodes -> Instances -> Service`
2. Use `Backspace` to step back through history

## 15. Usage Recommendations

- use `F6` to isolate unhealthy objects quickly;
- use `F9` when text filtering is not precise enough;
- use `F11` for large lists;
- use `F3` whenever you need the full payload;
- in `Telemetry`, watch these first:
  - `Open FDs`
  - `RPC errors`
  - `Blocking RPC`
  - `Raft saturation`

## 16. Key Cheat Sheet

- `Tab` - next section
- `Shift+Tab` / `Ctrl+Tab` - previous section
- `T` - `Telemetry`
- `0..9` - numbered sections
- `Left` / `Right` - switch between `Items` and `Details`
- `Enter` - drill down / open
- `Backspace` - back
- `Ctrl+N` - jump to node
- `Alt+S` - jump to service
- `F1` - help
- `F2` - auto refresh on/off
- `F3` - viewer
- `F4` - token `SecretID`
- `F5` - refresh
- `F6` - status filter
- `F7` or `/` - text filter
- `F8` - clear filters dialog
- `F9` - instance filter
- `F11` - sort
- `F10` / `Esc` - confirm exit / close popup

