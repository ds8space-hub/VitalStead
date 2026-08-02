---
description: Sync connected data providers now (all of them, or one specific provider/connection).
argument-hint: [provider] [connection_id]
---

The user ran `/sync $ARGUMENTS`.

- If `$ARGUMENTS` is empty, call the `sync_now` tool (syncs every connected
  source). Report the resulting `status` ("success" / "partial" /
  "no_connections" / "no_data_folder_configured") and, for each entry in
  `results`, its provider, connection_id, status, and record counts — do not
  print raw health values, only what the tool response itself contains.
- If `$ARGUMENTS` gives a provider (and optionally a connection_id), call
  `sync_provider` with those values instead. If only a provider is given and
  they have more than one connection for it, ask which `connection_id` (call
  `list_data` first if you need to show the options) rather than guessing.
- If the tool response's `status` is `"error"`, relay `error.message` and
  `error.recovery` from the response verbatim — do not invent your own
  explanation.
- If `status` is `"no_data_folder_configured"`, tell the user to run
  `set_data_folder` first (or re-run the setup-guide skill).
