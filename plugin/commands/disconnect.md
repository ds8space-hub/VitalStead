---
description: Disconnect a data provider. Revokes/removes stored credentials; never deletes CSV files (D-010).
argument-hint: [provider] [connection_id]
---

The user ran `/disconnect $ARGUMENTS`.

- Before calling anything, tell the user explicitly: disconnecting removes
  stored credentials only — their existing CSV files are never touched by
  this (D-010). If they want data deleted too, that's a separate, explicit
  `delete_app_data` call they have to ask for directly; do not offer to
  chain it automatically.
- Parse `$ARGUMENTS` for `provider` and `connection_id`. If `connection_id`
  is missing, call `list_data` first to show the user their current
  connections and ask which one — do not guess or invent a connection_id.
- Call the `disconnect_provider` tool with the resolved provider and
  connection_id.
- Report the tool's own response fields (`status`, `revoke_attempted`,
  `revoke_succeeded`) plainly. If `status` is `"error"`, relay
  `error.message`/`error.recovery` verbatim rather than paraphrasing.
