# Privacy — Vitalstead

English (D-012). This document describes exactly what Vitalstead
stores, sends, and shows to the AI model — drawn directly from the project's
decisions (`docs/decisions.md`) and the actual behavior of its tools, not
aspirational claims.

## What's stored locally, on your machine

- **CSV files** in the folder you choose (`set_data_folder`): one file per
  data type per provider (e.g. `sleep.csv`, `recovery.csv`, `cycles.csv`,
  `workouts.csv` for WHOOP). These are plain text files you can open, back
  up, move, or delete yourself at any time.
- **`config.json`** (app support directory): just the path to your chosen
  data folder. No credentials, no tokens — ever (see `src/config.rs`'s own
  contract: `AppConfig` intentionally has no secret field).
- **`sync_state.json`** (app support directory): which (provider,
  connection_id, data_type) combinations have synced, when, and a cursor for
  incremental sync. No health values, no tokens.

## What's stored in your OS Keychain

- OAuth access tokens and refresh tokens, one per connection, namespaced by
  provider and connection ID. Nothing else touches the Keychain.
- If you use the Claude Desktop MCPB bundle or the plugin's `userConfig`,
  your WHOOP Client Secret is also stored there by Claude Desktop/Claude
  Code itself (not by this server) — see the plugin manifests
  (`plugin/.claude-plugin/plugin.json`, `mcpb/manifest.json`).

## What's sent to the provider (WHOOP)

Only what's required for OAuth (authorization code exchange, token refresh)
and to fetch your own data via WHOOP's API (`GET` requests for sleep,
recovery, cycle, and workout records within the time range you sync). No
data flows the other direction — this server never writes anything back to
the provider.

## What reaches the AI model's conversation context

This is the boundary most people care about, so it's explicit:

- **By default: nothing from your health data.** Tool responses contain
  statuses, record counts, timestamps, and file paths — never raw health
  values (see every tool's response shape in `docs/tasks/EPIC-06-sync-tools.md`).
- **Aggregates, by default, only when you ask a question about your data.**
  `query_data` returns `count`/`min`/`max`/`avg` for a column over a time
  period — computed numbers, not your raw readings — unless you explicitly
  pass `include_raw: true`.
- **Raw values only with explicit opt-in.** `query_data(..., include_raw: true)`
  returns the actual matching row values, capped at 500 rows per call, and
  the tool's own description says plainly that doing this puts those values
  in the conversation. Nothing else in this server's tool surface returns
  raw health data.
- **Never, under any circumstance:** OAuth tokens, client secrets,
  authorization codes, Authorization headers, or full raw API response
  bodies. This is enforced by construction — see `src/error_mapping.rs`'s
  `ToMcpError` trait (every error type is mapped to a redacted
  code/message/recovery triple before it can reach a tool response) and the
  logging rules in this repo's `CLAUDE.md` (never log tokens/secrets/full
  callback URLs/full API responses).

## What's never collected at all

- No telemetry, no analytics, no usage tracking (D-013).
- No provider passwords — this server only ever handles OAuth tokens
  obtained through the provider's own login page in your browser; it never
  sees or asks for your WHOOP account password (D-005).
- No data about you leaves your machine to any server operated by this
  project — there is no project-operated backend at all (D-001, local-first).

## Deleting your data

- **Disconnecting a provider** (`disconnect_provider` / `/disconnect`)
  revokes/removes the stored OAuth tokens for that connection. Your CSV
  files are never touched by this — D-010.
- **Deleting everything** (`delete_app_data`) is a separate, explicit call —
  never triggered automatically by any other action. It reports back exactly
  what was deleted (paths/providers), never health values, and distinguishes
  a full success from a partial failure rather than silently claiming
  success.

## BYO OAuth apps

You connect using your own WHOOP developer application (Bring-Your-Own
OAuth, D-006) — this project doesn't operate a shared/central OAuth client
that would let it see traffic across users. You register your own app in
WHOOP's developer dashboard and grant it access to your own account only.

## Questions or issues

See the plugin's own README (`plugin/README.md`) for what's safe to include
when reporting a problem (tool `error.kind`/`error.message`/`error.recovery`
fields, OS version, which setup step) versus what should never be shared
(Client Secret, tokens, raw CSV contents).
