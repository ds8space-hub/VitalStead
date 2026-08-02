---
description: Connect a wearable data provider (currently WHOOP) via OAuth.
argument-hint: [provider]
---

The user ran `/connect $ARGUMENTS`.

- If `$ARGUMENTS` is empty, default `provider` to `"whoop"` (the only
  currently supported provider) rather than asking which one — but tell them
  it defaulted to WHOOP.
- If `$ARGUMENTS` names a provider other than `whoop` (case-insensitive),
  do NOT call the tool — tell the user that provider isn't supported yet
  (only WHOOP is available in this MVP; others are post-MVP) and stop.
- Otherwise, invoke the `setup-guide` skill's connection flow (steps 3-7:
  register_whoop_app through verify_connection/run_first_sync) rather than
  calling `connect_provider` blind — the skill knows the exact redirect URI,
  required scopes, and how to relay this tool's errors without inventing
  wording (D-015: always prefer the tool's own `error.message`/`error.recovery`).
- If the skill's connect step reports an error, relay its `error.message`
  and `error.recovery` fields verbatim — do not paraphrase or invent
  troubleshooting steps beyond what the tool response says.
