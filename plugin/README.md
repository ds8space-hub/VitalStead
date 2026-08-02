# Vitalstead — plugin (closed MVP)

Claude plugin that syncs wearable health data (WHOOP today) into local CSV
files. Health data stays on your machine — the server only talks to the
provider's own API and your local disk. Full privacy policy:
[`docs/privacy.md`](../docs/privacy.md) — what's stored locally, what's in
Keychain, what reaches WHOOP, and exactly what (if anything) reaches this
conversation with the AI model.

## Prerequisites

- **macOS, Apple Silicon (arm64).** The bundled binary at `bin/vitalstead-mcp`
  is built for `aarch64-apple-darwin`. If you're on Intel Mac, build from
  source instead (see "Building from source" below) — an x86_64 binary isn't
  bundled in this closed-MVP channel yet (the MCPB one-click bundle, T-704,
  targets both architectures).
- Claude Desktop with plugin support enabled.
- Your own WHOOP developer app (BYO OAuth, D-006) — the setup skill walks
  you through registering one; you don't need it before installing.

## Install

1. `Directory → Plugins → Personal → Add marketplace`, pointing at this
   marketplace's git repository (ask whoever gave you access to this MVP
   for the URL — this is a closed/private marketplace, not the public
   directory).
2. Install the `vitalstead` plugin from that marketplace.
3. Enable the plugin. Claude Desktop will prompt you for the plugin's
   `userConfig` — you can leave WHOOP Client ID/Secret blank for now, the
   setup skill will tell you when to come back and fill them in.

## First connection

Ask Claude to "set up Vitalstead" or run `/connect whoop` — this
invokes the `setup-guide` skill, which walks through: choosing a data
folder, registering a WHOOP developer app, entering credentials through the
plugin settings UI (never in chat), connecting via OAuth, and running your
first sync.

## Updating

Pull the marketplace repository (or use Claude Desktop's marketplace
refresh) — plugin updates are delivered by the marketplace pulling the
latest commit, not by a separate release process for this closed channel.

## Reporting problems

Include: the tool's `error.kind`/`error.message`/`error.recovery` fields
(safe to share — see D-015, they never contain secrets or raw health
values), macOS version, and which step of the setup skill you were on.
**Never** include: your WHOOP Client Secret, access/refresh tokens, or raw
CSV file contents.

## Building from source (Intel Mac, or after pulling core changes)

From the parent repo root (one level up from `plugin/`):

```sh
cargo build --release
cp target/release/vitalstead-mcp plugin/bin/vitalstead-mcp
chmod +x plugin/bin/vitalstead-mcp
```

For an Intel Mac build, add `--target x86_64-apple-darwin` (requires that
target installed via `rustup target add x86_64-apple-darwin`) and copy from
`target/x86_64-apple-darwin/release/` instead.

## Known limitations of this closed-MVP channel

- Single architecture bundled (arm64) — see Prerequisites above.
- OAuth callback port is fixed at 53682 (D-019) — if something else on your
  machine is already using that port, the WHOOP connect step will fail;
  close whatever's using it and retry.
- Only WHOOP is supported; Oura and Garmin are post-MVP (D-017/D-018).
