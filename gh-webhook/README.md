# gh-webhook — temporary alias for local-webhook

This plugin is a **byte-for-byte copy** of `../local-webhook/webhook.mjs` under
the plugin's pre-2026-07-15 name. It exists only because the claude-box launch
flag baked into the running NixOS generation still says
`--channels plugin:gh-webhook@local-channels`, and fixing that flag requires a
`nixos-rebuild` (root) that isn't available right now.

Rules while this exists:

- **Never enable both** `gh-webhook` and `local-webhook` in the same client:
  they'd race for 127.0.0.1:8788 and deliveries would go to a coin-flip winner.
- Do not patch `webhook.mjs` here; patch `../local-webhook/webhook.mjs` and
  re-copy.
- State is shared (`~/.local/state/local-webhook/`) — hardcoded in the code,
  not derived from the plugin name.

**Delete this directory** (and its marketplace.json entry, and re-enable
`local-webhook` in `~/.claude/settings.json`) once nixos-defang-ca commit
`698082c` has been applied to `/etc/nixos` and rebuilt. Tracked in
nixos-defang-ca issue 9.
