# Contributing

This is an experimental reference project. Issues and pull requests are welcome, with a few ground rules.

## Before you start

- Read [README.md](README.md), [docs/AUTHN.md](docs/AUTHN.md) and [docs/SECURITY.md](docs/SECURITY.md). The two
  Internet-Drafts are the source of truth for protocol details; please cite a section when you change behaviour.
- Open an issue for anything larger than a typo or a one-file fix.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r mcp/requirements.txt
python3 -m unittest discover -s tests -t .        # 41 tests

cd mcp && npm ci && cd ..                         # Cedar WASM
echo '{"op":"validate"}' | node mcp/pdp.mjs       # policy bundle must validate
```

The end-to-end checks (`scripts/verify.sh`) need a running Keycloak lab; see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). They are not run in CI.

## Rules

- **No secrets, tokens, private keys or tenant-specific identifiers** in commits, tests or examples.
- Keep Markdown files under 150 lines; split by topic instead of growing one file.
- Preserve the security properties listed in `docs/SECURITY.md`: deny-by-default, fail-closed, no raw-argument
  authorisation, exact-string client identity, and no implicit network egress from the MCP server.
- By contributing you agree that your contribution is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
