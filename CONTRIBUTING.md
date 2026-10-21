# Contributing

Thanks for helping. Before anything else, read the
[threat model](docs/threat-model.md) and the
[ten commandments](docs/commandments.md): every change keeps those promises,
and the tests they name. Open an issue first for anything large.

## The gate

Every commit must pass:

```sh
cargo build --workspace --all-targets && cargo test --workspace
```

On a machine short on memory, `-j2` (or `-j1`) and `-- --test-threads=2`
keep it from being killed.

## Rules

- **Security first, and fail closed.** If something can't be checked or
  applied, refuse. Add a test that shows the refusal.
- **No proprietary formats.** Tokens follow the AAT draft, receipts the
  agent-action-receipts draft. Extensions go where those formats allow them.
- **Receipts carry digests, never content** (arguments, outputs, file data).
- **No numbers without a reproducible benchmark** (`scripts/bench.sh`).
- **Commits:** English, [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(sandbox):`, `fix(p2p):`, `test(aat):`, `docs:`), one logical change
  per commit. Don't reformat whole files or reorder imports.
- Frozen crates (storage, adapters, HTTP/gRPC API, multi-tenancy) take no new
  work without a recorded decision.

## Security issues

See [`SECURITY.md`](SECURITY.md). Never in a public issue.

## License

By contributing you agree that your contributions are licensed under the
project's terms: MIT OR Apache-2.0, at the user's option.
