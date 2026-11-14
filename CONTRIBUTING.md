# Contributing to AetherVault

1. **Zero External Go Dependencies**: `cmd/aethervault` must remain 100% Go standard library (`CGO_ENABLED=0`) to guarantee deterministic static compilation and minimal supply-chain surface.
2. **FFP Headers**: Every source file must retain its `# ffp:` or `// ffp:` header declaration.
3. **Verification Gate**: Run both test suites prior to opening a pull request:
   ```bash
   PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
   go test -race -v ./...
   ```
4. **No Test Credentials in Source**: Never commit static keys, `.svlt` files, or `.master.key` artifacts.
