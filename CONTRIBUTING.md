# Contributing to NetherNet

Thanks for wanting to contribute to NetherNet. Here are a few simple rules to keep the codebase consistent.

## Code Style

- Use `declare(strict_types=1);` in all PHP files.
- Directory names and namespace paths are lowercase (e.g. `amber\nethernet\`, `src/`).
- Class names use `PascalCase` and match the filename directly.
- Indent PHP files with tabs, YAML with 2 spaces, and markdown or JSON with 4 spaces.
- Keep comments short and focused on why something is done, not what the code already says.

## Architecture Boundaries

- NetherNet handles transport networking only.
- Don't implement packet codecs, session management, or gameplay logic here (those belong in BedrockProtocol or server cores like [Amber](https://github.com/Amber-PM/Amber)).
- Payloads passed through NetherNet remain opaque bytes.

## Checking Your Code

Before sending a PR, make sure checks pass:

```bash
composer check
```

This runs:
- `composer validate --strict`
- `composer check-platform-reqs`
- PHPUnit tests
- PHPStan analysis (level 9)
- Benchmark bootstrap check

Also make sure autoloading and git formatting are clean:

```bash
composer dump-autoload --optimize --strict-psr --strict-ambiguous
git diff --check
```
