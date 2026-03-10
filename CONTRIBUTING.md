# Contributing to Veil

Contributions are welcome. Whether it's a bug report, a fix, a new feature, or an improvement to the docs — all of it helps.

## Getting started

```bash
git clone <repo>
cd veil
pnpm install
pnpm run build
```

Run the tests before and after your change to make sure nothing broke:

```bash
pnpm run typecheck
pnpm run test:unit
```

## Submitting a change

1. Fork the repo and create a branch from `main`
2. Make your change
3. Make sure `typecheck` and `test:unit` both pass
4. Open a pull request with a short description of what you changed and why

## Reporting a bug

Open an issue. Include what you expected to happen, what actually happened, and which browser version you were using.

## Security issues

If you find a security vulnerability — especially anything affecting the crypto layer — please do not open a public issue. Contact the maintainer directly first.

## Code style

- TypeScript strict mode — no `any`, no unchecked nulls
- Keep functions small and focused
- Tests live in `test/` and follow the existing Vitest conventions
