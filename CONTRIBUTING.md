# Contributing

Contributions are welcome while the API is still experimental.

## Development

The build/test toolchain (`tsup` 9, `vitest` 4) requires a newer Node.js than
the published package does. Use Node.js `^22.18.0`, `^24.11.0`, or `>=26` for
development (the `tsup` 9 `engines` range); CI runs the latest Node 22 and the
release workflow runs the latest Node 24. The published package itself still
supports Node.js `>=20` (`engines.node`).

```sh
npm install
npm test
npm run build
```

## Design Principles

- Keep the core library side-effect free.
- Add fixtures before broad rewrites.
- Prefer explicit signal names and reason keys over opaque scores.
- Avoid policy decisions that are specific to one mail client.

## License

By contributing, you agree that your contribution is provided under the Apache-2.0 license.

