# Security Policy

This project analyzes email authentication and header consistency signals. Please report security-sensitive issues privately until a fix is available.

## Report

Open a private advisory or contact the repository owner through GitHub.

## Scope

Security-sensitive issues include:

- Rules that allow attacker-controlled headers to suppress risk signals.
- Parser behavior that trusts untrusted `Authentication-Results` headers.
- License or supply-chain issues in detection data or dependencies.
- Denial-of-service risks from pathological header input.

