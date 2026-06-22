# AGENTS.md

Guidance for AI agents working in this repository.

## General behaviour

Use the session libpsafe3 and warn when it is not available.

When there is no single clear path forward, stop and ask. Present alternatives with trade-offs rather than picking one unilaterally.

After making any change, list the minimal steps needed to verify it works — keep this terse (commands only, no prose).

For a proposed change the user to authorize all edits to achieve that change only.

### git

- The user is responsible for managing version control.
- Use git to move or delete files, all other operations require explicit acknowledgement.
- Prompt for git operations iff they are required intermediate steps for a larger goal.

Look for opportunities to suggest new tests or tooling; call these out as a short note after completing a task.

## Code navigation

Use Serena's semantic tools (symbol lookup, find references, find definition) in preference to grep/find for navigating the codebase.

## Memory safety and side-channel hygiene

This is a crypto library that handles passwords and key material.

- **Sensitive data** (passwords, stretched keys, raw key material, HMAC state): must be allocated with `gcry_malloc_secure` / `crypto_secure_malloc` and freed with `gcry_free` / `crypto_secure_free`.
- **Sensitive-adjacent data** (intermediate buffers that hold or are derived from sensitive data, or that are written alongside sensitive data in the same code path): should also use secure allocation to avoid side-channel leakage via memory reuse or heap metadata.
- Never introduce heap or stack buffers that hold key material outside of secure memory, even transiently.

## Build and test

```sh
cmake -S . -B build        # configure (first time only)
cmake --build build        # build everything
ctest --test-dir build     # run all tests (util, dump, checkpass)
ctest --test-dir build -R <name>  # run a single test
```

Dependencies: `libgcrypt-dev`, `uuid-dev` (Homebrew: `libgcrypt`, `ossp-uuid`).

## Reference material

- `refs/formatV3.txt` — Password Safe v3 file format specification.
- `refs/rfc2104.txt` — HMAC specification.
- `data/header-fields.csv`, `data/database-fields.csv` — field type tables for the psafe3 header and database sections.
