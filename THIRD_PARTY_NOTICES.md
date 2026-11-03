# Third-party notices

`internal/mtproto/record`, `internal/mtproto/fake` and `internal/mtproto/obfuscation`
contain modified portions of [9seconds/mtg](https://github.com/9seconds/mtg),
commit `2026e32e229f88ccb20831edc4874213e42d9e65`.

Copyright (c) 2018 Sergey Arkhipov. MIT license: see `LICENSE.mtg`.

Changes: standard-library connection types and X25519, one-pass multi-secret
authentication, bounded handshake/record parsing, and corrected I/O handling.
The upstream process, CLI, telemetry integrations and background workers are not included.

`modernc.org/sqlite` and its dependencies are downloaded through Go modules.
Their own licenses apply; exact versions are recorded in `go.mod` / `go.sum`.
