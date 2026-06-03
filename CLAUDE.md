# 3gpp-server

JSON-to-NGAP/NAS translation server for testing 5G core networks. Sends crafted 3GPP messages over SCTP and returns decoded responses as JSON.

## Build & check

```bash
go build ./...
go vet ./...
golangci-lint run ./...        # fix with: golangci-lint run --fix ./...
```

All three must pass before submitting changes.

## Integration tests

Tests run inside Docker against a live Ella Core instance. They are gated behind the `integration` build tag and never run with `go test ./...`.

```bash
# Build Ella Core from source (requires github.com/ellanetworks/core)
go build -C /path/to/core -o /path/to/3gpp-server/integration/ella-core ./cmd/core/

# Start environment
docker compose -f integration/compose-local.yaml build
docker compose -f integration/compose-local.yaml up -d

# Inside the tester container: build the server, start it, run tests
docker compose -f integration/compose-local.yaml exec 3gpp-server-tester bash
cd /app
go build -buildvcs=false -o /tmp/3gpp-server ./cmd/3gpp-server/
/tmp/3gpp-server --listen :8080 &
go test -v -tags integration -count=1 -timeout 120s ./integration/

# Cleanup
docker compose -f integration/compose-local.yaml down
```

Test files are organized by purpose:
- `message_*.go` — per-NGAP-message tests (crafted IE combinations, valid and invalid)
- `scenario_*.go` — multi-step procedure tests (e.g. full registration flow)

**Never work around Ella Core bugs in tests.** If Ella Core misbehaves, the test must fail — that's the whole point of this project. Don't add expected-failure assertions, skip annotations, or use separate subscribers/resources to avoid triggering AMF bugs. A failing test means a bug to fix in Ella Core.

## OpenAPI spec

The spec at `internal/api/openapi.yaml` is embedded at compile time and served at `GET /openapi.yaml`. Update it when adding or changing endpoints.

## Key references

- Ella Core tester (porting source): `/home/guillaume/code/core2/internal/tester/`
- TS 38.413 (NGAP): `ts_138413v180500p.pdf`
- TS 24.501 (NAS 5GS): `ts_124501v170701p.pdf`
- Implementation plan: `PLAN.md`

## Code comments

Default to **no comment** — prefer precise names and obvious structure; rewrite unclear code before commenting it. When one is unavoidable:

- Explain *why*, never *what*; concise and precise.
- Present state only — no prior/alternative/future implementations, no "was a bug".
- No caller or flow narration; comment the code in front of you.
- Anchor rationale to the spec (e.g. `TS 24.501 §6.4.2.4`); keep it true; no commented-out code or `TODO`s.

Applies to doc/inline comments, test names, and failure messages (state expected vs. actual, don't editorialize). Banned: "rather than", "instead of", "no longer", "used to", "previously", "now (does/responds)", "would mean", "silently drop(ped)".
