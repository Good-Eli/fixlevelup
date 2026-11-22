# Synthetic file ledger and trust floor

This opt-in fixture is internal to P03-04 D. It adds no HTTP provider, main Prisma model, startup wiring or live defaults. The ledger is not a main DB schema, and the floor is not a ledger schema. Each service has its own database, network, named volume and credentials. Both use the existing pinned PostgreSQL 18.7 image with `fsync`, `synchronous_commit` and `full_page_writes` on. Main snapshot/restore jobs must never include either service; ledger-only backups must also exclude the floor.

| Service / database | Local address | Named volume |
| --- | --- | --- |
| `fixlevelup-test-file-ledger` / `fixlevelup_file_ledger` | `127.0.0.1:55433` | `fixlevelup-test-file-ledger-data` |
| `fixlevelup-test-file-floor` / `fixlevelup_file_floor` | `127.0.0.1:55434` | `fixlevelup-test-file-floor-data` |

Verify free loopback ports and unused resource names before first startup. Put independent, randomly generated synthetic secrets in a local ignored `infra/file-ledger/.env`: `FILE_LEDGER_ADMIN_PASSWORD`, `FILE_LEDGER_WRITER_PASSWORD`, `FILE_LEDGER_WRITER_NEXT_PASSWORD`, `FILE_LEDGER_SIGNER_PASSWORD`, `FILE_LEDGER_OPERATOR_PASSWORD`, `FILE_FLOOR_ADMIN_PASSWORD`, `FILE_FLOOR_VERIFIER_PASSWORD`, `FILE_FLOOR_OPERATOR_PASSWORD`. Do not print or commit that file. Test fixtures expect 64 lowercase hexadecimal characters per secret. Start from the repository root:

```powershell
docker compose --env-file infra/file-ledger/.env -f infra/file-ledger/compose.yaml up -d --wait
```

Init scripts run only on empty disks. Startup is not a migration of an existing ledger. Do not delete existing state to rerun bootstrap. Fixture tests leave their fresh synthetic databases and namespaces in place.

### Roles and lifecycle

- `file_ledger_writer` can only append through the SQL routine; `file_ledger_signer` only reads the signed-head and evidence relations. The app signer must use the actual primary read pool. Its Ed25519 private key is trusted configuration outside every database and backup; tests use ephemeral keys.
- A new namespace starts with the initial writer login. `fenceLedgerWriter(scope, nextEpoch, nextWriterRole)` atomically advances the head epoch and binds the named new appender login. Append (including replay) verifies the actual database `SESSION_USER` role OID for that namespace and epoch, not the role or epoch in a caller value. Old credentials cannot append at the new epoch; a role cannot regain writer authority in a namespace where it previously held it. For the synthetic handoff use the separately provisioned `file_ledger_writer_next` pool. Use that pool only after the fence and fresh floor verification. A database clone must preserve its writer binding provenance; do not silently reinterpret role OIDs in another cluster.
- The floor operator can create **only a fresh, server-generated** namespace and incarnation, with the initial key fingerprint, epoch and genesis hash. The floor verifier can read floor rows and perform a bounded compare-and-pin; it cannot initialize a namespace. Admin and operator credentials are independent from execution credentials.
- Call `bootstrapFileLedgerNamespace` only with the two privileged operator pools and an explicitly pinned public key. Use the returned namespace/incarnation, initial epoch and genesis in trusted tool configuration. Configure the ledger signer and the verifier separately with the intended signer key and pools. A partially acknowledged bootstrap does not authorize use; do not retry against a chosen old identity.
- After reading a fresh challenged signed head, the verifier authenticates the full bounded proof to the current floor and any supplied snapshot anchor. It uses a synchronous WAL-committed floor CAS before returning membership or lineage. CAS changes require re-verification; missing floor, rollback, fork, stale writer epoch, unknown acknowledgement or a proof larger than the configured caps denies. Nothing reconstructs a missing floor from the ledger or from a snapshot.
- Membership is process-local evidence for the exact graph; it does not itself authorize storage access or restore. The caller must separately hold the live source authority, main runtime fence, exact current intent decision/claim and hold evidence. Epoch fencing stops old ledger appends; it cannot recall a storage request already sent.

### Focused test

```powershell
$env:FIXLEVELUP_ISOLATED_FILE_LEDGER_TESTS='1'
pnpm exec vitest run apps/api/tests/file-ledger.test.ts
```

The suite includes two competing PG connections and an observed lock edge, committed retry vs. rollback atomicity, ACL and immutable history, proper floor CAS retry, valid fresh signatures from an old restored ledger database, signed same-height and longer forks, and a verifier restart against an empty third-store database. Tests use synthetic UUIDs/targets, not stored real file bytes. The durability trust model is the independent floor service, its storage and operators; this is not physical WORM, not protection against privileged manipulation of the trusted floor, and not a production recovery procedure.