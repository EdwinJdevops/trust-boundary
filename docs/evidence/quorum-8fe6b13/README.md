# Deployment quorum verification — 2026-11-05

The seven portable stages passed against commit 8fe6b139d0cc6756e3eb4848b090e89764381e51.
The raw logs cover format, build, vet, race tests, integration compilation,
historical archive checksums and a disposable Kubernetes cluster. The supervisor
also rejected a source archive with altered bytes and accepted the restored copy.

The real-cluster test first denied a signed release without a validation quorum.
It then used the same grant with two valid fixture attestations, created the
Deployment and confirmed that replay failed and read-only recovery succeeded.
Rollout verified one ready container with the measured digest. The harness
rejected an unrelated digest and deleted the test node.

The executor uses separately configured validator and release signing keys. In
this test, one fixture generates all keys and uses synthetic validation receipts.
Production evidence issuance requires separately controlled keys and runners.
The portable bundle records unsigned receipts for this implementation test.

The bundle SHA-256 is 5d7c0a67c8271d647dba1c909de0ffb8af88d433e899368a6d58b83fca1ae238.
The statement file SHA-256 is ad04f63bba4b60acd47b926d0eccdbd5e74fe471c8b97a7aeea7361c9fa168c5.
The statement binds the exact source archive, verifier, suite and log digests.
To reproduce, check out the tested commit and follow the portable validation
instructions in docs/PORTABLE_VALIDATION.md from a disposable Linux environment.
