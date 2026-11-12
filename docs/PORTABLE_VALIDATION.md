# Portable validation and evidence

This is an experimental alternative execution path during hosted CI outages.
It preserves the full local suite, including the real disposable Kubernetes test.
It does not replace repository branch protection, independent human review or an
independent validator. It does not authorize a deployment.

## Single entry point

On a dedicated, disposable Linux amd64 host with the existing Go, Git, Docker,
kubectl, GNU coreutils, curl and setpriv tools, start the local Docker engine.
Use reviewed source: tests execute code and the root integration harness is not a
hardened sandbox for arbitrary pull requests. Never install this as a permanent
runner on a workstation containing production credentials.

Check out the exact approved commit, ensure the checkout is clean, and run:

```sh
sudo env "PATH=$PATH" bash scripts/verify-commit.sh FULL_40_CHARACTER_COMMIT /new/output/directory
```

The output directory must not already exist. No cloud resources or signing keys
are provisioned. Submodules and symlinks are rejected for this first version.
The supervisor exports exact Git archive bytes and extracts a snapshot onto Linux
storage. Tests run as UID 21003 with a private home/cache, a read-only source tree,
no inherited credentials, no Go workspace overrides and dependency networking off.
This removes inherited environment authority but is not kernel/network containment.

All seven checks are mandatory: format, full build, vet, race/adversarial tests,
integration compilation, historical archive integrity and real Kubernetes
enforcement. The reviewed root integration stage uses its existing separate
caller/executor identities and only a new kind cluster. Stage output is bounded
to 32 MiB and each command has a timeout. A failure stops the run, preserves logs
and writes a failed outcome; no successful statement is issued. SIGKILL, power
loss or a compromised root supervisor can still interrupt cleanup.

The worker-built tbverify executable is compared byte-for-byte by SHA-256 with a
supervisor rebuild before evidence is recorded. Both builds use trimpath and
disable VCS stamping. This is a same-host consistency check, not an independent
reproducible-build result or protection from a compromised compiler.

## Bundle contents and interpretation

The bundle contains source.tar, the built tbverify artifact, suite.sha256,
coverage.out, fixed-name logs, statement.json and integrity.json. The statement
binds the full Git commit, source bytes, built artifact, validation harness, tool
metadata, execution interval, all seven exit codes and exact log digests.

The suite manifest hashes the runner, integration harness, cluster policy and
recorder/verifier source. Operator trust must be pinned to reviewed code outside
the untrusted bundle. A self-reported suite digest is not a trusted policy.

An administrator-controlled verifier can inspect received bytes using:

```sh
tbverify inspect --statement bundle/statement.json --logs bundle/logs \
  --source bundle/source.tar --artifact bundle/tbverify --suite bundle/suite.sha256
```

Do not execute an untrusted received tbverify binary to decide whether that binary
or its own bundle is trustworthy. Use a previously reviewed installed verifier.
Integrity success explicitly returns `authentication: not-verified`.

## Independently signed validation

The evidence library provides domain-separated Ed25519 signing and quorum
verification. No runner key-generation, private-key loading or auto-enrollment
exists. A separate validator must review the source, rerun the full suite in its
own controlled environment, verify the bundle contents and attest its own result.
Do not sign somebody else's logs as if they were an independent rerun.

`tbverify verify --policy trusted-policy.json --attestation validator-a.json
--attestation validator-b.json` checks at least two distinct configured public keys,
the exact expected commit/source/artifact/suite, complete passing checks, signature
domain/identity binding, bounded execution interval and freshness (at most 24h).
Two identities using one key, an unknown key, stale/future evidence, failed checks
or changed digests are denied. Every supplied attestation must be valid. Keys and
expected digests come from independently installed policy, never from the bundle.

All documents use the canonical JSON emitted by Go encoding/json for these fixed
versioned structs; reordered/indented documents, duplicate keys, case aliases,
unknown fields and trailing data are rejected. The trusted policy schema is
defined by `DiskPolicy` in `internal/evidencefiles/files.go`, using hex Ed25519 public
keys. This custom research format is not DSSE, in-toto or SLSA provenance.

The protected executor requires a fresh quorum before consuming the grant and
checks freshness again before sending POST. The trusted operator supplies
`Config.ValidationPolicy` and `Config.Attestations`. The policy pins the source
archive and deployable artifact digests, commit, suite and validator public keys.
The executor matches those digests against the signed intent and independent
artifact measurement. It rejects reuse of the release signer's key as a
validator key. Deployments for another source or artifact require a new policy.

The portable runner records the digest of its verifier executable. Deployment
attestations must instead cover the actual release artifact. The integration
fixture models that binding using temporary keys and synthetic check receipts.
Independent validator enrollment, signing operations and release provenance
remain production gates. Separate keys establish cryptographic separation.
Operational independence requires separate control over those keys and runners.

Recovery retains the version-2 journal format and verifies the original release
signature before a read-only GET. Historical recovery can proceed with an empty
attestation set and valid operator policy. The journal records release
authorization. Validator receipts belong in the operator's evidence store.

## Issue validator evidence

Build `tbattest` on Linux and run it under the validator's own identity. Keep the
key and trusted policy outside the runner's control. Each validator reviews and
reruns the approved suite, then transfers its own statement and files into
private staging. Supply the actual deployable artifact when issuing deployment
evidence. The supervisor's verifier executable digest serves the portable
verification workflow.

The operator enrolls the validator's public key in the trusted policy. The issuer
expects an existing Ed25519 PKCS#8 DER private key owned by the signer with mode
0400 or 0600. Use trusted parent directories and keep staged inputs stable during
issuance. The issuer checks policy scope, freshness and bundle hashes, then checks
that the key matches the enrolled identity. It emits a single canonical attestation
to standard output.

```sh
go build -o tbattest ./cmd/tbattest
```

From the validator's staging directory, invoke the trusted binary:

```sh
/path/to/tbattest --policy trusted-policy.json --validator validator-a --key validator-a.der \
  --statement statement.json --source source.tar --artifact release-artifact \
  --suite suite.sha256 --logs logs > validator-a.json
```

Repeat under the other validator's independent control and verify the resulting
quorum with `tbverify verify`. The operator's review establishes which run produced
the inputs. The issuer checks the supplied bytes and signs the reviewed statement.

## Replace or revoke a validator key

Each executor takes a snapshot of its policy and attestations at construction.
Editing a policy file leaves existing executor instances with their original keys.
For a planned rotation, stage the replacement public key and a fresh quorum first.
For a suspected compromise, stop admitting new deployment requests immediately
and stop or isolate every executor that still trusts the affected key. Inspect
in-flight creates through the existing read-only recovery path.

Remove the affected public key from the trusted policy and discard attestations
made with that key. Obtain a fresh quorum from the resulting enrolled set. If the
remaining set cannot meet the existing threshold, keep deployment paused until
another validator is enrolled. Verify the replacement quorum with `tbverify verify`
and construct new executor instances using the updated policy and evidence. Keep
the existing journal directory so previously consumed grants stay consumed.

## Remaining gates

Enroll independently controlled validators, exercise the key replacement procedure,
approve toolchains, and protect signing outside test execution. Test issuance
and verification with production identities and release evidence. Repository
controls are recorded in [Repository settings](REPOSITORY_SETTINGS.md).

Design reference: [SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
requires configured trust roots and artifact/policy matching; the present work
does not claim a SLSA level. Ed25519 uses Go's existing standard library.
