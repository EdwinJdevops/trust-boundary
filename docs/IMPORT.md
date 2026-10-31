# Import provenance

The user supplied `trust-boundary-complete-work-handoff (6).zip` on 2026-10-30.
SHA-256: `c5d8f71a1ba4b5378b0c883915bba53e6d39e78b2016cab1acb252240e042465`.
All 13 archive digests match the supplied checksum list. All latest v0.13 files
match the corresponding historical v0.13 ZIP byte for byte.

The initial source import preserves the original Go files, README, SECURITY.md,
workflow, handoff and historical archives. Historical ZIPs are reference material,
not active dependencies. Their original hashes remain in
`history/HISTORY_SHA256SUMS.txt`; paths there refer to the original package layout.
The archive bytes are stored under `history/archives/`.

The user explicitly selected Apache-2.0. This is not an external audit. The handoff's
previous Linux test results are historical assertions until independently rerun.
The original same-UID adapter bypass, unverified sandbox containment, caller-supplied
artifact measurement and local-only durability limits remain security blockers.

The first Windows rerun passed deploycheck, but replay tests failed closed because
Windows does not expose the required Unix private-directory permissions. Sandboxed
loopback restrictions also blocked positive TLS tests. These are not passing Linux
enforcement results and must not be worked around by relaxing permission checks.
