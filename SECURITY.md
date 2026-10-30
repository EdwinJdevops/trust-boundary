# Security policy — experimental release

No code in this repository is approved to control production infrastructure.
Report suspected vulnerabilities privately to the repository maintainer via GitHub private vulnerability reporting if enabled, or through a private contact channel published by the maintainer. Do not publish secrets, exploit chains, or customer data in public issues.

## Trust boundaries
The caller supplies the observed artifact digest; the library does not measure live Kubernetes state, prove workload identity, isolate hostile code, authenticate remote clients, or secure a deployment credential. A privileged attacker able to modify replay storage can defeat replay protection. The deployment validator accepts a limited subset of Kubernetes JSON; it is not a substitute for API admission or RBAC.

## Release requirements
Before production consideration: independent identity attestation, dedicated executor identity, tightly scoped Kubernetes Role/RoleBinding, secure storage and key rotation, artifact digest confirmation from registry and live workload, server-side enforcement, external audit, failure injection, and adversarial multi-user tests.

Experiment 013 adds a Kubernetes server-side dry-run client. This is NOT production isolation or an enforcement proxy. The underlying Kubernetes identity must be protected; a token capable of dry-run create may be authorized for ordinary create. Do not expose this code as an Internet-facing service or use it to authorize production deployment without the missing protected-executor controls.
