# Secret exposure incident response

Removing a credential from the latest commit is not containment. Use this sequence.

## 1. Rotate before investigating deeply

Revoke or rotate the credential through its provider. If rotation creates a replacement, store it in
the approved secret manager and deploy it without placing it in shell history, chat, tickets, or
commits. For asymmetric keys, replace the key pair and remove trust for the old public key.

## 2. Establish exposure scope

Record the first commit/path from `leaklens scan --history`, repository visibility at the time,
remote pushes, forks, clones, CI jobs, artifacts, container images, packages, logs, and caches. Assume
a public credential was copied immediately. For private repositories, use audit evidence rather than
assuming no access.

## 3. Review use

Inspect provider audit logs from before the earliest exposure through revocation. Look for unfamiliar
source addresses, agents, regions, resources, privilege changes, data access, and new credentials.
Escalate according to the asset and data protected by the credential.

## 4. Remove current and historical material

Replace inline configuration with environment/secret-manager references. History rewriting may be
appropriate, but it is a coordinated destructive operation: protect evidence, notify collaborators,
rewrite all refs/tags, force-push intentionally, expire server caches where supported, and have every
clone rebase or reclone. Rotation remains mandatory because forks and caches may persist.

## 5. Prevent recurrence

Install staged scanning, run full worktree scans in CI, protect required checks, reduce credential
scope/lifetime, prefer workload identity over static keys, and alert on provider-side credential use.
Track the incident through closure without pasting the credential into the ticket.

