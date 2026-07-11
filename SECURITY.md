# Security policy

## Supported versions

The latest release and current default branch receive security fixes.

## Report privately

Use GitHub private vulnerability reporting for vulnerabilities in LeakLens. Do not open a public
issue containing a bypass sample derived from a live credential, a denial-of-service payload, a
repository containing secrets, or output that exposes private paths or infrastructure.

Useful reports include the affected version, source adapter, minimal synthetic reproducer, expected
behavior, actual behavior, impact, and suggested fix. Expect acknowledgement within seven days.

## Operator guidance

LeakLens is an offline static detector, not proof that a credential is valid or invalid. Treat every
real finding as sensitive, rotate before cleanup, and protect reports/baselines as security metadata.
Run history scans on trusted repositories as an unprivileged user.

