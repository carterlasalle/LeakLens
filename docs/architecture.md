# Architecture and threat model

LeakLens treats repository content as hostile and configuration as trusted project policy.

```text
untrusted bytes → bounded source adapter → text decoder → detector engine → safe Finding → renderer
                  files/Git/stdin        binary skip      raw value dies     no raw-value field
```

## Trust boundaries

### Untrusted content

Files, Git objects, diffs, history paths, encodings, and matched strings are untrusted. The scanner:

- does not follow symlinks unless explicitly configured;
- skips binary content and bounds file/object sizes;
- checks Git object sizes before loading historical blobs;
- invokes Git as an argument vector without a shell;
- applies command timeouts and commit/finding/patch limits;
- never performs provider validation or any other network request;
- redacts a match and computes its fingerprint before constructing a finding.

### Trusted policy

`.leaklens.toml` can define regular expressions. Python's standard `re` engine has no match timeout,
so repository administrators must review custom patterns like code. Built-in expressions avoid
nested ambiguous quantifiers and bound token-sized captures. Keyword prefilters reduce exposure and
cost but do not make an unsafe custom expression safe.

## Data lifecycle

The detector's local `secret` variable exists only while a match is classified. It is used to:

1. test entropy and placeholder policy;
2. compute a domain-separated BLAKE2s fingerprint;
3. create a small redaction showing at most four prefix/suffix characters.

`Finding` has no raw-value field. Baselines, JSON, CSV, SARIF, tables, and exception paths operate
only on the safe model. This is deliberate defense in depth against a second leak through scanner
logs or CI artifacts.

Fingerprints identify repeated findings; they are not password hashes. Very low-entropy values could
be guessed, which is one reason built-in generic findings require entropy and baselines should still
be access-controlled as security metadata.

## Source adapters

| Adapter | Semantics |
| --- | --- |
| Filesystem | Explicit files and recursive directories under exclusion/size/symlink policy |
| Worktree | `git ls-files` tracked plus untracked, respecting `.gitignore` |
| Staged | Only `+` lines in the index diff, relocated to real new-file line numbers |
| History | Oldest-to-newest changed snapshots, deduplicated to first fingerprint/path appearance |
| Standard input | Caller-provided logical filename, no temporary file |

History scans snapshots rather than raw patches so credentials added in binary-to-text transitions or
unusual changes remain visible. A repeated secret in a path is reported once at its first observed
commit; movement to another path is a separate exposure.

## Detector pipeline

Rules are ordered from provider-specific to contextual. Literal keyword prefilters cheaply discard
impossible rules. Regexes produce one named capture, which is then checked for placeholder and
entropy constraints. Overlapping lower-specificity matches are suppressed so one credential does
not become several noisy findings.

Severity represents likely impact; confidence represents pattern specificity. They are intentionally
separate. An AWS access key ID alone is high severity but cannot authenticate without its paired
secret; a private-key header is critical because the surrounding material is almost certainly
sensitive even though LeakLens intentionally retains only the header match.

## Failure semantics

Input/configuration/Git/safety-limit errors produce exit `2`. Findings at or above policy produce
exit `1`. A clean result produces `0`. Errors are never converted to a clean scan, preventing CI from
silently passing when a source could not be inspected.

