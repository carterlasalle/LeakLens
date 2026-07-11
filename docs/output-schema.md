# Output schema

JSON output has a top-level `version` of `1` and three fields: `findings`, `stats`, and `errors`.

Each finding contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `rule_id` | string | Stable kebab-case detector identifier |
| `title` | string | Human detector name |
| `severity` | enum | `low`, `medium`, `high`, or `critical` |
| `confidence` | string | Pattern specificity, independent of impact |
| `location` | object | Path, start/end line/column, optional introducing commit |
| `fingerprint` | string | 40-character domain-separated digest |
| `redacted` | string | Limited shape for operator recognition |
| `secret_length` | integer | Original matched character count |
| `entropy` | number | Shannon entropy in bits per character, rounded to 3 decimals |
| `message` | string | Remediation-oriented explanation |
| `tags` | array | Provider and credential-category labels |

The raw matched value is not a private/undocumented field—it does not exist on the finding model.

## Stability

Version 1 may add optional fields. Removing fields, changing their types, changing fingerprint
semantics, or renaming rule IDs requires a new schema/fingerprint version. JSON object key order is
not contractual. Finding order is deterministic for a given source view.

## SARIF

SARIF uses version 2.1.0. Rule severity maps to `error`, `warning`, or `note`; a numeric
`security-severity` property supports code-scanning prioritization. The LeakLens fingerprint is
published as `leakLensSecretFingerprint/v1`. Messages contain only the redacted value.

