# `signatures.json` schema

The JSON feed consumed by the NekoBox Hardening Fork's Phase 4
`HostileSignatureUpdater`. Every field is optional except `version`.
Client behavior for missing fields: fall back to the built-in list
for that layer.

## Top-level shape

```json
{
  "version": 1,
  "updated_at": "2026-04-11T15:00:00Z",
  "package_prefixes":       [ "ru.yandex.", "com.yandex.", ... ],
  "cert_fingerprints":      [ "A5:12:34:56:...:F7", ... ],
  "metadata_keys":          [ "io.appmetrica.analytics.API_KEY", ... ],
  "provider_authorities":   [ "io.appmetrica.analytics", ... ],
  "suspicious_permissions": [ "android.permission.QUERY_ALL_PACKAGES" ],
  "class_prefixes":         [ "io.appmetrica.analytics", "com.vk.sdk", ... ],
  "domain_patterns":        [ "mc.yandex.ru", "appmetrica.yandex.net", ... ]
}
```

## Field semantics

### `version` (int, required)

Monotonic counter. The client rejects any update whose `version` is
less than or equal to the stored version. To roll back a bad entry,
publish a new version with the entry removed.

### `updated_at` (ISO-8601 string, optional)

Purely informational — for humans reading the feed and for the GitHub
Action's commit message. Clients ignore this field.

### `package_prefixes` (list of strings)

Package name prefixes for Layer 1 (`HostilePackagePatterns.matches`).
Each entry is matched via `startsWith`. Trailing `.` recommended to
avoid accidental substring matches — `"ru.yandex."` matches
`ru.yandex.taxi` but not `ru.yandexlookalike`.

### `cert_fingerprints` (list of strings)

SHA-256 hashes of signer certificates, colon-separated **uppercase**
hex (e.g. `"A5:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77"`).
Used by Layer 2 (`HostileCertificates.check`). Matching is by exact
string equality after the client computes SHA-256 of each installed
app's signer cert.

### `metadata_keys` (list of strings)

Android manifest `<meta-data android:name="...">` keys declared by
hostile SDKs during auto-init. Used by Layer 3
(`HostileManifestMarkers.check`). Matching is by exact string equality.

### `provider_authorities` (list of strings)

Substrings of Android content provider authorities registered by
hostile SDKs. Used by Layer 3 (`HostileManifestMarkers.checkProviders`).
Matching is via `String.contains` so shorter entries like
`"io.appmetrica.analytics"` match the full authority like
`"io.appmetrica.analytics.multiprocess.authority"`.

### `suspicious_permissions` (list of strings)

Fully-qualified Android permission names that bump an app's risk
score. Used by Layer 5 (`HostilePermissionCheck.check`). Matching is
by exact string equality against `PackageInfo.requestedPermissions`.
Currently hardcoded at the client to `android.permission.QUERY_ALL_PACKAGES`
but can be extended via this field.

### `class_prefixes` (list of strings)

Java class name prefixes that indicate a hostile SDK is compiled into
the app's DEX bytecode. Used by Layer 4 (`HostileDexScanner.scan`).
Matching is via `startsWith` against the dotted class name — so
`"io.appmetrica.analytics"` matches
`io.appmetrica.analytics.impl.AppMetricaImpl`.

### `domain_patterns` (list of strings)

**Added in signatures v2**, reserved for Phase 4 Layer 6 (DNS blocking).
Domain-suffix patterns that the client passes to sing-box's DNS module
as `reject` rules. Matches any FQDN whose suffix equals one of these
strings. E.g. `"yandex.ru"` matches both `yandex.ru` and
`mc.yandex.ru` and `something.yandex.ru`. Clients that don't support
Layer 6 ignore this field.

## Validation

`build-signatures.py` emits a deterministic sort order within each
field (lexicographic ASCII). This makes git diffs stable across
rebuilds — if the same publishers.yaml is rebuilt the resulting
signatures.json is byte-identical.

## Versioning discipline

- `version` is bumped by `build-signatures.py` if and only if the
  content has actually changed (diff against previous signatures.json).
- If the source YAML changes but normalization produces the same
  output, version is NOT bumped (avoid spurious updates).
- If content changes but the human didn't change the version explicitly,
  the script auto-increments.
