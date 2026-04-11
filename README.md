# hostile-sigs

Signature database for the [NekoBox Hardening Fork](https://github.com/tr0mb1r/NekoBoxForAndroid/tree/hardening)'s
Phase 4 hostile-app scanner. Updates are fetched by the client at
VPN start time (over the tunnel), version-gated, and merged with the
fork's built-in detection lists.

The client code that consumes this feed is
[`HostileSignatureUpdater.kt`](https://github.com/tr0mb1r/NekoBoxForAndroid/blob/hardening/app/src/main/java/io/nekohasekai/sagernet/scanner/HostileSignatureUpdater.kt)
and [`SignatureRegistry.kt`](https://github.com/tr0mb1r/NekoBoxForAndroid/blob/hardening/app/src/main/java/io/nekohasekai/sagernet/scanner/SignatureRegistry.kt).

## Current version

See `signatures.json`. The `version` field is an integer that must
strictly increase — rollbacks are not supported (to roll back, push a
new version with the entry removed).

## What this repo contains

| File | Purpose |
|---|---|
| `publishers.yaml` | Hand-curated seed list of hostile publishers and their SDK fingerprints |
| `build-signatures.py` | Script that reads `publishers.yaml`, fetches Exodus Privacy's tracker list for cross-referencing, and emits `signatures.json` |
| `signatures.json` | Generated feed. This is what clients download. |
| `SCHEMA.md` | Description of the `signatures.json` schema fields |
| `.github/workflows/build.yml` | Daily cron + manual-trigger workflow that rebuilds and commits the signatures |

## How updates land

```
cron ── build-signatures.py ── diff old vs new signatures.json
                                          │
                                    (if changed)
                                          │
                                          ▼
                              git commit + git push origin main
                                          │
                                          ▼
           raw.githubusercontent.com/tr0mb1r/hostile-sigs/main/signatures.json
                                          │
                                          ▼
     client HostileSignatureUpdater.fetchAndApply() (runs after box.start)
                                          │
                                          ▼
                      SignatureRegistry.applyRemote()
                                          │
                                          ▼
                     5-layer scanner union with built-ins
```

## Contributing new entries

1. Fork this repo
2. Edit `publishers.yaml` — add a new `- publisher:` block with:
   - Required: `publisher`, `country`, `package_prefixes`, `evidence` (a URL documenting why this publisher is hostile)
   - Optional: `class_prefixes`, `metadata_keys`, `provider_authorities`, `cert_sha256`, `sdk_maven`
3. Run `python3 build-signatures.py` locally to validate
4. Open a PR with the diff to `signatures.json` included

Every entry must have an `evidence` URL linking to documentation of
why the publisher is on the list — an SDK docs page, a news article
about state-mandated tracking, a privacy research report, etc. This
keeps false-positive disputes debate-able rather than opaque.

## Data sources

- **Exodus Privacy** (https://reports.exodus-privacy.eu.org/) —
  AGPL-3.0, community-maintained Android tracker database. We use
  their public API to cross-reference `class_prefixes` (what they
  call `code_signature`) for each SDK. Attribution required.
- **Published SDK integration docs** — Yandex AppMetrica, VK SDK,
  MyTracker, etc. all document their `meta-data` keys, content
  providers, and class namespaces publicly. No scraping involved.
- **Maven Central + Yandex's Maven repo** — we inspect published
  AAR files to validate class prefixes are real (not hallucinated).

## License

AGPL-3.0 — because we derive data from Exodus Privacy which is
AGPL-3.0. The NekoBox Hardening Fork that consumes this feed is
GPL-3.0, and AGPL is compatible with GPL for this derivation.

## Threat model scope

This feed targets **on-device SDKs that let third parties (advertisers,
censors, regulatory bodies) determine whether a user is running a VPN
and optionally leak the VPN server's exit IP**. The initial scope is:

- **Russia** — Yandex, VK/Mail.ru, Sberbank, Tinkoff, Kaspersky,
  Gosuslugi, MTS, Beeline, Wildberries, Ozon, and their SDKs, per
  the April 2026 Russian regulatory directive.
- **Iran** — major state-affiliated apps and local ad networks
  relevant to on-device VPN detection.
- **China** — WeChat/Tencent, Alipay/Ant, ByteDance, Baidu,
  Meituan, and similar ecosystems with known anti-VPN behavior.

See `publishers.yaml` for the full current list. The scope may
expand as new threats emerge.
