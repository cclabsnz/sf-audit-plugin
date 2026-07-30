<p align="center">
  <a href="https://cloudcounsel.co.nz"><img src="https://raw.githubusercontent.com/cclabsnz/sf-audit-plugin/main/assets/cloudcounsel-lockup.png" width="240" alt="CloudCounsel Ltd" /></a>
</p>

# CloudCounsel Salesforce `sf` plugins

Read-only `sf` CLI plugins for understanding a Salesforce org: how secure it is, and how it
actually works. A pnpm workspace monorepo sharing one platform layer.

**Local-first by design.** Every command is read-only against the org (SOQL / Tooling / Metadata
reads and describes only), no metadata leaves your machine, and there are no LLM calls, telemetry,
or analytics.

## Packages

| Package | Command | Answers | Status |
| --- | --- | --- | --- |
| **[@cclabsnz/sf-audit](packages/sf-audit-plugin/README.md)** | `sf audit` | *How secure is this org?* — read-only security checks across ten domains, an A-to-F posture score, attack-chain correlation, and compliance mapping across eight frameworks | published on [npm](https://www.npmjs.com/package/@cclabsnz/sf-audit) |
| **[@cclabsnz/sf-orgintel](packages/sf-orgintel-plugin/README.md)** | `sf intel` | *How does this org work?* — capability probe, business-process domain discovery, and cross-object coupling graph | in development |
| **[@cclabsnz/sf-core](packages/core)** | *(library)* | Shared platform layer: API clients, org context, event-log pull, report shell, versioned IR schemas | internal |

**Start here:** most people want the security audit — see
**[packages/sf-audit-plugin/README.md](packages/sf-audit-plugin/README.md)** for the full
documentation, including every check, the scoring model, the compliance frameworks, and the
minimum read-only permission set.

## Install

```bash
sf plugins install @cclabsnz/sf-audit
sf audit security --target-org myOrg
```

That runs the full check suite and writes an HTML report to the current directory. See the
[plugin README](packages/sf-audit-plugin/README.md) for options, report formats, the free
`EventLogFile` baseline (`sf audit events pull`), and connected-app least-privilege analysis
(`sf audit apps`).

## Development

```bash
pnpm install            # installs all workspace packages
pnpm build              # pnpm -r build
pnpm test               # pnpm -r test
sf plugins link packages/sf-audit-plugin
```

Requires Node.js 18+, Salesforce CLI (`sf`) v2+, and pnpm.

- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Releases:** [docs/RELEASE.md](docs/RELEASE.md)
- **Permissions:** [packages/sf-audit-plugin/PERMISSIONS.md](packages/sf-audit-plugin/PERMISSIONS.md)

## Commercial support

These plugins are free and open source. If you'd like hands-on help — interpreting findings,
prioritising remediation, or a full Salesforce security and architecture review —
**[CloudCounsel](https://cloudcounsel.co.nz)**, the team behind them, offers Salesforce security
consulting. Reach us at [hello@cloudcounsel.co.nz](mailto:hello@cloudcounsel.co.nz).

## License

Apache-2.0 — see [LICENSE](LICENSE).
