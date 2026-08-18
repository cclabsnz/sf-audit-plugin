# Installation

```bash
sf plugins install @cclabsnz/sf-audit
```

**You will be warned that this plugin is not digitally signed.** That is expected, and it is not a judgement on this plugin. Salesforce's signature verification only accepts public keys served from `developer.salesforce.com`, so no third-party plugin can satisfy it: every community plugin in the ecosystem produces the same prompt. Answer `y` to continue.

Since "trust us" is a poor answer from a tool that authenticates against your production org, the guarantees this project offers are ones you can check yourself rather than take on faith. Releases carry signed npm provenance, so you can confirm the published tarball was built from the exact public commit, and the read-only promise is enforced by a test that fails the build if a single write path appears in the source:

```bash
npm audit signatures   # reports "verified attestations" for @cclabsnz/sf-audit
```

See [Trust & verification](../README.md#trust--verification) for the full list, including the no-network-egress guard and the independent scans.

For CI or any unattended install, where an interactive prompt would hang the job, allowlist the package on the machine doing the installing:

```jsonc
// macOS and Linux: ~/.config/sf/unsignedPluginAllowList.json
// Windows:         %LOCALAPPDATA%\sf\unsignedPluginAllowList.json
["@cclabsnz/sf-audit"]
```

Or, for local development:

```bash
git clone https://github.com/cclabsnz/sf-audit-plugin.git
cd sf-audit-plugin
npm install
npm run build
sf plugins link .
```
