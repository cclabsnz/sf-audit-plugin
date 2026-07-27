# Bundled font attribution

These `.woff2` files are third-party fonts redistributed inside `@cclabsnz/sf-core` so that
generated reports can embed them as data URIs and never call out to a font CDN. They are **not**
CloudCounsel work and are not covered by this repository's Apache-2.0 licence.

All four families are licensed under the **SIL Open Font License, Version 1.1**. The full licence
text is in [`OFL.txt`](./OFL.txt) alongside these files, as OFL §1 requires when redistributing.

| Family | Files | Copyright |
| --- | --- | --- |
| DM Sans | `dm-sans-normal-latin.woff2`, `dm-sans-italic-latin.woff2` | Copyright 2014–2021 The DM Sans Project Authors (https://github.com/googlefonts/dm-fonts) |
| DM Serif Display | `dm-serif-display-normal-latin.woff2`, `dm-serif-display-italic-latin.woff2` | Copyright 2014–2018 The DM Serif Display Project Authors |
| Fira Sans | `fira-sans-400-latin.woff2`, `fira-sans-600-latin.woff2`, `fira-sans-700-latin.woff2` | Copyright (c) 2012–2015, The Mozilla Foundation and Telefonica S.A. |
| Fira Code | `fira-code-400-latin.woff2` | Copyright (c) 2014, The Fira Code Project Authors (https://github.com/tonsky/FiraCode) |

Each file is the **latin subset** as served by Google Fonts, kept to the weights the reports
actually use. The `OFL.txt` header line carries the Fira Code copyright because that is the
upstream file it was taken from; the licence body applies equally to every family listed above.

Reserved Font Names apply per OFL §3 — do not ship modified versions of these files under the
original family names.
