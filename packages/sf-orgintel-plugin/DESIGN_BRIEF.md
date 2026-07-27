# Design Brief: Bench Instrument

Governs all UI for the **OrgIntel viewer** — the surface that consumes `landscape-manifest.json`
and `coupling-graph.json` and lets a Salesforce architect navigate an org's domains (L0 → L4).
Read this before touching any viewer markup or styles.

## Concept

The org is a specimen on a laboratory bench, and the viewer is the instrument measuring it —
a daylight Braun/Dieter Rams bench unit, not another dark HUD. Every value on screen is a
calibrated reading against a visible scale, never a floating number: coupling weight has a
gauge, automation density has a ramp, record volume has a size. The chassis is honest about
what the instrument is and isn't — `READ-ONLY · NO EGRESS` is printed on the case because
those are enforced product properties, not marketing. The feeling is *measured confidence*:
an architect should be able to point at any mark on screen and say what produced it.

Chosen over Survey Contour and Interchange because it is the only direction where **coupling
weight — the actual product claim — survives contact with real data.** Interchange made the
better picture and lost the measurement; that trade is not available to an evidence tool.

**Audience:** client-side Salesforce admin / architect. A technical peer who will drill into
specific flows and objects, wants API names not friendly labels, and needs to defend findings
to their own team. Density is a feature. Explanatory hand-holding is not.

**Delivery constraint (hard):** a single self-contained HTML file. Fonts embedded as data
URIs, all JS inlined, manifest JSON inlined. No CDN, no `<script src>`, no `<link rel=stylesheet>`
to a remote host — `test/unit/invariants/network-egress.test.ts` fails the build otherwise.
That invariant is the reason the "no egress" claim on the chassis is true.

## Tokens

```css
--panel:  #E8E6E1;  /* instrument face */
--case:   #DAD7D0;  /* chassis bar */
--screen: #DFDCD5;  /* plot ground */
--edge:   #9A968E;  /* bezel / rule */
--ink:    #111111;
--dim:    #5E5A53;  /* secondary text, tick labels */
--cad:    #F2C200;  /* cadmium — SELECTION ONLY, never decoration */
--red:    #B3261E;  /* needle, redline */
```

Automation density uses a **neutral graphite ramp**, not the accent:
`#C9C5BD → #8E8A82 → #5E5A53 → #2B2823`. If cadmium appears on something the user did not
select, it is a bug.

**Type**
- Display / numerals: **Space Grotesk** 500/700 — `font-variant-numeric: tabular-nums` on every figure
- Body: **Switzer** 400/500
- Labels, readouts, all instrument text: **Martian Mono** 400/600, uppercase, `letter-spacing: .1em`
- Scale: 9px tick labels · 10px readouts · 13px body · 19px values · 34px hero figure

**Geometry:** 2px chassis borders, 1px internal rules, 4–5px radius on the outer case only —
everything inside is square. Panel gutters 18–20px. No drop shadows inside the case; depth
comes from `inset 0 1px 0 #fff` highlights against `--edge` borders.

## Motion

Personality: **mechanical/precise**. Nothing bounces except a needle.

```css
--ease-snap: cubic-bezier(0.7, 0, 0.2, 1);
--ease-settle: cubic-bezier(0.34, 1.2, 0.64, 1); /* needle only */
```
- Hover / selection response: **140ms** `--ease-snap`
- Panel readout swap: **180ms**
- Needle travel: **420ms** `--ease-settle`, slight overshoot then settle
- Entrance stagger: **40ms** between siblings, mechanical and even
- **Signature — instrument self-test:** on load, needles sweep full-scale and settle back;
  pins latch in on a 40ms stagger; tick marks draw before the plot populates
- `prefers-reduced-motion`: keep opacity fades and the readout swap, kill the needle sweep,
  the stagger, and all transforms

## Signature moment (how it is built)

Hovering or selecting a coupling **slams a calibrated needle to that pair's weight**. The gauge
carries numbered major ticks, minor divisions, and a redline band above the org's 90th-percentile
weight, so the reading is interpretable without a legend. Canvas or inline SVG, driven by the
same `weight` value the table prints — one number, three simultaneous encodings (needle, bar,
figure). Cursor magnetism snaps to the nearest pin within ~14px.

## Encodings (non-negotiable — the concept is measurement)

| Datum | Encoding |
| --- | --- |
| Coupling weight | Edge stroke width + needle + numeric, always all three |
| Automation density | Pin fill on the graphite ramp |
| Record volume (90d) | Pin size |
| Custom vs standard object | Pin border weight |
| Selection | Cadmium fill + full-opacity edges, everything else drops to 25% |
| Domain (cluster) | Position — L0 places domains, L1 places objects within one |

## What this concept is NOT

1. **Not a dark HUD.** No black background, no neon, no glow. It is a daylight object.
2. **Not glassmorphic.** No blur, no translucency, no layered frosted panels.
3. **Not a force-directed hairball.** Edges are measured connections between calibrated points,
   and the plot must be fitted to its data with even margins — never a sparse scatter in a void.
4. **Not decorative-instrument.** A gauge with an arbitrary maximum, an unnumbered scale, or a
   needle that can exceed full-scale is worse than a plain number. If it looks like it measures,
   it measures.
5. **Not a poster.** Anything that looks interactive is interactive. Inert elements must look
   inert.
6. **Not friendly.** No rounded-happy shapes, no emoji, no exclamation marks. API names in full,
   `Invoice__c` not "Invoice". The voice is a calibration certificate.
