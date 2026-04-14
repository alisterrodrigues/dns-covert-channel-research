# Detection Limits and Known Evasion Surface

This document describes what the detector reliably catches, what it misses, and what is genuinely out of scope for a research tool versus a production SOC deployment. Gaps that could be closed with code changes have been addressed; what remains here represents either fundamental limitations of the technique or production-scale requirements that are outside the scope of this project.

## What the Detector Catches Reliably

**Encoded payloads with long labels.** Any session where the average subdomain label exceeds 20 characters triggers the label length signal regardless of encoding scheme. Encoded labels in this implementation average 30–37 characters. This signal is the most robust — it requires no knowledge of the encoding and fires even on hex-encoded low-entropy data where the entropy signal is weak.

**Base32 and base64 encoded payloads.** Both schemes produce entropy scores well above the 3.0 threshold. Base32 averages 4.27 bits per character on typical payloads; base64url averages 4.44 bits. The synthetic detection matrix confirms both are detected at high confidence across all three jitter levels tested (0.0, 0.3, 0.8).

**Regular beaconing.** Fixed inter-query delay produces a CV below 0.15, which the beacon detector classifies as high confidence. The basic sender at 0.5-second intervals produces CV ≈ 0.02.

**High-volume sessions.** Any session exceeding 20 queries to the same domain triggers the volume signal. A 285-byte payload is the minimum to exceed this threshold at the default chunk size.

**Sessions from multiple source IPs.** The analyzer tracks all distinct source IPs per domain group and includes them in the signals list when more than one is found.

**Extra-label prepending attacks.** Fixed. The grouping algorithm anchors to the last two labels of each FQDN. An attacker prepending throwaway labels (`x1.00_h_data.exfil.invalid`, `x2.00_h_data.exfil.invalid`) still aggregates under `exfil.invalid` — the bypass no longer works.

## What Evades the Current Detector

**Slow, low-volume exfiltration.** A payload of 284 bytes or fewer encodes to 19 data chunks plus one terminator — exactly 20 total queries, at the threshold but not above it. Splitting a credential dump across multiple slow, small sessions defeats both volume detection and beaconing detection simultaneously. The volume threshold is a configurable parameter (`--threshold-volume`) but any fixed threshold has this property.

**Timing randomisation.** The evasion variant raises CV from 0.02 to approximately 0.48 by drawing inter-query delays from a uniform 0.5–3.0 second distribution. This exceeds the 0.30 cutoff and removes the beacon signal from the output entirely. The session is still detected via entropy and label length, but a pure timing-only detector would miss it.

**Hex encoding of highly repetitive data.** Hex-encoded English text produces entropy around 3.15 bits — only 0.15 bits above the 3.0 threshold. A payload consisting of highly repetitive data (repeated keys, padding bytes, null sequences) could push the entropy score below the threshold. Applying compression before encoding would lower entropy further.

## Encoding Comparison

Results from `python -m cli.main research --matrix` against a fixed 960-byte payload with seed 42:

| Encoding | Avg Entropy | Detected | Beacon (j=0.0) | Beacon (j=0.8) |
|----------|-------------|----------|----------------|----------------|
| hex      | 3.14        | Yes      | high           | low            |
| base32   | 4.27        | Yes      | high           | low            |
| base64   | 4.44        | Yes      | high           | low            |

The entropy margin is widest for base64 (1.44 bits above threshold) and narrowest for hex (0.14 bits). At high timing jitter, all three remain detected at high confidence because label length and volume signals persist regardless of timing.

## What a Production Deployment Would Add

These are not gaps in this project's design — they are production-scale requirements that belong in a different class of tooling:

**NXDOMAIN ratio tracking.** The current parser filters to DNS queries only. Tracking the ratio of NXDOMAIN responses to queries for the same domain provides an additional signal — exfiltration to a non-resolving domain produces 100% NXDOMAIN, unusual for legitimate traffic. Requires response packet parsing.

**Domain age and passive DNS context.** A newly registered domain queried only from internal hosts is more suspicious than an established CDN domain with similar label patterns. Requires integration with a passive DNS feed or WHOIS enrichment service.

**Allowlist/baseline profiles.** CDN and telemetry domains use long, high-entropy labels for legitimate reasons (cache-busting, signed URLs, tracking tokens). A baseline profile built from observed normal traffic would reduce false positives on production networks significantly. Requires a training data collection phase.

**Zeek Intelligence Framework integration.** The Zeek script fires a notice but does not cross-reference against known bad infrastructure. Wiring the `$identifier` field into Zeek's Intel framework would allow automated IOC correlation.

**ML-based label character modelling.** A character frequency or n-gram model trained on a benign DNS corpus would catch encodings that fall below the entropy threshold but still differ statistically from human-readable labels. Requires a labelled training dataset and introduces a dependency on a modelling framework.
