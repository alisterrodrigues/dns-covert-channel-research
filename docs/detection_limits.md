# Detection Limits and Known Evasion Surface

This document describes what the detector reliably catches, what it misses, the conditions under which the evasion variant succeeds and fails, and what a production deployment would need to close the gaps. It is intended as an honest engineering assessment, not a claim of completeness.

## What the Detector Catches Reliably

**Encoded payloads with long labels.** Any session where the average subdomain label exceeds 20 characters triggers the label length signal regardless of encoding scheme. Encoded labels in this implementation average 30–37 characters. This signal is the most robust — it requires no knowledge of the encoding and fires even on hex-encoded low-entropy data where the entropy signal is weak.

**Base32 and base64 encoded payloads.** Both schemes produce entropy scores well above the 3.0 threshold. Base32 averages 4.27 bits per character on typical payloads; base64url averages 4.44 bits. The synthetic detection matrix confirms both are detected at high confidence across all three jitter levels tested (0.0, 0.3, 0.8).

**Regular beaconing.** Fixed inter-query delay produces a CV below 0.15, which the beacon detector classifies as high confidence. The basic sender at 0.5-second intervals produces CV ≈ 0.02. This is a strong signal for automated tools but says nothing about encoding.

**High-volume sessions.** Any session exceeding 20 queries to the same domain triggers the volume signal. A 285-byte payload is the minimum to exceed this threshold at the default chunk size.

## What Evades the Current Detector

**Slow, low-volume exfiltration.** A payload of 284 bytes or fewer encodes to 19 data chunks plus one terminator — exactly 20 total queries, at the threshold not above it. Splitting a credential dump across multiple slow, small sessions defeats both volume detection and beaconing detection simultaneously.

**Timing randomisation.** The evasion variant raises CV from 0.02 to approximately 0.48 by drawing inter-query delays from a uniform 0.5–3.0 second distribution. This exceeds the 0.30 cutoff and removes the beacon signal from the output entirely. The session is still detected via entropy and label length, but confidence cannot reach `high` through the beacon pathway alone.

**Hex encoding of repetitive plaintext.** Hex-encoded English text produces entropy around 3.15 bits — only 0.15 bits above the 3.0 threshold. A payload consisting of highly repetitive data (repeated keys, padding bytes, null sequences) could push the entropy score below the threshold. Applying compression before encoding would lower entropy further, potentially defeating the entropy signal while keeping data intact.

**Extra-label prepending.** The analyzer groups queries by base domain using the first label as the subdomain. An attacker can prepend a throwaway label — `x1.00_h_data.exfil.invalid` — causing each query to group under a different base domain (`00_h_data.exfil.invalid`, `01_h_data.exfil.invalid`, etc.). Each group contains one query and is discarded. This bypasses aggregation entirely.

## Encoding Comparison

Results from `python -m cli.main research --matrix` against a fixed 960-byte payload with seed 42:

| Encoding | Avg Entropy | Detected | Beacon (j=0.0) | Beacon (j=0.8) |
|----------|-------------|----------|----------------|----------------|
| hex      | 3.14        | Yes      | high           | low            |
| base32   | 4.27        | Yes      | high           | low            |
| base64   | 4.44        | Yes      | high           | low            |

All three encoding schemes are detected at high confidence regardless of timing jitter. The entropy margin is widest for base64 (1.44 bits above threshold) and narrowest for hex (0.14 bits). An attacker choosing hex encoding of compressible data has the smallest entropy margin to work with and the best chance of dropping below the threshold.

## What a Production Deployment Would Add

**Request/response distinction and NXDOMAIN ratio.** The current `parse_pcap()` filters to DNS queries only (QR=0). In a real deployment, tracking the ratio of NXDOMAIN responses to queries provides an additional signal — exfiltration to a non-existent domain produces 100% NXDOMAIN, which is unusual for legitimate traffic.

**Per-source-IP aggregation.** The current analyzer groups by base domain only. A production tool would aggregate by `(src_ip, base_domain)` pair, enabling detection of distributed sessions where the same host queries multiple domains at low volume.

**Domain age and passive DNS context.** A newly registered domain queried only from internal hosts is far more suspicious than an established CDN domain with similar label patterns. Integration with a passive DNS feed or WHOIS enrichment would reduce false positive rates on legitimate services with long cache-busting labels.

**Allowlist/baseline profiles.** CDN and telemetry domains — Akamai, Cloudflare, Google, Microsoft update infrastructure — use long, high-entropy labels for legitimate reasons. A baseline profile built from a week of normal traffic would dramatically reduce false positives on production networks.

**Zeek Intelligence Framework integration.** The Zeek script in `detection/zeek/dns_exfil_detect.zeek` fires a notice but does not cross-reference against known bad infrastructure. Wiring the `$identifier` field into Zeek's Intel framework would allow correlation against threat intelligence feeds.

**ML-based label character modelling.** A simple n-gram or character frequency model trained on a benign DNS corpus would catch encodings that fall below the entropy threshold but still differ from human-readable labels in their character distribution. This would close the hex-of-repetitive-data gap that the current threshold-based approach misses.
