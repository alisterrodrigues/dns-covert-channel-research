# PCAP Evidence Walkthrough

The files in `sample_data/` are real packet captures taken on a Kali Linux VM using `tcpdump -i lo -w session.pcap port 53`. Both sessions target `exfil.invalid` over loopback, with `127.0.0.1` as the DNS server. The queries fail to resolve — there is no authoritative nameserver — but the outbound query packets are captured in full, and those packets are all the detection side needs.

## Basic Exfil Session (`exfil_session.pcap`)

This capture was produced by running `DNSSender` with default settings against a ~700-byte ASCII payload repeated 10 times.

**Session parameters:**
- Payload: ~700 bytes of ASCII text
- Encoding: hex (`h` tag)
- Chunk size: 30 characters
- Inter-query delay: 0.5 seconds
- Queries sent: 47 (46 data + 1 terminator)

**What to look for in Wireshark:**

Open the PCAP with `wireshark sample_data/exfil_session.pcap` and apply the filter `udp.port == 53`. Every packet is a DNS query to a subdomain of `exfil.invalid`. The Info column shows the queried names in sequence:

```
Standard query  00_h_5468697320697320612073696d756c.exfil.invalid
Standard query  01_h_61746564206461746120657866696c.exfil.invalid
...
Standard query  45_h_6172636820707572706f7365732e20.exfil.invalid
Standard query  done.exfil.invalid
```

Each label is 33 characters long — the 2-digit sequence prefix (`00_`), the encoding tag (`h_`), and a 30-character hex chunk. Compare that to a normal DNS capture where labels like `www`, `api`, and `cdn-east-1` average 3–12 characters.

The timing between packets is visually regular at roughly 0.5-second intervals. This regularity is what the beacon detector measures.

**Detection output:**

```bash
python -m cli.main detect --pcap sample_data/exfil_session.pcap
```

```
Domain:          exfil.invalid
Confidence:      high
Avg entropy:     3.16
Avg label len:   33.0
Query count:     47
Beacon:          high
Signals:
  - avg entropy 3.16 > threshold 3.0
  - avg label length 33.0 > threshold 20
  - query volume 47 > threshold 20
  - beaconing detected: interval 0.53s, confidence high
```

All four signals fire. Entropy at 3.16 clears the 3.0 threshold — hex encoding of repeated ASCII text is not uniform but it is measurably more diverse than a human-readable label. Label length and volume are well above threshold. The CV of inter-query intervals is approximately 0.02, indicating near-perfect regularity.

## Evasion Session (`evasion_session.pcap`)

The same payload sent through `EvasionSender` with `min_delay=0.5s`, `max_delay=3.0s`, and `padding_chars=4`.

**What differs from the basic session:**

Labels are 37 characters instead of 33 — the four padding characters are visible as an extra suffix on each chunk. Because padding is drawn from the hex alphabet (`0-9a-f`), the padding characters are indistinguishable from payload characters in the label itself. The receiver strips them by filtering to the known encoding alphabet before decoding.

Timing gaps between packets are irregular. Gaps range from roughly 0.5 to 3.0 seconds with no discernible pattern. The CV rises to approximately 0.48.

**Detection output:**

```bash
python -m cli.main detect --pcap sample_data/evasion_session.pcap
```

```
Domain:          exfil.invalid
Confidence:      high
Avg entropy:     3.50
Avg label len:   37.0
Query count:     47
Beacon:          low
Signals:
  - avg entropy 3.50 > threshold 3.0
  - avg label length 37.0 > threshold 20
  - query volume 47 > threshold 20
```

The beacon signal is absent. Timing randomisation worked — CV 0.48 exceeds the 0.30 cutoff and the beacon detector returns `low` confidence. Everything else still fires. Entropy is actually higher than the basic session (3.50 vs 3.16) because the padding characters add character diversity to each label.

## Running the Benchmark

```bash
python -m cli.main benchmark
```

This loads both PCAPs, mixes in 20 synthetic benign DNS queries time-aligned to the capture window, and runs the analyzer against the combined traffic. Detection is reported specifically for `exfil.invalid` so benign traffic false positives do not obscure the result. The committed `analysis/results/benchmark_results.json` records the output of this run.

## Running Zeek Against the PCAP

With Zeek installed:

```bash
zeek -r sample_data/exfil_session.pcap detection/zeek/dns_exfil_detect.zeek
cat notice.log
```

The Zeek script tracks per-domain stats in a `DomainStats` record and fires a `DNSExfil::Exfil_Suspected` notice when average label length, query rate, or long-label ratio exceed their thresholds. The `notice.log` entry will look similar to:

```
1775677126.0  DNSExfil::Exfil_Suspected  DNS exfiltration suspected:
exfil.invalid — avg_label_len=33.0 > threshold 20.0;
long_label_ratio=1.00 (100% of queries have long labels) (queries=47)
```

The Zeek script and the Python detector operate independently but fire on the same signals, providing two separate detection paths against the same capture.
