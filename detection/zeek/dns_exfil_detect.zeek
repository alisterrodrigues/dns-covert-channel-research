##! DNS exfiltration detection script.
##! Tracks subdomain label entropy, query volume, and inter-query timing
##! per queried domain. Fires a Notice when thresholds are exceeded.
##!
##! Usage:
##!   zeek -r capture.pcap dns_exfil_detect.zeek
##!   zeek -i eth0 dns_exfil_detect.zeek

module DNSExfil;

export {
    redef enum Notice::Type += {
        ## Fired when a domain shows characteristics consistent with DNS exfiltration.
        Exfil_Suspected,
    };

    ## Average subdomain label length above which the domain is flagged.
    const long_label_threshold: double = 20.0 &redef;

    ## Minimum number of queries to the same domain before analysis is applied.
    const min_query_threshold: count = 5 &redef;

    ## Query rate (queries per minute) above which volume signal fires.
    const high_rate_threshold: double = 10.0 &redef;

    ## Observation window in seconds for rate calculation.
    const observation_window: interval = 60sec &redef;
}

## Per-domain tracking state.
type DomainStats: record {
    query_count:          count    &default=0;
    long_label_count:     count    &default=0;
    total_label_length:   count    &default=0;
    first_seen:           time     &optional;
    last_seen:            time     &optional;
    alerted:              bool     &default=F;
};

## Global table mapping base domain to its accumulated stats.
global domain_stats: table[string] of DomainStats;

## Extract the base domain (everything after the first label) from a full FQDN.
function base_domain(qname: string): string
    {
    local parts = split_string(qname, /\./);
    if ( |parts| < 2 )
        return qname;
    local result = parts[1];
    local i = 2;
    while ( i < |parts| )
        {
        result = fmt("%s.%s", result, parts[i]);
        ++i;
        }
    return result;
    }

## Compute a simple character-diversity proxy for a label.
## Returns the ratio of unique characters to total length.
## Higher values indicate more uniform character distribution (encoded data).
function label_diversity(label: string): double
    {
    if ( |label| == 0 )
        return 0.0;
    local seen: set[string];
    local i = 0;
    while ( i < |label| )
        {
        add seen[label[i]];
        ++i;
        }
    return |seen| / (|label| + 0.0);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( query == "" )
        return;

    ## Strip trailing dot if present.
    local q = query;
    if ( |q| > 0 && q[|q|-1] == "." )
        q = q[0:|q|-1];

    local parts = split_string(q, /\./);
    if ( |parts| < 2 )
        return;

    ## The subdomain label is the first component.
    local subdomain = parts[0];
    local base = base_domain(q);

    ## Skip the terminator label.
    if ( subdomain == "done" )
        return;

    if ( base !in domain_stats )
        domain_stats[base] = DomainStats();

    local stats = domain_stats[base];
    stats$query_count += 1;
    stats$total_label_length += |subdomain|;

    if ( ! stats?$first_seen )
        stats$first_seen = network_time();
    stats$last_seen = network_time();

    if ( (|subdomain| + 0.0) > long_label_threshold )
        stats$long_label_count += 1;

    domain_stats[base] = stats;

    ## Only evaluate after minimum query threshold is reached.
    if ( stats$query_count < min_query_threshold )
        return;

    if ( stats$alerted )
        return;

    local avg_label_len = stats$total_label_length / (stats$query_count + 0.0);
    local long_label_ratio = stats$long_label_count / (stats$query_count + 0.0);

    ## Rate calculation: queries per minute within the observation window.
    local elapsed = stats$last_seen - stats$first_seen;
    local rate = 0.0;
    if ( elapsed > 0sec )
        rate = stats$query_count / (interval_to_double(elapsed) / 60.0);

    local signals: vector of string = vector();
    local fired = F;

    if ( avg_label_len > long_label_threshold )
        {
        fired = T;
        signals += fmt("avg_label_len=%.1f > threshold %.1f",
                        avg_label_len, long_label_threshold);
        }

    if ( rate > high_rate_threshold )
        {
        fired = T;
        signals += fmt("query_rate=%.1f/min > threshold %.1f/min",
                        rate, high_rate_threshold);
        }

    if ( long_label_ratio > 0.7 )
        {
        fired = T;
        signals += fmt("long_label_ratio=%.2f (%.0f%% of queries have long labels)",
                        long_label_ratio, long_label_ratio * 100);
        }

    if ( fired )
        {
        local signal_str = "";
        local j = 0;
        while ( j < |signals| )
            {
            if ( j > 0 )
                signal_str += "; ";
            signal_str += signals[j];
            ++j;
            }
        NOTICE([$note=Exfil_Suspected,
                $conn=c,
                $msg=fmt("DNS exfiltration suspected: %s — %s (queries=%d)",
                          base, signal_str, stats$query_count),
                $identifier=base]);
        domain_stats[base]$alerted = T;
        }
    }
