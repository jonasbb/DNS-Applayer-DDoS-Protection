-- Query can take very long
SET statement_timeout TO 0;

-- Create a table with the following fields
-- location,
-- iprange_src,
-- iprange_dst
-- array_agg(COALESCE(total_packets, 0)
--
-- The array contains one element per aggregation interval (hours) and counts the number of UDP packets for the combination of source and destination.
-- This makes it easier afterwards to look at time-based subsets of the data.
CREATE MATERIALIZED VIEW pre_test_intervals AS
WITH RECURSIVE
-- Calculate the minimal and the maximal timestamp. We use this to determine the border of the list of all possible timestamps.
time_min_max AS (
    SELECT
        min(nfa.time) time_min,
        max(nfa.time) time_max
    FROM
        nfaggregates nfa
    WHERE
        nfa.agg_interval = 3600
        AND nfa.time >= 1652421600
        AND nfa.time <= 1654750800
),
-- Create a list of all possible timestamps.
time_starts (
    time_start
) AS (
    SELECT
        time_min time_start
    FROM
        time_min_max
    UNION ALL
    SELECT
        time_start + 3600 time_start
    FROM
        time_starts
    WHERE
        time_start < (
            SELECT
                time_max
            FROM
                time_min_max)
),
-- Create a list of all possible traffic flows. This mainly includes the source and destination.
-- The destination is determined by the location and IP address, since some locations host multiple IPs.
all_ips AS (
    SELECT DISTINCT
        location,
        iprange_src,
        iprange_dst
    FROM
        /* looking into one shard should be enough */
        nfaggregates_3600 nfa
)
SELECT
    all_ips.*,
    array_agg(COALESCE(total_packets, 0)
    ORDER BY time_starts.time_start) total_packets
FROM
    time_starts
    JOIN all_ips ON TRUE
    LEFT JOIN nfaggregates_3600 nfa ON (nfa.location = all_ips.location
            AND nfa.iprange_src = all_ips.iprange_src
            AND nfa.iprange_dst = all_ips.iprange_dst
            AND nfa.time = time_starts.time_start
            AND nfa.proto = 17)
GROUP BY
    all_ips.location, all_ips.iprange_src, all_ips.iprange_dst;

