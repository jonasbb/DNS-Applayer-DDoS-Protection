-- \copy (SELECT row_to_json(s) FROM (
SELECT
    location,
    iprange_src,
    max(total_packets) total_packets_max,
    sum(total_packets) total_packets_sum,
    count(DISTINCT time) active_hours
FROM
    nfaggregates nfa
WHERE
    nfa.agg_interval = 3600
    AND nfa.time >= 1652421600
    AND nfa.time <= 1654750800
GROUP BY
    location, iprange_src
    -- ) AS s) to ./peak-rate.json
