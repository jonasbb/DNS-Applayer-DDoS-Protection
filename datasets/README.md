# Details about the data sources

The files are big JSON objects in the form `"IP": 123` where we have the network of the IP (i.e., /24) and a weight per network.
The weight corresponds to the amount of traffic each network could send.

The `mirai-*` files are calculated based on the darknet data.
The normal files are weighted by the number of probes in the darknet.
The `ipcount` files are weighted by the number of distinct source IPs in the network.
The files with `2022-19`, `2022-20`, `2022-21`, `2022-22`, and `2022-23` only consider traffic from these weeks of 2022.
The files with `2022-all` consider the full timerange of 202-05-13T06:00 to 2022-06-09T07:00.

```sql
\copy (
    SELECT
        json_object_agg(s.net, s.count)
    FROM (
        SELECT
            /* Round the IP address to the nearest /24 */
            split_part((src / 24)::text, '/', 1) AS net,
            count(DISTINCT src) AS count
        FROM
            darknet_tcp
        WHERE
            ts BETWEEN '20220513T0600' AND '20220609T0700'
            AND dport IN (22, 23, 2323)
            AND EXTRACT(WEEK FROM ts) = 23
        GROUP BY
            1
        ORDER BY
            1) s) to ~/mirai-2022-2022-23-ipcount.json
```

The `sality` contains a list of Sality botnet peers as observed on 2022-06-28.

The `open-resolver-equal-*` are gathered by scanning the IPv4 internet and recording the scanned destination IP address and the IP address of the resolver as observed by the authoritative name server.
This gives us a mapping of destination IP address (also encoded) to the source IPs seen by the authoritative server.
The `equal-encoded-traffic` weights the networks, such that the scanned IP addresses are equally distributed.
The `equal-source-traffic` weights the IP addresses, such that the IP addresses as seen by the authoritative server are equally distributed.
