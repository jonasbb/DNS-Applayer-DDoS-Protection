-- Query can take very long
SET statement_timeout TO 0;

BEGIN;

CREATE TABLE traffic_interval_xxx AS
WITH
-- All array offsets are valid start positions.
-- The array index starts with 1
time_starts AS (
    SELECT
        s AS time_start
    FROM
        generate_series(1, (
                SELECT
                    array_length(total_packets, 1)
                FROM pre_test_intervals LIMIT 1)) AS s
),
-- Training intervals, assumes hours as base unit
windows_train AS (
    SELECT
        unnest AS train_window
    FROM
        unnest(ARRAY[1, 2, 4, 8, 12, 24, 25, 48, 49, 72, 73]))
    -- Final allowlists based on the grid search
    SELECT
        time_start,
        train_window,
        location,
        iprange_dst,
        array_agg(iprange_src ORDER BY iprange_src) iprange_srcs,
    array_agg(avg ORDER BY iprange_src) pkts_avgs
FROM (
    -- Subset of the `subwindow` relation with added aggregates of each subwindow.
    -- Filters out all entries which show no activity
    SELECT
        time_start,
        train_window,
        location,
        iprange_dst,
        iprange_src,
        total_packets,
        active,
        -- Compute aggregates based on total_packets
        -- sum is the sum over the train window
        -- max is the maximum of any time in the train window
        -- active is thenumber of hours the source send any traffic
        -- avg is the average number of packets during the active period
        COALESCE(sum::float / nullif (active, 0), 0) AS avg
    FROM (
        SELECT
            time_start,
            train_window,
            location,
            iprange_dst,
            iprange_src,
            total_packets,
            (
                SELECT
                    sum(s)
                FROM
                    unnest(total_packets) AS s) AS sum,
                (
                    SELECT
                        max(s)
                    FROM
                        unnest(total_packets) AS s) AS max,
                    (
                        SELECT
                            count(s) FILTER (WHERE s > 0)
                        FROM
                            unnest(total_packets) AS s) AS active
                    FROM
                        -- Select all subwindows based on `time_starts` and `windows_train` from the pre-aggregated data in `pre_test_intervals`.
                        -- Only keep those entries, where there is enough data in to fit the training window with the start offset.
                        (
                            SELECT
                                location,
                                iprange_dst,
                                iprange_src,
                                total_packets[time_starts.time_start :time_starts.time_start + windows_train.train_window - 1] total_packets,
                                time_starts.time_start,
                                windows_train.train_window
                            FROM
                                pre_test_intervals,
                                time_starts,
                                windows_train
                            WHERE
                                -- Ensure there are no out-of-bounds accesses
                                -- out-of-bound accesses result in a too small sub-array
                                array_length(total_packets, 1) >= time_starts.time_start + windows_train.train_window - 1
                                AND location = 'xxx') AS subwindows) AS subwindows_with_aggregates
                    WHERE
                        active > 0) AS active_resolvers
GROUP BY
    time_start, train_window, location, iprange_dst;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN time_start SET NOT NULL;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN train_window SET NOT NULL;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN location SET NOT NULL;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN iprange_dst SET NOT NULL;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN iprange_srcs SET NOT NULL;

ALTER TABLE traffic_interval_xxx
    ALTER COLUMN pkts_avgs SET NOT NULL;

CREATE UNIQUE INDEX ON traffic_interval_xxx USING btree (time_start, train_window, location, iprange_dst) WITH (fillfactor = '100');

COMMIT;

BEGIN;

ALTER TABLE traffic_interval ATTACH PARTITION traffic_interval_xxx
FOR VALUES IN ('xxx');

COMMIT;

