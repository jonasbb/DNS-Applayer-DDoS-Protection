-- Replace xxx with the location information.
-- Run it multiple times for multiple locations.

-- Query can take very long
SET statement_timeout TO 0;

BEGIN;

CREATE TABLE allowlist_xxx AS
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
    unnest(ARRAY[1, 2, 4, 8, 12, 24, 25, 48, 49, 72, 73])
),
-- Minimum number of hours the traffic source must be active (i.e., more than 0 pkts)
active_min AS (
    SELECT
        s AS active_min
    FROM
        generate_series(1, 12) AS s
),
-- Minimum number of pkt a source needs to transmit in the training window
pkts_min AS (
    SELECT
        s AS pkts_min
    FROM
        unnest(ARRAY[4, 8, 16, 32, 64, 128, 256]) AS s
),
-- Subset of the `subwindow` relation with added aggregates of each subwindow.
-- Filters out all entries which show no activity
active_resolvers AS (
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
        -- active is the number of hours the source send any traffic
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
            active > 0
            -- ensure the average is high enough for the minimal level
            -- removes some values already
            AND COALESCE(sum::float / nullif (active, 0), 0) >= (
                SELECT
                    min(pkts_min)
                FROM
                    pkts_min))
        -- Final allowlists based on the grid search
        SELECT
            time_start,
            train_window,
            active_min,
            pkts_min,
            location,
            iprange_dst,
            array_agg(DISTINCT iprange_src ORDER BY iprange_src)
    FROM
        -- For each grid search parameter combination, filter the `active_resolvers` for matching entries.
        (
            SELECT
                time_start,
                train_window,
                active_min,
                pkts_min,
                location,
                iprange_dst,
                iprange_src,
                total_packets
            FROM
                active_min,
                pkts_min,
                active_resolvers
            WHERE
                -- Filter for active hours and pkts activity
                active_resolvers.active >= active_min.active_min
                AND active_resolvers.avg >= pkts_min.pkts_min
                -- Ensure there are enough hours for the active_min to be possible
                AND active_resolvers.train_window >= active_min.active_min) AS grid_search_raw
    GROUP BY
        time_start, train_window, active_min, pkts_min, location, iprange_dst;

ALTER TABLE allowlist_xxx
    ALTER COLUMN time_start SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN train_window SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN active_min SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN pkts_min SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN location SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN iprange_dst SET NOT NULL;

ALTER TABLE allowlist_xxx
    ALTER COLUMN array_agg SET NOT NULL;

CREATE UNIQUE INDEX ON allowlist_xxx USING btree (time_start, train_window, active_min, pkts_min, location, iprange_dst) WITH (fillfactor = '100');

COMMIT;

BEGIN;

ALTER TABLE allowlist ATTACH PARTITION allowlist_xxx
FOR VALUES IN ('xxx');

COMMIT;
