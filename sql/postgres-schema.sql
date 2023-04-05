/**********************************************************

**********************************************************/

CREATE TABLE IF NOT EXISTS nfaggregates (
    -- Aggregation key
    location text NOT NULL,
    iprange_src cidr NOT NULL,
    time integer NOT NULL,
    agg_interval integer NOT NULL,
    proto smallint NOT NULL,
    iprange_dst inet NOT NULL,
    -- Add columns from the IpAggregate struct
    -- General fields
    total_packets integer NOT NULL,
    -- #
    -- Checks and other table settings
    CONSTRAINT location_length CHECK (char_length(location) <= 4)
)
PARTITION BY LIST (agg_interval);

CREATE TABLE IF NOT EXISTS nfaggregates_60 PARTITION OF nfaggregates
FOR VALUES IN (60);

CREATE TABLE IF NOT EXISTS nfaggregates_300 PARTITION OF nfaggregates
FOR VALUES IN (300);

CREATE TABLE IF NOT EXISTS nfaggregates_900 PARTITION OF nfaggregates
FOR VALUES IN (900);

CREATE TABLE IF NOT EXISTS nfaggregates_1800 PARTITION OF nfaggregates
FOR VALUES IN (1800);

CREATE TABLE IF NOT EXISTS nfaggregates_3600 PARTITION OF nfaggregates
FOR VALUES IN (3600);

ALTER TABLE nfaggregates_60
    ADD PRIMARY KEY (location, iprange_src, time, proto, iprange_dst);

ALTER TABLE nfaggregates_300
    ADD PRIMARY KEY (location, iprange_src, time, proto, iprange_dst);

ALTER TABLE nfaggregates_900
    ADD PRIMARY KEY (location, iprange_src, time, proto, iprange_dst);

ALTER TABLE nfaggregates_1800
    ADD PRIMARY KEY (location, iprange_src, time, proto, iprange_dst);

ALTER TABLE nfaggregates_3600
    ADD PRIMARY KEY (location, iprange_src, time, proto, iprange_dst);

-- Shared table with data for all locations
-- The locations are created as individual partitions and added at the end of this script
CREATE TABLE IF NOT EXISTS allowlist (
    time_start integer NOT NULL,
    train_window integer NOT NULL,
    active_min integer NOT NULL,
    pkts_min integer NOT NULL,
    location text NOT NULL,
    iprange_dst inet NOT NULL,
    array_agg cidr[] NOT NULL
)
PARTITION BY LIST (location);

-- Shared table with data for all locations
-- The locations are created as individual partitions and added at the end of this script
CREATE TABLE traffic_interval (
    time_start integer NOT NULL,
    train_window integer NOT NULL,
    location text NOT NULL,
    iprange_dst inet NOT NULL,
    iprange_srcs cidr[] NOT NULL,
    pkts_avgs double precision[] NOT NULL
)
PARTITION BY LIST (location);
