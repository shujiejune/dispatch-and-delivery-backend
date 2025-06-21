CREATE TYPE machine_type AS ENUM ('DRONE', 'ROBOT');
CREATE TYPE machine_status AS ENUM ('IDLE', 'IN_TRANSIT', 'CHARGING', 'MAINTENANCE');
CREATE TABLE machines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type machine_type NOT NULL,
    status machine_status NOT NULL DEFAULT 'IDLE',
    -- Store location as a geography point for distance calculations. SRID 4326 is standard GPS.
    current_location GEOGRAPHY(Point, 4326),
    battery_level INTEGER NOT NULL CHECK (battery_level >= 0 AND battery_level <= 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Create a geospatial index (using GIST， generalized search tree) for efficient location-based queries on machines (the nearest available robot or drone).
CREATE INDEX IF NOT EXISTS idx_machines_location ON machines USING GIST (current_location);
