CREATE TYPE order_status AS ENUM ('PENDING_PAYMENT', 'CANCELLED', 'CONFIRMED', 'IN_PROGRESS', 'DELIVERED', 'FAILED');
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    machine_id UUID REFERENCES machines(id) ON DELETE SET NULL, // nullable
    pickup_address_id UUID NOT NULL REFERENCES addresses(id) ON DELETE RESTRICT,
    dropoff_address_id UUID NOT NULL REFERENCES addresses(id) ON DELETE RESTRICT,
    status order_status NOT NULL DEFAULT 'PENDING_PAYMENT',
    item_description TEXT NOT NULL,
    item_weight_kg DECIMAL(10, 2) NOT NULL,
    cost DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_machine_id ON orders(machine_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
