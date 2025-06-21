    users {
        UUID id PK
        VARCHAR name
        VARCHAR email UK
        VARCHAR password_hash
        VARCHAR role
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    addresses {
        UUID id PK
        UUID user_id FK
        VARCHAR label
        TEXT street_address
        BOOLEAN is_default
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    machines {
        UUID id PK
        machine_type type
        machine_status status
        GEOGRAPHY current_location
        INTEGER battery_level
        TIMESTAMPTZ updated_at
    }

    orders {
        UUID id PK
        UUID user_id FK
        UUID machine_id FK "Nullable"
        UUID pickup_address_id FK
        UUID dropoff_address_id FK
        order_status status
        TEXT item_description
        DECIMAL item_weight_kg
        DECIMAL cost
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    payments {
        UUID id PK
        UUID order_id FK UK
        VARCHAR external_payment_id
        DECIMAL amount
        VARCHAR status
        TIMESTAMPTZ created_at
    }

    feedback {
        UUID id PK
        UUID order_id FK UK
        INTEGER rating
        TEXT comment
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    notifications {
        UUID id PK
        UUID user_id FK
        TEXT message
        BOOLEAN is_read
        TIMESTAMPTZ created_at
    }

    users ||--o{ addresses : "has"
    users ||--o{ orders : "places"
    users ||--o{ notifications : "receives"
    orders }|--|| payments : "has one"
    orders }|--|| feedback : "has one"
    orders }o--|| machines : "is assigned"
    orders }|--o| addresses : "pickup"
    orders }|--o| addresses : "dropoff"


