-- Create 'users' table
CREATE TABLE users (
    user_id VARCHAR PRIMARY KEY,
    email VARCHAR NOT NULL UNIQUE,
    password_hash VARCHAR NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT
);

-- Create 'calculations' table
CREATE TABLE calculations (
    calculation_id VARCHAR PRIMARY KEY,
    input_value VARCHAR,
    operation VARCHAR,
    result VARCHAR,
    created_at BIGINT NOT NULL,
    updated_at BIGINT,
    device_type VARCHAR,
    device_id VARCHAR,
    error_message VARCHAR,
    user_agent VARCHAR
);

-- Create 'settings' table
CREATE TABLE settings (
    setting_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    theme VARCHAR,
    button_size VARCHAR,
    created_at BIGINT NOT NULL,
    updated_at BIGINT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Seed data for 'users' table
INSERT INTO users (user_id, email, password_hash, is_active, created_at, updated_at) VALUES
('user1', 'user1@example.com', 'password123', TRUE, 1634012800, 1634016400),
('user2', 'user2@example.com', 'user123', TRUE, 1634012900, NULL);

-- Seed data for 'calculations' table
INSERT INTO calculations (calculation_id, input_value, operation, result, created_at, updated_at, device_type, device_id, error_message, user_agent) VALUES
('calc1', '5+5', 'addition', '10', 1634013000, 1634016600, 'mobile', 'device123', NULL, 'Mozilla/5.0'),
('calc2', '10-2', 'subtraction', '8', 1634013100, NULL, 'desktop', 'device456', 'Syntax Error', 'Mozilla/5.0');

-- Seed data for 'settings' table
INSERT INTO settings (setting_id, user_id, theme, button_size, created_at, updated_at) VALUES
('setting1', 'user1', 'dark', 'medium', 1634013200, 1634016800),
('setting2', 'user2', 'light', 'large', 1634013300, NULL);