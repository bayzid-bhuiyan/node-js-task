This is th sql query 
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    last_login DATETIME DEFAULT NULL,
    registration_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('active', 'blocked', 'unverified') DEFAULT 'unverified'
);

-- Mandatory Unique Index on Email
CREATE UNIQUE INDEX unique_email ON users(email);
