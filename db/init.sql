-- ShopLedger Database Schema & Seed Data
-- Models a small business inventory and billing system.

CREATE DATABASE IF NOT EXISTS shopledger;
USE shopledger;

-- 1. Products Table
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sku VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Customers Table
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    email VARCHAR(128) NOT NULL UNIQUE,
    phone VARCHAR(32) NOT NULL,
    address VARCHAR(256),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. Invoices Table
CREATE TABLE IF NOT EXISTS invoices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    invoice_number VARCHAR(32) NOT NULL UNIQUE,
    customer_id INT NOT NULL,
    total_amount DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

-- 4. Invoice Line Items Table
CREATE TABLE IF NOT EXISTS invoice_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    invoice_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL,
    line_total DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

-- =============================================================
-- Database Users Configuration (Principle of Least Privilege)
-- =============================================================

-- User 1: app_user (Used exclusively by the Mode B Application Tier)
-- Authorized for CRUD operations on shopledger tables, no administrative or DDL privileges.
CREATE USER IF NOT EXISTS 'app_user'@'%' IDENTIFIED BY 'app_secure_pass_123';
GRANT SELECT, INSERT, UPDATE, DELETE ON shopledger.* TO 'app_user'@'%';

-- User 2: client_user (Used exclusively by the Mode A Desktop / CLI Client)
-- Restricted access: can query catalog, view customers, insert invoices, and decrement stock.
-- No DDL, no DELETE, no access to MySQL system metadata or user tables.
CREATE USER IF NOT EXISTS 'client_user'@'%' IDENTIFIED BY 'client_secure_pass_456';
GRANT SELECT ON shopledger.products TO 'client_user'@'%';
GRANT UPDATE (stock) ON shopledger.products TO 'client_user'@'%';
GRANT SELECT ON shopledger.customers TO 'client_user'@'%';
GRANT SELECT, INSERT ON shopledger.invoices TO 'client_user'@'%';
GRANT SELECT, INSERT ON shopledger.invoice_items TO 'client_user'@'%';

-- User 3: admin (Lab audit only, never accessed by application logic or client tier)
CREATE USER IF NOT EXISTS 'admin_user'@'%' IDENTIFIED BY 'admin_secure_vault_789';
GRANT ALL PRIVILEGES ON shopledger.* TO 'admin_user'@'%';

FLUSH PRIVILEGES;

-- =============================================================
-- Seed Data: 50 Products, 20 Customers, 100 Initial Invoices
-- =============================================================

INSERT INTO products (sku, name, category, price, stock) VALUES
('SKU-1001', 'Logitech MX Master 3S Mouse', 'Peripherals', 99.99, 45),
('SKU-1002', 'Dell UltraSharp 27 4K Monitor', 'Displays', 499.50, 18),
('SKU-1003', 'Keychron K2 Mechanical Keyboard', 'Peripherals', 79.00, 32),
('SKU-1004', 'Sony WH-1000XM5 Headphones', 'Audio', 349.99, 14),
('SKU-1005', 'Samsung 990 Pro 2TB NVMe SSD', 'Storage', 179.99, 60),
('SKU-1006', 'Crucial DDR5 32GB RAM Kit', 'Memory', 104.99, 40),
('SKU-1007', 'Apple iPad Air 11-inch M2', 'Tablets', 599.00, 22),
('SKU-1008', 'Anker 737 Power Bank 24000mAh', 'Accessories', 119.99, 5),
('SKU-1009', 'LG C3 42 OLED 4K Display', 'Displays', 899.99, 8),
('SKU-1010', 'Bose QuietComfort 45', 'Audio', 279.00, 19),
('SKU-1011', 'CalDigit TS4 Thunderbolt 4 Dock', 'Accessories', 399.95, 7),
('SKU-1012', 'Raspberry Pi 5 8GB Board', 'Embedded', 80.00, 4),
('SKU-1013', 'SanDisk Extreme 1TB Portable SSD', 'Storage', 109.99, 50),
('SKU-1014', 'Blue Yeti USB Microphone', 'Audio', 129.99, 25),
('SKU-1015', 'Elgato Stream Deck MK.2', 'Peripherals', 149.99, 15),
('SKU-1016', 'ASUS ROG Rapture WiFi 6E Router', 'Networking', 329.99, 12),
('SKU-1017', 'Ubiquiti UniFi 8-Port PoE Switch', 'Networking', 199.00, 16),
('SKU-1018', 'Cat6A Shielded Ethernet Cable 50ft', 'Networking', 24.50, 120),
('SKU-1019', 'APC 1500VA Smart-UPS Pro', 'Power', 249.99, 9),
('SKU-1020', 'Noctua NH-D15 CPU Cooler', 'Cooling', 109.95, 30),
('SKU-1021', 'Corsair RM850x Power Supply', 'Power', 139.99, 28),
('SKU-1022', 'NZXT H5 Flow Compact ATX Case', 'Chassis', 94.99, 17),
('SKU-1023', 'Seagate IronWolf 8TB NAS HDD', 'Storage', 189.99, 35),
('SKU-1024', 'Synology DiskStation DS224+', 'Storage', 299.99, 11),
('SKU-1025', 'Logitech C920 HD Pro Webcam', 'Peripherals', 69.99, 42),
('SKU-1026', 'Yubico YubiKey 5 NFC', 'Security', 55.00, 85),
('SKU-1027', 'Epson EcoTank L3250 Printer', 'Printers', 219.00, 14),
('SKU-1028', 'Dymo LabelWriter 550 Turbo', 'Printers', 145.00, 6),
('SKU-1029', 'Brother HL-L2350DW Laser Printer', 'Printers', 169.99, 20),
('SKU-1030', 'Thermal Receipt Paper Roll (Box of 50)', 'Supplies', 39.50, 75),
('SKU-1031', 'Honeywell Orbit 7120 Barcode Scanner', 'POS', 165.00, 8),
('SKU-1032', 'APG Vasario Cash Drawer 1616', 'POS', 119.00, 10),
('SKU-1033', 'Star Micronics TSP143III Receipt Printer', 'POS', 229.00, 7),
('SKU-1034', 'Zebra ZD421 Direct Thermal Printer', 'POS', 389.00, 4),
('SKU-1035', 'Verifone e285 Mobile PIN Pad', 'POS', 199.00, 6),
('SKU-1036', 'Fellowes Powershred 79Ci Paper Shredder', 'Office', 189.99, 13),
('SKU-1037', 'Fellowes Ergonomic Standing Desk Converter', 'Office', 249.99, 5),
('SKU-1038', 'Steelcase Gesture Ergonomic Chair', 'Office', 1199.00, 3),
('SKU-1039', 'BenQ WiT e-Reading LED Desk Lamp', 'Office', 179.00, 22),
('SKU-1040', 'CyberPower 8-Outlet Surge Protector', 'Power', 29.99, 90),
('SKU-1041', 'TP-Link Omada AC1750 Access Point', 'Networking', 89.99, 25),
('SKU-1042', 'MikroTik hEX S Gigabit Router', 'Networking', 79.00, 18),
('SKU-1043', 'Netgear 5-Port Gigabit Unmanaged Switch', 'Networking', 19.99, 65),
('SKU-1044', 'Intel Core i7-14700K Processor', 'Processors', 409.99, 15),
('SKU-1045', 'AMD Ryzen 7 7800X3D Processor', 'Processors', 389.00, 12),
('SKU-1046', 'MSI MAG B650 Tomahawk Motherboard', 'Components', 199.99, 14),
('SKU-1047', 'NVIDIA GeForce RTX 4070 Super 12GB', 'Graphics', 599.99, 8),
('SKU-1048', 'Arctic MX-6 Thermal Paste 4g', 'Cooling', 9.99, 140),
('SKU-1049', 'Cable Matters DisplayPort 1.4 Cable 6ft', 'Cables', 14.99, 85),
('SKU-1050', 'Anker USB-C to USB-C 100W Cable 6ft', 'Cables', 12.99, 110);

-- Insert 20 Customers
INSERT INTO customers (name, email, phone, address) VALUES
('Apex Solutions Ltd', 'billing@apexsolutions.com', '+1-555-0101', '100 Market St, Suite 400, San Francisco, CA'),
('Beacon Health Clinic', 'accounts@beaconhealth.org', '+1-555-0102', '742 Evergreen Terrace, Springfield, OR'),
('Cascadia Technical Institute', 'procurement@cascadiatech.edu', '+1-555-0103', '1200 University Way, Seattle, WA'),
('Downtown Retail Hub', 'admin@downtownretail.net', '+1-555-0104', '45 Broadway Avenue, New York, NY'),
('Evergreen Dental Care', 'contact@evergreendental.com', '+1-555-0105', '88 Medical Park Blvd, Austin, TX'),
('Frontier Logistics Group', 'invoices@frontierlogistics.com', '+1-555-0106', '330 Industrial Pkwy, Chicago, IL'),
('Gateway Creative Studio', 'finance@gatewaycreative.co', '+1-555-0107', '550 Design Center Dr, Los Angeles, CA'),
('Horizon Financial Partners', 'accounting@horizonfin.com', '+1-555-0108', '200 Wall Street, Floor 12, New York, NY'),
('Ironclad Construction Supplies', 'ap@ironcladsupplies.com', '+1-555-0109', '910 Quarry Rd, Denver, CO'),
('Juniper Community College', 'purchasing@juniper.edu', '+1-555-0110', '404 Academic Drive, Portland, OR'),
('Kodiak Marine Repair', 'service@kodiakmarine.com', '+1-555-0111', '12 Harbor View Rd, Anchorage, AK'),
('Lighthouse Law Practice', 'billing@lighthouselaw.com', '+1-555-0112', '60 State St, Suite 800, Boston, MA'),
('Metro Transport Authority', 'finance@metrotransit.gov', '+1-555-0113', '1 City Hall Plaza, Philadelphia, PA'),
('Northwest Orthopedics', 'orders@northwestortho.org', '+1-555-0114', '770 Clinical Way, Boise, ID'),
('Oakridge Regional Hospital', 'supplychain@oakridgehealth.org', '+1-555-0115', '500 Health Blvd, Nashville, TN'),
('Pioneer Farm Cooperative', 'office@pioneerfarm.coop', '+1-555-0116', '312 Rural Route 4, Des Moines, IA'),
('Quantum Data Labs', 'accounts@quantumdatalabs.io', '+1-555-0117', '180 Tech Square, Cambridge, MA'),
('Redwood Architecture Group', 'invoicing@redwoodarch.com', '+1-555-0118', '210 Pine St, San Francisco, CA'),
('Summit Veterinary Hospital', 'bills@summitvet.com', '+1-555-0119', '65 Mountain View Dr, Salt Lake City, UT'),
('Titan Industrial Robotics', 'procure@titanrobotics.com', '+1-555-0120', '420 Automation Ave, Detroit, MI');

-- Generate 100 Realistic Seed Invoices using a Stored Procedure
DELIMITER //
CREATE PROCEDURE PopulateSeedInvoices()
BEGIN
    DECLARE i INT DEFAULT 1;
    DECLARE cust_id INT;
    DECLARE p1 INT;
    DECLARE p2 INT;
    DECLARE q1 INT;
    DECLARE q2 INT;
    DECLARE price1 DECIMAL(10,2);
    DECLARE price2 DECIMAL(10,2);
    DECLARE total DECIMAL(10,2);
    DECLARE inv_id INT;

    WHILE i <= 100 DO
        SET cust_id = ((i - 1) % 20) + 1;
        SET p1 = ((i * 3) % 50) + 1;
        SET p2 = ((i * 7 + 5) % 50) + 1;
        SET q1 = ((i % 4) + 1);
        SET q2 = (((i + 2) % 3) + 1);

        SELECT price INTO price1 FROM products WHERE id = p1;
        SELECT price INTO price2 FROM products WHERE id = p2;
        SET total = (price1 * q1) + (price2 * q2);

        INSERT INTO invoices (invoice_number, customer_id, total_amount, created_at)
        VALUES (
            CONCAT('INV-2026-', LPAD(i, 4, '0')),
            cust_id,
            total,
            DATE_SUB(NOW(), INTERVAL (100 - i) HOUR)
        );
        SET inv_id = LAST_INSERT_ID();

        INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total)
        VALUES
            (inv_id, p1, q1, price1, price1 * q1),
            (inv_id, p2, q2, price2, price2 * q2);

        SET i = i + 1;
    END WHILE;
END //
DELIMITER ;

CALL PopulateSeedInvoices();
DROP PROCEDURE PopulateSeedInvoices;
