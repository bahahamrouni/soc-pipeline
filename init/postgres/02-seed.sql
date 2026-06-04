INSERT INTO cmdb_assets (hostname, ip_address, os, role, site, criticality, owner) VALUES
('wazuh-manager', '192.168.10.10', 'Ubuntu 24.04', 'siem-server', 'haouaria', 3, 'SOC'),
('web-srv-01', '192.168.10.21', 'Ubuntu 22.04', 'web-server', 'haouaria', 2, 'IT'),
('db-srv-01', '192.168.10.22', 'Ubuntu 22.04', 'db-server', 'haouaria', 3, 'IT'),
('win-srv-2022-01', '192.168.10.30', 'Windows Server 2022', 'file-server', 'haouaria', 2, 'IT'),
('workstation-01', '192.168.20.11', 'Windows 10', 'workstation', 'haouaria', 1, 'IT')
ON CONFLICT (hostname) DO NOTHING;

INSERT INTO users (username, email, hashed_password, role) VALUES
('admin', 'admin@haco-soc.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMZJZ6a7B2k3pNq4qN1kR5hV6y', 'admin'),
('analyst1', 'analyst1@haco-soc.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMZJZ6a7B2k3pNq4qN1kR5hV6y', 'analyst')
ON CONFLICT (username) DO NOTHING;