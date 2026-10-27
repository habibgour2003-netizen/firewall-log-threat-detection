-- Run these queries against outputs/firewall_lab.db using any SQLite client.
-- No cloud resources required.

-- Overall counts by firewall action
SELECT action, COUNT(*) AS events
FROM firewall_logs
GROUP BY action
ORDER BY events DESC;

-- Most frequent denied sources
SELECT src_ip, COUNT(*) AS denied_events,
       COUNT(DISTINCT dst_port) AS distinct_denied_ports
FROM firewall_logs
WHERE action = 'DENY'
GROUP BY src_ip
ORDER BY denied_events DESC
LIMIT 10;

-- Recorded alerts and their evidence
SELECT window_start, src_ip, dst_ip, alert_type,
       event_count, distinct_ports, reason
FROM alerts
ORDER BY window_start DESC;
