# CanaryGuard Database Documentation

CanaryGuard uses SQLite 3 with SQLAlchemy ORM.

## Relational Schema Tables (13 Tables)

1. `users`: Admin/analyst credential management.
2. `incidents`: Ransomware detection records, threat levels, actions taken.
3. `canary_files`: Canary file metadata, original & current SHA-256 hashes.
4. `entropy_logs`: Historical Shannon entropy calculations.
5. `process_logs`: Active process snapshots and resource metrics.
6. `threat_statistics`: Daily aggregated threat counts for analytics charts.
7. `quarantine_history`: Record of process terminations and isolated files.
8. `system_settings`: Key-value configuration persistence.
9. `activity_logs`: System audit trail.
10. `dashboard_events`: WebSocket payload records.
11. `security_policies`: Threat policy definitions.
12. `monitored_folders`: Watched directory paths.
13. `alerts`: Active security alert messages.
