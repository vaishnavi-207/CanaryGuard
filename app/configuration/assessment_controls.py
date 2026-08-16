"""
Readiness Assessment Control Library for CanaryGuard EDR.
Defines security framework domains and controls across IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, and PEOPLE.
"""

DOMAIN_NAMES = {
    'IDENTIFY': 'Asset & Risk Identification',
    'PROTECT': 'Protective Controls & Perimeter Safeguards',
    'DETECT': 'Continuous Monitoring & Threat Detection',
    'RESPOND': 'Incident Response & Threat Containment',
    'RECOVER': 'Business Continuity & Disaster Recovery',
    'PEOPLE': 'Security Culture & Awareness'
}

DOMAIN_WEIGHTS = {
    'IDENTIFY': 15.0,
    'PROTECT': 25.0,
    'DETECT': 20.0,
    'RESPOND': 15.0,
    'RECOVER': 15.0,
    'PEOPLE': 10.0
}

ASSESSMENT_CONTROLS = [
    # --- IDENTIFY DOMAIN ---
    {
        'domain_code': 'IDENTIFY',
        'control_code': 'asset_inventory',
        'control_title': 'Comprehensive IT Asset Inventory',
        'control_description': 'Maintain an up-to-date hardware and software asset register across all organization endpoints.',
        'why_it_matters': 'You cannot secure endpoints or detect ransomware targets without knowing what assets exist on the network.',
        'weight': 3,
        'remediation_tip': 'Deploy automated active directory or network discovery scanners to audit all connected endpoints continuously.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'IDENTIFY',
        'control_code': 'data_classification',
        'control_title': 'Sensitive Data Classification & Tagging',
        'control_description': 'Classify critical enterprise data, databases, PII, and financial records by confidentiality level.',
        'why_it_matters': 'Ransomware actors explicitly target high-value confidential data for exfiltration and double extortion.',
        'weight': 2,
        'remediation_tip': 'Implement DLP data tagging policies and classify file shares based on sensitivity and business criticality.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'IDENTIFY',
        'control_code': 'crown_jewel_mapping',
        'control_title': 'Crown Jewel & Critical Dependency Mapping',
        'control_description': 'Identify mission-critical systems whose compromise or encryption would halt core business operations.',
        'why_it_matters': 'Prioritizes defense and rapid isolation mechanisms around high-impact business systems.',
        'weight': 2,
        'remediation_tip': 'Map critical application dependencies and enforce strict zero-trust access rules for crown jewel servers.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'IDENTIFY',
        'control_code': 'software_inventory',
        'control_title': 'Authorized Software & Binary Inventory',
        'control_description': 'Maintain an inventory of authorized applications and block unapproved executable binaries.',
        'why_it_matters': 'Ransomware strains often rely on dual-use administrative software (PsExec, Cobalt Strike) or unapproved tools.',
        'weight': 2,
        'remediation_tip': 'Enforce software allowlisting and monitor unexpected binary executions on critical workstations.',
        'auto_detectable': False,
        'auto_detect_key': None
    },

    # --- PROTECT DOMAIN ---
    {
        'domain_code': 'PROTECT',
        'control_code': 'offline_backup',
        'control_title': 'Immutable & Offline Backup Strategy',
        'control_description': 'Maintain air-gapped or immutable write-once read-many (WORM) backups disconnected from network access.',
        'why_it_matters': 'Modern ransomware systematically destroys online shadow copies and network backups prior to encryption.',
        'weight': 3,
        'remediation_tip': 'Implement the 3-2-1 backup rule with at least one immutable or offline offsite copy.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'backup_tested',
        'control_title': 'Regular Backup Restoration Testing',
        'control_description': 'Conduct scheduled technical restoration drills to verify data integrity and restore speeds.',
        'why_it_matters': 'Unverified backups frequently fail during real incident recovery due to corruption or missing encryption keys.',
        'weight': 2,
        'remediation_tip': 'Automate monthly test restores into an isolated sandbox environment and validate database bootability.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'mfa_enabled',
        'control_title': 'Multi-Factor Authentication (MFA)',
        'control_description': 'Require phishing-resistant MFA for all external logins, VPNs, RDP endpoints, and cloud portals.',
        'why_it_matters': 'Credential stuffing and compromised passwords account for over 60% of initial ransomware access vectors.',
        'weight': 3,
        'remediation_tip': 'Enforce hardware security keys (FIDO2) or authenticator app push notifications across all accounts.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'least_privilege',
        'control_title': 'Principle of Least Privilege (PoLP)',
        'control_description': 'Restrict administrative rights and prevent domain accounts from holding local admin access on endpoints.',
        'why_it_matters': 'Limits lateral movement and prevents malware from elevating privileges to stop security services.',
        'weight': 2,
        'remediation_tip': 'Implement Just-in-Time (JIT) admin access tools and remove permanent local administrator privileges.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'patch_management',
        'control_title': 'Timely Vulnerability & Patch Management',
        'control_description': 'Deploy operating system and third-party software security updates within 14 days of release.',
        'why_it_matters': 'Exploitation of known edge vulnerabilities (e.g. Fortinet, Exchange, VPN gateways) triggers mass infection.',
        'weight': 2,
        'remediation_tip': 'Establish automated patch cycles for critical zero-day vulnerabilities within 48 hours.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'network_segmentation',
        'control_title': 'Microsegmentation & VLAN Isolation',
        'control_description': 'Segment internal networks into isolated zones to contain potential lateral movement.',
        'why_it_matters': 'Flat networks allow ransomware to spread across hundreds of servers in minutes.',
        'weight': 2,
        'remediation_tip': 'Restrict SMB/RDP traffic between workstations and enforce strict firewall rules between server subnets.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'email_security',
        'control_title': 'Email Security Filtering & Anti-Phishing',
        'control_description': 'Filter incoming emails for malicious attachments, links, SPF/DKIM/DMARC spoofing, and macro scripts.',
        'why_it_matters': 'Phishing emails delivering droppers (Qakbot, Emotet) remain a primary ransomware initial access vector.',
        'weight': 2,
        'remediation_tip': 'Enable attachment sandboxing, block executable extension types, and enforce strict DMARC rejection.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'endpoint_protection',
        'control_title': 'Next-Gen Anti-Virus (NGAV) & Behavioral Controls',
        'control_description': 'Deploy behavioral antivirus controls capable of blocking unauthorized file modifications.',
        'why_it_matters': 'Signature-based traditional AV fails against freshly compiled zero-day ransomware binaries.',
        'weight': 3,
        'remediation_tip': 'Ensure real-time engine protection is enabled with tamper protection turned on.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PROTECT',
        'control_code': 'encryption_at_rest',
        'control_title': 'Full Disk & Database Encryption at Rest',
        'control_description': 'Encrypt laptops, removable media, and database storage using AES-256 or BitLocker.',
        'why_it_matters': 'Protects physical device theft and prevents unauthorized offline disk mounting.',
        'weight': 1,
        'remediation_tip': 'Enforce BitLocker / FileVault policy via central MDM and securely escrow recovery keys.',
        'auto_detectable': False,
        'auto_detect_key': None
    },

    # --- DETECT DOMAIN ---
    {
        'domain_code': 'DETECT',
        'control_code': 'canary_deployment',
        'control_title': 'Decoy Canary File Deployment',
        'control_description': 'Deploy hidden honeypot canary files across sensitive directories to trigger instant alerts upon tampering.',
        'why_it_matters': 'Canary traps provide zero-false-positive early warning when ransomware starts bulk encryption.',
        'weight': 3,
        'remediation_tip': 'Deploy realistic decoy files across monitored shares and configure automatic process kill triggers.',
        'auto_detectable': True,
        'auto_detect_key': 'canary_deployment'
    },
    {
        'domain_code': 'DETECT',
        'control_code': 'log_monitoring',
        'control_title': 'Centralized Security Event Logging',
        'control_description': 'Collect and monitor security event logs, filesystem modifications, and process creations.',
        'why_it_matters': 'Enables early threat hunting and preserves audit trails during incident forensics.',
        'weight': 2,
        'remediation_tip': 'Ensure OS audit policies capture process creation (Event ID 4688) and command-line logging.',
        'auto_detectable': True,
        'auto_detect_key': 'log_monitoring'
    },
    {
        'domain_code': 'DETECT',
        'control_code': 'siem_coverage',
        'control_title': 'SIEM Integration & Real-Time Correlation',
        'control_description': 'Feed endpoint and firewall logs into a SIEM platform for real-time rule correlation.',
        'why_it_matters': 'Correlates suspicious events across multiple network nodes before widespread encryption occurs.',
        'weight': 2,
        'remediation_tip': 'Configure log forwarders with TLS encryption to send events to a central SOC SIEM dashboard.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'DETECT',
        'control_code': 'anomaly_detection',
        'control_title': 'Shannon Entropy & Heuristic Anomaly Engine',
        'control_description': 'Calculate mathematical entropy scores on file modifications to catch high-randomness ciphertext writing.',
        'why_it_matters': 'High Shannon entropy accurately identifies encrypted payloads even when process names are disguised.',
        'weight': 3,
        'remediation_tip': 'Tune entropy thresholds (7.0 - 7.5) to catch encryption bursts without flagging compressed media files.',
        'auto_detectable': True,
        'auto_detect_key': 'anomaly_detection'
    },
    {
        'domain_code': 'DETECT',
        'control_code': 'edr_coverage',
        'control_title': 'Endpoint Detection & Response (EDR) Agent Coverage',
        'control_description': 'Deploy active EDR agents across 100% of network workstations and servers with process tree tracing.',
        'why_it_matters': 'Provides granular process hierarchy details and enables automated quarantine response.',
        'weight': 3,
        'remediation_tip': 'Maintain 100% agent installation density and audit unmonitored shadow IT servers regularly.',
        'auto_detectable': True,
        'auto_detect_key': 'edr_coverage'
    },
    {
        'domain_code': 'DETECT',
        'control_code': 'alert_thresholds',
        'control_title': 'Automated Alert Rate & Burst Threshold Tuning',
        'control_description': 'Configure burst thresholds to catch rapid file rename/delete operations in rolling windows.',
        'why_it_matters': 'Catches fast-encrypting ransomware strains that operate in seconds.',
        'weight': 2,
        'remediation_tip': 'Set file modification burst rate limits (e.g. >10 modifications / 3s) to trigger containment alerts.',
        'auto_detectable': False,
        'auto_detect_key': None
    },

    # --- RESPOND DOMAIN ---
    {
        'domain_code': 'RESPOND',
        'control_code': 'ir_plan_exists',
        'control_title': 'Documented Ransomware Incident Response Plan',
        'control_description': 'Maintain a formally approved Incident Response (IR) plan detailing roles, isolation steps, and escalation paths.',
        'why_it_matters': 'Chaos during an active outbreak leads to delayed containment and increased financial damage.',
        'weight': 3,
        'remediation_tip': 'Ensure IR playbooks clearly define host network isolation procedures and executive decision protocols.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RESPOND',
        'control_code': 'ir_plan_tested',
        'control_title': 'Tabletop Exercises & Simulated Outbreak Drills',
        'control_description': 'Conduct bi-annual incident response tabletop exercises simulating ransomware compromise.',
        'why_it_matters': 'Tests communication channels, team preparedness, and operational response speed under stress.',
        'weight': 2,
        'remediation_tip': 'Include legal, PR, insurance, and C-suite stakeholders in realistic simulation scenarios.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RESPOND',
        'control_code': 'communication_plan',
        'control_title': 'Out-of-Band Emergency Communication Channel',
        'control_description': 'Establish secondary out-of-band communication methods (e.g., Signal, separate email domain) during incident handling.',
        'why_it_matters': 'Attackers often monitor internal Exchange/Teams communications once network access is compromised.',
        'weight': 2,
        'remediation_tip': 'Set up pre-provisioned out-of-band communication accounts for key incident handlers.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RESPOND',
        'control_code': 'external_contacts',
        'control_title': 'Pre-Established Retainer & Legal Contacts',
        'control_description': 'Maintain active retainers with external forensic IR firms, legal counsel, and cyber insurance providers.',
        'why_it_matters': 'Shortens response time and secures specialized digital forensics expertise during critical incidents.',
        'weight': 1,
        'remediation_tip': 'Keep offline emergency contact lists for incident responders, legal counsel, and law enforcement (CISA/FBI).',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RESPOND',
        'control_code': 'ransomware_playbook',
        'control_title': 'Automated Host Isolation & Process Quarantine',
        'control_description': 'Deploy automated capabilities to freeze or kill malicious process trees immediately upon threat detection.',
        'why_it_matters': 'Automated process termination stops ransomware encryption before it reaches secondary folders.',
        'weight': 3,
        'remediation_tip': 'Enable automated process suspension and socket alerts for critical threat triggers.',
        'auto_detectable': False,
        'auto_detect_key': None
    },

    # --- RECOVER DOMAIN ---
    {
        'domain_code': 'RECOVER',
        'control_code': 'rto_rpo_defined',
        'control_title': 'Defined Recovery Time & Point Objectives (RTO/RPO)',
        'control_description': 'Establish clear Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) for all critical data.',
        'why_it_matters': 'Sets realistic business expectation and drives data architecture resilience during disaster recovery.',
        'weight': 2,
        'remediation_tip': 'Align backup frequency with RPO targets (e.g., hourly transactional backups for financial databases).',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RECOVER',
        'control_code': 'restore_tested',
        'control_title': 'Bare-Metal & Server Rebuild Automation',
        'control_description': 'Maintain golden OS images and Infrastructure-as-Code (IaC) playbooks to rapidly rebuild compromised servers.',
        'why_it_matters': 'Rebuilding clean infrastructure from scratch is safer than decrypting or patching infected OS installations.',
        'weight': 2,
        'remediation_tip': 'Automate OS image deployment via PXE/MDM and store configuration playbooks in secure code repositories.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RECOVER',
        'control_code': 'clean_backups_available',
        'control_title': 'Pre-Restoration Malware & Persistence Scanning',
        'control_description': 'Scan restored backup volumes for hidden web shells, persistence mechanisms, or dormant payloads prior to production boot.',
        'why_it_matters': 'Prevents re-infection cycles caused by restoring backups that contain dormant attacker backdoors.',
        'weight': 2,
        'remediation_tip': 'Mount backup volumes in isolated staging networks and perform full AV/EDR scans before production cutover.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'RECOVER',
        'control_code': 'business_continuity_plan',
        'control_title': 'Business Continuity & Manual Process Operations',
        'control_description': 'Maintain manual paper/offline business operating procedures during prolonged IT network outages.',
        'why_it_matters': 'Allows essential organizational operations to continue even during total IT infrastructure downtime.',
        'weight': 2,
        'remediation_tip': 'Review offline business continuity playbooks annually with operational department leads.',
        'auto_detectable': False,
        'auto_detect_key': None
    },

    # --- PEOPLE DOMAIN ---
    {
        'domain_code': 'PEOPLE',
        'control_code': 'security_training',
        'control_title': 'Mandatory Security Awareness Training',
        'control_description': 'Require all employees to complete security awareness training covering phishing and password hygiene.',
        'why_it_matters': 'Human error remains the primary trigger for initial access and credential compromise.',
        'weight': 2,
        'remediation_tip': 'Conduct quarterly interactive training modules with tracking for completion compliance.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PEOPLE',
        'control_code': 'phishing_simulation',
        'control_title': 'Regular Simulated Phishing Campaigns',
        'control_description': 'Execute unannounced simulated phishing tests to measure employee click rates and reporting habits.',
        'why_it_matters': 'Identifies high-risk user groups and reinforces vigilant link-clicking behavior.',
        'weight': 2,
        'remediation_tip': 'Provide immediate targeted micro-learning for users who fail simulated phishing exercises.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PEOPLE',
        'control_code': 'policy_acknowledged',
        'control_title': 'Acceptable Use & Security Policy Acknowledgment',
        'control_description': 'Require signed annual acknowledgment of Acceptable Use Policies (AUP) and remote work security rules.',
        'why_it_matters': 'Ensures legal clarity and compliance regarding corporate IT asset usage and personal device access.',
        'weight': 1,
        'remediation_tip': 'Integrate policy sign-off into annual performance reviews and HR onboarding workflows.',
        'auto_detectable': False,
        'auto_detect_key': None
    },
    {
        'domain_code': 'PEOPLE',
        'control_code': 'vendor_risk_awareness',
        'control_title': 'Third-Party Vendor & Supply Chain Risk Management',
        'control_description': 'Assess security controls and access privileges of third-party vendors and MSPs with network connectivity.',
        'why_it_matters': 'Ransomware actors frequently compromise MSPs or software vendors to gain access to customer networks.',
        'weight': 2,
        'remediation_tip': 'Require third-party vendors to enforce MFA and perform annual vendor risk assessments.',
        'auto_detectable': False,
        'auto_detect_key': None
    }
]
