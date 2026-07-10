# SentinelPulse Full-Stack Python Backend Server
# Written using built-in libraries to ensure dependency-free execution

import os
import json
import time
import random
import threading
import socketserver
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 8000
DB_FILE = "db.json"

# Initial mock database configuration
DEFAULT_DB = {
  "alerts": [
    {
      "id": "SOC-2026-0001",
      "title": "Cobalt Strike Beacon Execution Detected",
      "severity": "critical",
      "system": "CrowdStrike Falcon",
      "eventId": "EV-9921-A",
      "time": "2026-07-10T18:02:15Z",
      "source": "10.0.4.15 (DC-01)",
      "dest": "185.220.101.5 (External IP)",
      "asset": "DC-01.rebel.ops",
      "status": "new",
      "tiMatched": True,
      "description": "A Cobalt Strike beacon communication sequence was identified running under LSASS shell credentials. The process spawned child processes attempting connection to known Tor exit nodes and suspicious external Command and Control (C2) domains.",
      "threatIntel": {
        "actor": "APT29 (Cozy Bear)",
        "confidence": "96%",
        "malware": "Cobalt Strike / Beacon",
        "status": "TI MATCHED"
      },
      "mitre": ["T1059.001", "T1071.004", "T1041", "T1021"],
      "entities": [
        { "class": "host", "val": "DC-01.rebel.ops", "role": "Target Asset" },
        { "class": "ip", "val": "10.0.4.15", "role": "Source IP" },
        { "class": "ip", "val": "185.220.101.5", "role": "Malicious Dest IP" },
        { "class": "user", "val": "SYSTEM", "role": "Security Context" },
        { "class": "process", "val": "lsass.exe", "role": "Parent Execution" }
      ],
      "timeline": [
        { "time": "18:02:15", "title": "Security Alert Generated", "details": "CrowdStrike detected threat execution sequence.", "active": True },
        { "time": "18:03:00", "title": "Threat Intel Enriched", "details": "Target destination IP matched AlienVault OTX active C2 indicators.", "active": True },
        { "time": "18:04:10", "title": "Automatic Containment Attempt", "details": "Host isolation recommended. Pending manager verification.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0002",
      "title": "LockBit 3.0 Ransomware Execution Attempt",
      "severity": "critical",
      "system": "SentinelOne Core",
      "eventId": "EV-8822-B",
      "time": "2026-07-10T17:58:30Z",
      "source": "10.0.12.82 (WS-LEGAL-04)",
      "dest": "Local Disk (D:\\)",
      "asset": "WS-LEGAL-04 (Legal Workstation)",
      "status": "investigating",
      "tiMatched": True,
      "description": "High-volume file modifications and entropy changes consistent with ransomware encryption patterns were detected. The SentinelOne agent intercepted the process and suspended execution.",
      "threatIntel": {
        "actor": "LockBit Syndicate",
        "confidence": "98%",
        "malware": "LockBit 3.0 (Black)",
        "status": "TI MATCHED"
      },
      "mitre": ["T1486", "T1562.001", "T1543.003"],
      "entities": [
        { "class": "host", "val": "WS-LEGAL-04", "role": "Impacted Host" },
        { "class": "file", "val": "D:\\Legal_Arch.zip", "role": "Encryption Target" },
        { "class": "process", "val": "lb3.exe", "role": "Malicious Payload" },
        { "class": "user", "val": "j.doe-legal", "role": "Compromised User" }
      ],
      "timeline": [
        { "time": "17:58:30", "title": "Ransomware Behavior Blocked", "details": "File modification engine locked out. Process suspended.", "active": True },
        { "time": "17:59:15", "title": "Incident Triaged by SentinelOne", "details": "File recovery snapshots prepared.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0003",
      "title": "APT41 Exfiltration Sequence Detected",
      "severity": "critical",
      "system": "Palo Alto NGFW",
      "eventId": "EV-1029-F",
      "time": "2026-07-10T17:45:00Z",
      "source": "10.0.6.44 (DB-PROD-01)",
      "dest": "45.89.222.18 (External Webserver)",
      "asset": "DB-PROD-01 (MySQL Server)",
      "status": "new",
      "tiMatched": True,
      "description": "An unusual outbound SSH/SFTP session exfiltrating approximately 14.5 GB of compressed database backups to an unrecognized external host was flagged by firewall behavioral patterns.",
      "threatIntel": {
        "actor": "APT41 (Double Dragon)",
        "confidence": "91%",
        "malware": "ShadowPad / Winonti",
        "status": "TI MATCHED"
      },
      "mitre": ["T1048.002", "T1114", "T1078.002"],
      "entities: ": [],
      "entities": [
        { "class": "host", "val": "DB-PROD-01", "role": "Database Server" },
        { "class": "ip", "val": "45.89.222.18", "role": "Destination C2" },
        { "class": "user", "val": "sql_svc", "role": "Access Context" }
      ],
      "timeline": [
        { "time": "17:45:00", "title": "Outbound Data Exfiltration Alert", "details": "14.5 GB volume limit breached on firewall egress rule.", "active": True },
        { "time": "17:46:20", "title": "Actor Correlation Match", "details": "Destination host IP matched active APT41 indicators.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0004",
      "title": "LSASS Process Memory Dump (Credential Harvesting)",
      "severity": "critical",
      "system": "Sysmon Enterprise",
      "eventId": "EV-4411-C",
      "time": "2026-07-10T17:30:10Z",
      "source": "10.0.2.110 (WS-HR-02)",
      "dest": "Local Memory Dump (C:\\Temp\\lsass.dmp)",
      "asset": "WS-HR-02.rebel.ops",
      "status": "escalated",
      "tiMatched": False,
      "description": "A memory read and dumping operation was performed on the Local Security Authority Subsystem Service (LSASS) using mimikatz-style Windows API calls. Highly suspicious attempt to extract administrator clear-text passwords.",
      "threatIntel": {
        "actor": "Unknown Penetration Tester / Insider Threat",
        "confidence": "82%",
        "malware": "Mimikatz dump",
        "status": "TI CHECK FAILED"
      },
      "mitre": ["T1003.001", "T1059.001"],
      "entities": [
        { "class": "host", "val": "WS-HR-02.rebel.ops", "role": "Target Client" },
        { "class": "user", "val": "administrator", "role": "Target Account" },
        { "class": "process", "val": "rundll32.exe", "role": "Executing Process" }
      ],
      "timeline": [
        { "time": "17:30:10", "title": "Sysmon Event ID 10 Registered", "details": "Process access on lsass.exe request granted to rundll32.exe.", "active": True },
        { "time": "17:32:00", "title": "SOC Alert Escalated", "details": "Assigned to Tier 2 Lead for credential change validation.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0005",
      "title": "Spearphishing Email Macro Code Execution",
      "severity": "high",
      "system": "Microsoft Defender for Office 365",
      "eventId": "EV-2099-M",
      "time": "2026-07-10T16:50:00Z",
      "source": "mail.rebel.ops (Exchange Server)",
      "dest": "WS-HR-01.rebel.ops (HR Client)",
      "asset": "WS-HR-01.rebel.ops",
      "status": "new",
      "tiMatched": True,
      "description": "User downloaded a phishing document containing macros from a spoofed tax invoice email. The document spawned cmd.exe and downloaded a second-stage Agent Tesla spyware payload.",
      "threatIntel": {
        "actor": "FIN7 / Unknown phishing crew",
        "confidence": "88%",
        "malware": "Agent Tesla payload",
        "status": "TI MATCHED"
      },
      "mitre": ["T1566.001", "T1204.002", "T1105"],
      "entities": [
        { "class": "host", "val": "WS-HR-01.rebel.ops", "role": "Victim Client" },
        { "class": "user", "val": "a.smith-hr", "role": "Recipient User" },
        { "class": "file", "val": "TaxInvoice_Q3.doc", "role": "Phishing Attachment" }
      ],
      "timeline": [
        { "time": "16:50:00", "title": "Phishing Email Open", "details": "Exchange recorded email delivery and open trigger.", "active": True },
        { "time": "16:51:10", "title": "Macro Process Execution", "details": "Word spawned powershell execution. Agent Tesla payload downloaded.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0006",
      "title": "Exchange AD Domain Brute Force Attack",
      "severity": "high",
      "system": "Active Directory Logs",
      "eventId": "EV-4625-N",
      "time": "2026-07-10T16:15:45Z",
      "source": "203.0.113.88 (Tor Proxy IP)",
      "dest": "10.0.1.10 (Exchange / Active Directory)",
      "asset": "Exchange.rebel.ops",
      "status": "new",
      "tiMatched": True,
      "description": "Multiple failed authentication attempts detected against the Exchange Outlook Web Access endpoint. Failed attempts targeted 14 different management accounts within a 3-minute period.",
      "threatIntel": {
        "actor": "Brute-force Threat Actors",
        "confidence": "90%",
        "malware": "Spray attack tools",
        "status": "TI MATCHED"
      },
      "mitre": ["T1110.003", "T1078.002"],
      "entities": [
        { "class": "host", "val": "Exchange.rebel.ops", "role": "Mail Server" },
        { "class": "ip", "val": "203.0.113.88", "role": "Attacking IP" },
        { "class": "user", "val": "admin-exchange", "role": "Target Profile" }
      ],
      "timeline": [
        { "time": "16:15:45", "title": "Authentication Failures Spike", "details": "148 authentication failures recorded in 3 minutes.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0007",
      "title": "AWS IAM Role Assumption Privilege Escalation",
      "severity": "high",
      "system": "AWS CloudTrail",
      "eventId": "EV-aws-77",
      "time": "2026-07-10T15:40:22Z",
      "source": "AWS IAM Console",
      "dest": "AWS Cloud Infrastructure",
      "asset": "Production AWS Environment",
      "status": "investigating",
      "tiMatched": False,
      "description": "A database-developer role was assumed from an external IP address, followed immediately by security-group policy changes opening database ports to the wider internet.",
      "threatIntel": {
        "actor": "Internal Account Misconfig / Malicious session hijacking",
        "confidence": "65%",
        "malware": "N/A",
        "status": "TI CHECK FAILED"
      },
      "mitre": ["T1078.004", "T1136.003"],
      "entities": [
        { "class": "domain", "val": "AWS-Production", "role": "Cloud Tenant" },
        { "class": "user", "val": "dev_user_ops", "role": "Assumed User" },
        { "class": "ip", "val": "198.51.100.14", "role": "Client Source IP" }
      ],
      "timeline": [
        { "time": "15:40:22", "title": "IAM AssumeRole Event", "details": "Role 'DB_Admin_Svc' assumed by user 'dev_user_ops'.", "active": True },
        { "time": "15:42:00", "title": "Security Group Modified", "details": "Inbound SSH rule open to 0.0.0.0/0.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0008",
      "title": "AD DC Shadow Copy Extraction Attempt (NTDS.dit)",
      "severity": "high",
      "system": "Windows Defender ATP",
      "eventId": "EV-7731-P",
      "time": "2026-07-10T15:10:00Z",
      "source": "10.0.4.15 (DC-01)",
      "dest": "vssadmin dump file",
      "asset": "DC-01.rebel.ops",
      "status": "escalated",
      "tiMatched": False,
      "description": "Execution of vssadmin command-line parameters attempting to create a volume shadow copy of the active directory database (ntds.dit). Intention is offline credential decryption.",
      "threatIntel": {
        "actor": "Adversary exploiting AD Database Dump",
        "confidence": "80%",
        "malware": "ntds.dit extractor",
        "status": "TI CHECK FAILED"
      },
      "mitre": ["T1003.003", "T1059.001"],
      "entities": [
        { "class": "host", "val": "DC-01.rebel.ops", "role": "Active Directory DC" },
        { "class": "process", "val": "vssadmin.exe", "role": "Executing Utility" },
        { "class": "user", "val": "SYSTEM", "role": "Running Privilege" }
      ],
      "timeline": [
        { "time": "15:10:00", "title": "vssadmin command flagged", "details": "Volume creation command intercepted and blocked.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0009",
      "title": "Suspicious PowerShell Ingestion Script Running",
      "severity": "medium",
      "system": "Sysmon Enterprise",
      "eventId": "EV-3211-P",
      "time": "2026-07-10T14:55:00Z",
      "source": "10.0.12.45 (WS-LEGAL-01)",
      "dest": "GitHub Raw (Gist)",
      "asset": "WS-LEGAL-01 (Legal Client)",
      "status": "investigating",
      "tiMatched": False,
      "description": "An obfuscated base64 encoded PowerShell script was loaded in memory on legal client workstation. The script retrieves telemetry libraries from a Gist repository.",
      "threatIntel": {
        "actor": "Unknown",
        "confidence": "50%",
        "malware": "PowerShell Downloader",
        "status": "TI CHECK FAILED"
      },
      "mitre": ["T1059.001", "T1140"],
      "entities": [
        { "class": "host", "val": "WS-LEGAL-01", "role": "Legal client" },
        { "class": "process", "val": "powershell.exe", "role": "Command Engine" },
        { "class": "user", "val": "a.legal-clerk", "role": "User Profile" }
      ],
      "timeline": [
        { "time": "14:55:00", "title": "Obfuscated powershell script ran", "details": "Bypass execution policy used to load shell script.", "active": True }
      ]
    },
    {
      "id": "SOC-2026-0010",
      "title": "Tor Exit Node Connection Attempt",
      "severity": "medium",
      "system": "Palo Alto NGFW",
      "eventId": "EV-0091-E",
      "time": "2026-07-10T14:10:35Z",
      "source": "10.0.10.12 (WS-SALES-10)",
      "dest": "109.163.220.129 (Tor Router)",
      "asset": "WS-SALES-10 (Sales Client)",
      "status": "new",
      "tiMatched": True,
      "description": "An outgoing connection attempt was observed on standard ports to a registered Tor directory/routing server node. Blocked by egress security policies.",
      "threatIntel": {
        "actor": "Tor proxy relay",
        "confidence": "95%",
        "malware": "Tor browser / anonymity agent",
        "status": "TI MATCHED"
      },
      "mitre": ["T1071"],
      "entities": [
        { "class": "host", "val": "WS-SALES-10", "role": "Target workstation" },
        { "class": "ip", "val": "109.163.220.129", "role": "Tor Router IP" },
        { "class": "user", "val": "r.sales-rep", "role": "Logged User" }
      ],
      "timeline": [
        { "time": "14:10:35", "title": "Egress Connection Intercepted", "details": "Tor router target blocked by Palo Alto.", "active": True }
      ]
    }
  ],

  "actors": [
    { "name": "APT29 (Cozy Bear)", "level": "Critical", "status": "Active", "campaigns": "Operation NightShade" },
    { "name": "LockBit Syndicate", "level": "Critical", "status": "Mitigated", "campaigns": "LockBit Outbreak — Legal Dept" },
    { "name": "APT41 (Double Dragon)", "level": "Critical", "status": "Active", "campaigns": "Database Exfil Sequence" },
    { "name": "FIN7 Phishing Crew", "level": "High", "status": "Active", "campaigns": "HR Phishing Campaign" },
    { "name": "Threat Actor Spray Group", "level": "High", "status": "Active", "campaigns": "Cloud Credential Attack" }
  ],

  "campaigns": [
    {
      "id": "CAMP-01",
      "title": "Operation NightShade",
      "status": "active",
      "severity": "critical",
      "desc": "Coordinated adversary intrusion campaign targeting enterprise domain controllers. Payload execution incorporates Cobalt Strike beacon implants, exfiltrating credential hashes to external C2 nodes.",
      "alerts": 4, "iocs": 3, "assets": 3,
      "actors": ["APT29", "Cozy Bear"],
      "mitre": ["T1059.001", "T1003.001", "T1041", "T1077", "T1021"],
      "timeline": [
        { "date": "Jul 10, 18:02", "details": "Active Cobalt Strike beacon detected on Domain Controller." },
        { "date": "Jul 10, 15:10", "details": "NTDS.dit Shadow copy extraction attempt on DC-01." }
      ]
    },
    {
      "id": "CAMP-02",
      "title": "LockBit Outbreak — Legal Dept",
      "status": "contained",
      "severity": "critical",
      "desc": "Outbreak of LockBit 3.0 ransomware targeting legal department workstations. Endpoint agents contained file system changes, though persistent backdoors require credential purging.",
      "alerts": 2, "iocs": 1, "assets": 2,
      "actors": ["LockBit Syndicate"],
      "mitre": ["T1486", "T1562.001", "T1543.003"],
      "timeline": [
        { "date": "Jul 10, 17:58", "details": "Ransomware encryption suspended on WS-LEGAL-04." },
        { "date": "Jul 10, 14:55", "details": "Obfuscated PowerShell loader script verified on WS-LEGAL-01." }
      ]
    },
    {
      "id": "CAMP-03",
      "title": "HR Phishing Campaign",
      "status": "active",
      "severity": "high",
      "desc": "Spear-phishing vector targeting human resources staff. Delivery uses macro-enabled tax documents deploying Agent Tesla spyware components to capture keystrokes and credentials.",
      "alerts": 4, "iocs": 3, "assets": 2,
      "actors": ["FIN7 Phishing Crew"],
      "mitre": ["T1566.001", "T1204.002", "T1105", "T1071.004"],
      "timeline": [
        { "date": "Jul 10, 16:50", "details": "Agent Tesla execution recorded on WS-HR-01." }
      ]
    },
    {
      "id": "CAMP-04",
      "title": "Cloud Credential Attack",
      "status": "active",
      "severity": "high",
      "desc": "Brute force and credential spray operations directed towards Exchange and Azure Active Directory profiles originating from Tor exit addresses, culminating in AWS IAM role assumptions.",
      "alerts": 3, "iocs": 3, "assets": 3,
      "actors": ["Unknown Threat Actors"],
      "mitre": ["T1110.003", "T1078.004", "T1136.003"],
      "timeline": [
        { "date": "Jul 10, 16:15", "details": "Exchange failed login spray identified from 203.0.113.88." },
        { "date": "Jul 10, 15:40", "details": "AWS Database Role assumption from unrecognized IP." }
      ]
    }
  ],

  "huntingQueries": [
    { "id": "q1", "title": "Cobalt Strike Beacon Patterns", "version": "v1.2", "tag": "APT29", "results": 2, "author": "secops-mgr", "desc": "Scan network traffic for standard beacon communication beacons and matching TCP handshake profiles." },
    { "id": "q2", "title": "LSASS Memory Dump Attempts", "version": "v2.0", "tag": "Credential Access", "results": 2, "author": "secops-lead", "desc": "Identify process access requests on LSASS memory vectors targeting credential extraction." },
    { "id": "q3", "title": "Tor Exit Node Connections", "version": "v1.0", "tag": "Anonymization", "results": 2, "author": "tier1-lead", "desc": "Match outgoing system firewalls logs with registered and updated lists of active Tor routing proxies." },
    { "id": "q4", "title": "Suspicious PowerShell Scripts", "version": "v1.4", "tag": "Execution", "results": 1, "author": "secops-mgr", "desc": "Check endpoint command telemetry for obfuscated, base64 encoded, or bypass-policy PowerShell scripts." },
    { "id": "q5", "title": "Ransomware File Extensions", "version": "v2.1", "tag": "Impact", "results": 1, "author": "threat-intel", "desc": "Flag spikes in filesystem modifications involving known ransomware output header extensions (e.g. .lockbit, .wannacry)." },
    { "id": "q6", "title": "AWS Privilege Escalation Logs", "version": "v1.1", "tag": "Cloud Security", "results": 1, "author": "cloud-sec", "desc": "Audit CloudTrail console policies for unusual role assumptions followed by group rules overrides." }
  ],

  "compliancePCI": [
    { "req": "Req 3", "name": "Protect stored cardholder data", "alerts": 3, "status": "warning" },
    { "req": "Req 4", "name": "Encrypt transmission of cardholder data across open, public networks", "alerts": 0, "status": "compliant" },
    { "req": "Req 5", "name": "Protect all systems against malware and regularly update anti-virus software", "alerts": 1, "status": "compliant" },
    { "req": "Req 6", "name": "Develop and maintain secure systems and software applications", "alerts": 5, "status": "warning" },
    { "req": "Req 7", "name": "Restrict access to cardholder data by business need-to-know", "alerts": 0, "status": "compliant" },
    { "req": "Req 8", "name": "Identify and authenticate access to system components", "alerts": 12, "status": "critical" },
    { "req": "Req 10", "name": "Track and monitor all access to network resources and cardholder data", "alerts": 2, "status": "compliant" },
    { "req": "Req 11", "name": "Regularly test security systems and network operational processes", "alerts": 0, "status": "compliant" }
  ],

  "scheduledReports": [
    { "title": "Daily SOC Threat Summary", "timing": "Every day at 08:00 (PDF format, 5 recipients)", "active": True },
    { "title": "Weekly Executive Security Brief", "timing": "Every Monday at 09:00 (PDF format, 12 recipients)", "active": True },
    { "title": "Monthly Compliance Audit Report", "timing": "1st of month at 10:00 (HTML format, 8 recipients)", "active": True }
  ]
}

# Database management helper functions
def read_db():
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump(DEFAULT_DB, f, indent=2)
        return DEFAULT_DB
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except:
        return DEFAULT_DB

def write_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Threat Generation Simulator Thread Loop
def threat_generation_simulator():
    titles = [
        "Exchange PowerShell Admin Abuse Detected",
        "Outbound SCP Backup Upload Spike",
        "AWS S3 Bucket Public ACL Modification",
        "WS-LEGAL-02 Process Masquerading (svchost)",
        "LSASS Memory Shadow Snapshot Dump",
        "Potential WannaCry Killswitch Bypass attempt"
    ]
    assets = ["DC-01.rebel.ops", "Exchange.rebel.ops", "WS-LEGAL-02.rebel.ops", "DB-PROD-01.rebel.ops", "Production AWS Env"]
    severities = ["critical", "high", "medium"]
    sources = ["10.0.4.15", "10.0.1.10", "10.0.12.44", "10.0.6.44", "203.0.113.5"]
    destinations = ["185.220.101.99", "45.89.222.102", "198.51.100.82", "github.com/payloads"]
    actors = ["APT29", "APT41", "LockBit Syndicate", "Unknown Threat Actor"]

    while True:
        # Generate new alert every 30 seconds
        time.sleep(30)
        try:
            db = read_db()
            
            # Formulate alert ID
            num = len(db["alerts"]) + 1
            alert_id = f"SOC-2026-{num:04d}"
            
            title = random.choice(titles)
            severity = random.choice(severities)
            asset = random.choice(assets)
            src = random.choice(sources)
            dst = random.choice(destinations)
            actor = random.choice(actors)
            
            new_alert = {
                "id": alert_id,
                "title": title,
                "severity": severity,
                "system": "Sentinel Telemetry Engine",
                "eventId": f"EV-{random.randint(1000, 9999)}-X",
                "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": src,
                "dest": dst,
                "asset": asset,
                "status": "new",
                "tiMatched": random.choice([True, False]),
                "description": f"An automated detection routine triggered on target host {asset}. Outbound telemetry indicates suspicious activity targeting {dst} context credentials.",
                "threatIntel": {
                    "actor": actor,
                    "confidence": f"{random.randint(70, 99)}%",
                    "malware": "Suspicious Payload Injection",
                    "status": "TI MATCHED" if random.choice([True, False]) else "TI CHECK FAILED"
                },
                "mitre": ["T1059.001", "T1071"],
                "entities": [
                    { "class": "host", "val": asset, "role": "Victim Node" },
                    { "class": "ip", "val": src, "role": "Source Address" }
                ],
                "timeline": [
                    { "time": datetime.now().strftime("%H:%M:%S"), "title": "Alert Triggered", "details": "Automatic telemetry collection.", "active": True }
                ]
            }

            db["alerts"].insert(0, new_alert)
            write_db(db)
            print(f"[SIMULATOR] Inserted new background threat alert: {alert_id} - {title}")
        except Exception as e:
            print(f"[SIMULATOR ERROR] {e}")


# Custom HTTP Request Handler Class
class SentinelPulseRequestHandler(SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Override to suppress excessive request logging
        pass

    def end_headers(self):
        # Add CORS headers for simplicity
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self):
        # Answer CORS preflight requests
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        url_parsed = urlparse(self.path)
        path = url_parsed.path

        # Handle API Routes
        if path.startswith("/api/"):
            self.handle_api_get(path, parse_qs(url_parsed.query))
        else:
            # Fallback to serving static files
            super().do_GET()

    def do_POST(self):
        url_parsed = urlparse(self.path)
        path = url_parsed.path

        if path.startswith("/api/"):
            # Read POST body contents
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                body = json.loads(post_data.decode('utf-8'))
            except:
                body = {}
            self.handle_api_post(path, body)
        else:
            self.send_error(404, "File Not Found")

    def handle_api_get(self, path, params):
        db = read_db()

        if path == "/api/alerts":
            alerts = db["alerts"]
            
            # Support simple backend filtering (severity & tiMatched)
            if "severity" in params:
                severities = params["severity"]
                alerts = [a for a in alerts if a["severity"] in severities]
            
            if "tiMatched" in params:
                ti_matched = params["tiMatched"][0] == "true"
                alerts = [a for a in alerts if a["tiMatched"] == ti_matched]

            self.send_json_response(alerts)

        elif path == "/api/campaigns":
            self.send_json_response(db["campaigns"])

        elif path == "/api/kpis":
            # Formulate dynamic counts from DB
            alerts = db["alerts"]
            counts = {
                "total": len(alerts),
                "critical": len([a for a in alerts if a["severity"] == "critical"]),
                "escalated": len([a for a in alerts if a["status"] == "escalated"]),
                "new": len([a for a in alerts if a["status"] == "new"]),
            }
            response = {
                "counts": counts,
                "actors": db["actors"]
            }
            self.send_json_response(response)

        elif path == "/api/compliance":
            self.send_json_response(db["compliancePCI"])

        else:
            self.send_error(404, "Endpoint Not Found")

    def handle_api_post(self, path, body):
        db = read_db()

        if path == "/api/alerts":
            # Create/Simulate manual alert
            num = len(db["alerts"]) + 1
            alert_id = f"SOC-2026-{num:04d}"

            new_alert = {
                "id": alert_id,
                "title": body.get("title", "Manual Penetration Event"),
                "severity": body.get("severity", "medium"),
                "system": body.get("system", "Manual Ingestion"),
                "eventId": f"EV-{random.randint(1000, 9999)}-M",
                "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": body.get("source", "127.0.0.1"),
                "dest": body.get("dest", "127.0.0.1"),
                "asset": body.get("asset", "Unknown Client"),
                "status": "new",
                "tiMatched": body.get("tiMatched", False),
                "description": body.get("description", "A manually generated threat alert simulation vector."),
                "threatIntel": {
                    "actor": "Manual Simulator",
                    "confidence": "100%",
                    "malware": "Simulation Payload",
                    "status": "TI MATCHED" if body.get("tiMatched", False) else "TI CHECK FAILED"
                },
                "mitre": body.get("mitre", ["T1059.001"]),
                "entities": [
                    { "class": "host", "val": body.get("asset"), "role": "Target Host" },
                    { "class": "ip", "val": body.get("source"), "role": "Source IP" }
                ],
                "timeline": [
                    { "time": datetime.now().strftime("%H:%M:%S"), "title": "Alert Generated", "details": "Manually simulated SOC threat.", "active": True }
                ]
            }

            db["alerts"].insert(0, new_alert)
            write_db(db)
            self.send_json_response(new_alert)

        elif path == "/api/alerts/status":
            # Update triage status
            alert_id = body.get("id")
            new_status = body.get("status")

            matched = None
            for alert in db["alerts"]:
                if alert["id"] == alert_id:
                    alert["status"] = new_status
                    alert["timeline"].append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "title": f"Status Changed to {new_status.toUpperCase() if hasattr(new_status, 'toUpperCase') else new_status.upper()}",
                        "details": "Manual status triage performed by user secops-mgr.",
                        "active": True
                    })
                    matched = alert
                    break
            
            if matched:
                write_db(db)
                self.send_json_response({ "success": True, "alert": matched })
            else:
                self.send_error(404, "Alert Not Found")

        elif path == "/api/hunting/run":
            # Process backend threat query searches
            query = body.get("query", "").strip().lower()
            alerts = db["alerts"]
            filtered = []

            if not query:
                self.send_json_response([])
                return

            # Advanced backend query parsing logic
            # e.g., process.name:"lsass.exe" OR severity:"critical"
            # Support simple match checks
            for alert in alerts:
                # Check fields
                alert_text = (alert["title"] + alert["description"] + alert["asset"] + alert["id"]).lower()
                
                # Check specific field definitions
                matches_criteria = False
                
                if "lsass.exe" in query and any(ent.get("val") == "lsass.exe" for ent in alert["entities"]):
                    matches_criteria = True
                elif "rundll32.exe" in query and any(ent.get("val") == "rundll32.exe" for ent in alert["entities"]):
                    matches_criteria = True
                elif "109.163" in query and (alert["source"].startswith("109.163") or alert["dest"].startswith("109.163")):
                    matches_criteria = True
                elif "powershell" in query and (any(ent.get("val") == "powershell.exe" for ent in alert["entities"]) or "powershell" in alert_text):
                    matches_criteria = True
                elif "lockbit" in query and ("lockbit" in alert_text or any(ent.get("val") == "lb3.exe" for ent in alert["entities"])):
                    matches_criteria = True
                elif "aws" in query and ("aws" in alert_text or any(ent.get("class") == "domain" and "aws" in ent.get("val").lower() for ent in alert["entities"])):
                    matches_criteria = True
                elif "severity:\"critical\"" in query and alert["severity"] == "critical":
                    matches_criteria = True
                elif "severity:\"high\"" in query and alert["severity"] == "high":
                    matches_criteria = True
                # Fallback simple substring search across alert parameters
                elif ":" not in query and query in alert_text:
                    matches_criteria = True

                if matches_criteria:
                    filtered.append(alert)

            self.send_json_response(filtered)

        else:
            self.send_error(404, "Endpoint Not Found")

    def send_json_response(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

# Server initialization entrypoint
def main():
    # Initialize JSON file DB
    read_db()
    
    # Start thread simulator
    sim_thread = threading.Thread(target=threat_generation_simulator, daemon=True)
    sim_thread.start()
    
    # Run socket listener
    server = ThreadingHTTPServer(("localhost", PORT), SentinelPulseRequestHandler)
    print(f"[*] SentinelPulse clone running locally at: http://localhost:{PORT}/")
    print(f"[*] Persistent database file loaded: {DB_FILE}")
    print(f"[*] Background threat generator simulator initiated (30 second intervals)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down SOC platform backend server.")

if __name__ == "__main__":
    main()
