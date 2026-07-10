# SentinelPulse - Security Operations Platform Clone

SentinelPulse is a high-fidelity, high-performance Security Operations Center (SOC) dashboard application designed for monitoring security events, triaging alerts, mapping adversarial tactics, executing threat hunting queries, and tracking active campaigns.

This project is cloned from the original SentinelPulse application at `https://rebel-sentinel-pulse-ops.base44.app/`.

---

## ⚡ Key Features

1. **SOC Commander Dashboard**: Real-time event ingestion telemetry line charts, severity distribution charts, active threats, and top threat actors.
2. **Alert Queue Triage**: Multi-checkbox severity filtering, AlienVault OTX Threat Intelligence details, involved entities list, and chronological incident timelines.
3. **Entity Graph Explorer**: Relationship mappings for hosts, IPs, users, domains, files, processes, and alerts. Includes a BFS-driven Path Finder to trace lateral propagation paths.
4. **MITRE ATT&CK Matrix**: Interactive enterprise tactics heatmap mapping active threat counts, linking directly back to relevant alerts.
5. **Threat Hunting Workbench**: Core syntax search command bar, saved hunting templates, and time-distribution histograms.
6. **Campaign Detection Grid**: Aggregated views of active adversary operations (such as APT29 cozy bear campaigns or LockBit ransomware outbreaks).
7. **Management KPIs & Posture**: Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), and composite safety health gauges.
8. **Compliance Auditor**: PCI DSS requirements tracking alongside an on-demand draft report builder (PDF/HTML generation).
9. **SOC Wall Mode**: Rotating fullscreen presentation displays with spacebar pausing and manual tab navigation controls.

---

## 🛠️ Full-Stack Technology

The application is structured to run with **zero external dependencies** and can be deployed instantly:
* **Frontend**: Pure HTML5, Vanilla CSS (cyber dark design theme), and Vanilla JavaScript (custom router, SVG graph drawings). Icons are loaded via Lucide CDN and charts via Chart.js CDN.
* **Backend**: A multithreaded Python server (`server.py`) using built-in standard libraries to serve static files and expose REST API endpoints.
* **Database**: Lightweight JSON persistence (`db.json`) recording all status logs and simulated alerts.
* **Simulator**: An integrated backend thread generating random realistic threat telemetry every 30 seconds to simulate a live operational feed.

---

## 🚀 Getting Started

Ensure you have **Python 3** installed on your system.

1. Clone or download the files.
2. Open your terminal in the project directory.
3. Start the multithreaded server:
   ```powershell
   python -u server.py
   ```
4. Open your web browser and navigate to:
   ```
   http://127.0.0.1:8000/
   ```
