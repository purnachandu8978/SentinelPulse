// SentinelPulse Full-Stack Client Logic & State Engine

// 1. DYNAMIC STATE STORAGE
const STATE = {
  alerts: [],
  actors: [],
  campaigns: [],
  huntingQueries: [
    { id: "q1", title: "Cobalt Strike Beacon Patterns", version: "v1.2", tag: "APT29", results: 2, author: "secops-mgr", desc: "Scan network traffic for standard beacon communication beacons and matching TCP handshake profiles." },
    { id: "q2", title: "LSASS Memory Dump Attempts", version: "v2.0", tag: "Credential Access", results: 2, author: "secops-lead", desc: "Identify process access requests on LSASS memory vectors targeting credential extraction." },
    { id: "q3", title: "Tor Exit Node Connections", version: "v1.0", tag: "Anonymization", results: 2, author: "tier1-lead", desc: "Match outgoing system firewalls logs with registered and updated lists of active Tor routing proxies." },
    { id: "q4", title: "Suspicious PowerShell Scripts", version: "v1.4", tag: "Execution", results: 1, author: "secops-mgr", desc: "Check endpoint command telemetry for obfuscated, base64 encoded, or bypass-policy PowerShell scripts." },
    { id: "q5", title: "Ransomware File Extensions", version: "v2.1", tag: "Impact", results: 1, author: "threat-intel", desc: "Flag spikes in filesystem modifications involving known ransomware output header extensions (e.g. .lockbit, .wannacry)." },
    { id: "q6", title: "AWS Privilege Escalation Logs", version: "v1.1", tag: "Cloud Security", results: 1, author: "cloud-sec", desc: "Audit CloudTrail console policies for unusual role assumptions followed by group rules overrides." }
  ],
  compliancePCI: [],
  scheduledReports: [
    { title: "Daily SOC Threat Summary", timing: "Every day at 08:00 (PDF format, 5 recipients)", active: true },
    { title: "Weekly Executive Security Brief", timing: "Every Monday at 09:00 (PDF format, 12 recipients)", active: true },
    { title: "Monthly Compliance Audit Report", timing: "1st of month at 10:00 (HTML format, 8 recipients)", active: true }
  ],
  selectedAlertId: null,
  activeWallTab: "critical",
  wallPaused: false,
  activeReportBlocks: ["summary", "mitre", "iocs"]
};

// 2. API CALL WRAPPERS
async function fetchAlertsFromApi(queryParams = "") {
  try {
    const res = await fetch(`/api/alerts${queryParams}`);
    if (res.ok) {
      STATE.alerts = await res.json();
      return STATE.alerts;
    }
  } catch (err) {
    console.error("API error loading alerts:", err);
  }
  return [];
}

async function fetchCampaignsFromApi() {
  try {
    const res = await fetch('/api/campaigns');
    if (res.ok) {
      STATE.campaigns = await res.json();
    }
  } catch (err) {
    console.error("API error loading campaigns:", err);
  }
}

async function fetchKpisFromApi() {
  try {
    const res = await fetch('/api/kpis');
    if (res.ok) {
      const data = await res.json();
      STATE.actors = data.actors;
      
      // Update counters in elements
      const updateEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
      };
      
      updateEl("kpi-open-alerts", data.counts.total);
      updateEl("kpi-critical-open", data.counts.critical);
      updateEl("sidebar-alert-count", data.counts.total);
      updateEl("kpis-open-total", data.counts.total);
      updateEl("kpis-open-critical", data.counts.critical);
      updateEl("kpis-open-escalated", data.counts.escalated);
    }
  } catch (err) {
    console.error("API error loading KPIs:", err);
  }
}

async function fetchComplianceFromApi() {
  try {
    const res = await fetch('/api/compliance');
    if (res.ok) {
      STATE.compliancePCI = await res.json();
    }
  } catch (err) {
    console.error("API error loading compliance:", err);
  }
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch("/api/alerts/status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: alertId, status: newStatus })
    });
    if (res.ok) {
      await fetchAlertsFromApi();
      const updated = STATE.alerts.find(a => a.id === alertId);
      if (updated) openAlertDetailDrawer(updated);
      renderAlertsQueueTable();
      fetchKpisFromApi();
    }
  } catch (err) {
    console.error("Error triaging alert status:", err);
  }
}

async function simulateAlertOnBackend(body) {
  try {
    const res = await fetch("/api/alerts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (res.ok) {
      await fetchAlertsFromApi();
      await fetchKpisFromApi();
      
      // Hide modal popup
      document.getElementById("modal-create-alert").classList.add("hidden");
      
      // Re-render active view contents
      const activeHash = window.location.hash || "#/";
      const routeName = activeHash.replace("#/", "").split("?")[0] || "dashboard";
      if (routeName === "dashboard") {
        renderDashboardAlerts();
        ChartsEngine.initDashboardCharts();
      } else if (routeName === "alerts") {
        renderAlertsQueueTable();
      }
    }
  } catch (err) {
    console.error("Error creating custom simulated alert:", err);
  }
}

// 3. ROUTING ENGINE
const Router = {
  routes: {
    "dashboard": "view-dashboard",
    "alerts": "view-alerts",
    "graph": "view-graph",
    "mitre": "view-mitre",
    "hunting": "view-hunting",
    "campaigns": "view-campaigns",
    "kpis": "view-kpis",
    "compliance": "view-compliance",
    "wall": "view-wall"
  },

  init() {
    window.addEventListener("hashchange", () => this.handleRouting());
    this.handleRouting();
    startAlertsPolling();
  },

  async handleRouting() {
    let hash = window.location.hash || "#/";
    let routeName = hash.replace("#/", "").split("?")[0] || "dashboard";
    
    if (!this.routes[routeName]) {
      routeName = "dashboard";
      window.location.hash = "#/";
    }

    const targetSectionId = this.routes[routeName];
    const shell = document.getElementById("app-shell");
    const wallView = document.getElementById("view-wall");
    
    if (routeName === "wall") {
      shell.style.display = "none";
      wallView.classList.remove("hidden");
      initWallMode();
    } else {
      shell.style.display = "flex";
      wallView.classList.add("hidden");
      stopWallMode();
    }

    document.querySelectorAll(".app-viewport > section").forEach(section => {
      section.classList.remove("active-view");
    });

    if (routeName !== "wall") {
      const section = document.getElementById(targetSectionId);
      if (section) section.classList.add("active-view");
    }

    document.querySelectorAll(".sidebar-nav a").forEach(link => {
      link.classList.remove("active");
      if (link.getAttribute("data-route") === routeName) {
        link.classList.add("active");
      }
    });

    await this.initViewComponents(routeName);
  },

  async initViewComponents(route) {
    // Perform standard API fetches beforehand
    await fetchKpisFromApi();
    
    if (route === "dashboard") {
      await fetchAlertsFromApi();
      ChartsEngine.initDashboardCharts();
      renderDashboardAlerts();
    } else if (route === "alerts") {
      await fetchAlertsFromApi();
      renderAlertsQueueTable();
    } else if (route === "graph") {
      EntityGraphEngine.initGraph();
    } else if (route === "mitre") {
      renderMitreMatrix();
    } else if (route === "hunting") {
      initHuntingWorkbench();
    } else if (route === "campaigns") {
      await fetchCampaignsFromApi();
      renderCampaignsGrid();
    } else if (route === "kpis") {
      ChartsEngine.initKPICharts();
    } else if (route === "compliance") {
      await fetchComplianceFromApi();
      renderComplianceChecklist();
      renderReportBlocks();
    }
  }
};

// 4. TELEMETRY CHARTS ENGINE
const ChartsEngine = {
  instances: {},

  initDashboardCharts() {
    const liveCanvas = document.getElementById("chart-live-alerts");
    if (liveCanvas) {
      if (this.instances["live-alerts"]) this.instances["live-alerts"].destroy();
      
      const ctx = liveCanvas.getContext("2d");
      const labels = Array.from({length: 15}, (_, i) => `${15 - i}s ago`);
      const defaultData = [12, 19, 14, 15, 23, 11, 8, 12, 17, 21, 26, 18, 15, 22, 28];
      
      this.instances["live-alerts"] = new Chart(ctx, {
        type: "line",
        data: {
          labels: labels,
          datasets: [{
            label: "Events Ingested / Sec",
            data: defaultData,
            borderColor: "#00d2ff",
            backgroundColor: "rgba(0, 210, 255, 0.05)",
            borderWidth: 2,
            tension: 0.3,
            fill: true,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "#162030" }, ticks: { color: "#64748b", font: { size: 10 } } },
            y: { grid: { color: "#162030" }, ticks: { color: "#64748b", font: { size: 10 } }, min: 0, max: 40 }
          }
        }
      });
      
      if (this.liveStreamInterval) clearInterval(this.liveStreamInterval);
      this.liveStreamInterval = setInterval(() => {
        const chart = this.instances["live-alerts"];
        if (chart) {
          const randVal = Math.floor(Math.random() * 20) + 10;
          chart.data.datasets[0].data.shift();
          chart.data.datasets[0].data.push(randVal);
          chart.update("none");
          
          const wallChart = this.instances["wall-telemetry"];
          if (wallChart && document.getElementById("view-wall").style.display !== "none") {
            wallChart.data.datasets[0].data.shift();
            wallChart.data.datasets[0].data.push(randVal);
            wallChart.update("none");
          }
        }
      }, 3000);
    }

    const severityCanvas = document.getElementById("chart-severity-donut");
    if (severityCanvas) {
      if (this.instances["severity-donut"]) this.instances["severity-donut"].destroy();
      
      const ctx = severityCanvas.getContext("2d");
      const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      STATE.alerts.forEach(a => counts[a.severity] = (counts[a.severity] || 0) + 1);

      this.instances["severity-donut"] = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels: ["Critical", "High", "Medium", "Low", "Info"],
          datasets: [{
            data: [counts.critical, counts.high, counts.medium, counts.low, counts.info],
            backgroundColor: ["#ff4c4c", "#ff9f43", "#f1c40f", "#3498db", "#00d2ff"],
            borderWidth: 1,
            borderColor: "#101520"
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          cutout: "75%"
        }
      });
    }
  },

  initKPICharts() {
    const mttrCanvas = document.getElementById("chart-kpis-mttr");
    if (mttrCanvas) {
      if (this.instances["kpis-mttr"]) this.instances["kpis-mttr"].destroy();
      const ctx = mttrCanvas.getContext("2d");
      this.instances["kpis-mttr"] = new Chart(ctx, {
        type: "line",
        data: {
          labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
          datasets: [
            {
              label: "Average MTTR (min)",
              data: [58.2, 54.1, 48.7, 49.3, 45.7, 38.2, 41.0],
              borderColor: "#ff9f43",
              backgroundColor: "rgba(255, 159, 67, 0.05)",
              borderWidth: 2,
              tension: 0.2
            },
            {
              label: "SLA Limit (60m)",
              data: [60, 60, 60, 60, 60, 60, 60],
              borderColor: "#ff4c4c",
              borderDash: [5, 5],
              borderWidth: 1.5,
              pointRadius: 0,
              fill: false
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { labels: { color: "#94a3b8" } } },
          scales: {
            x: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" } },
            y: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" }, min: 20 }
          }
        }
      });
    }

    const volumeCanvas = document.getElementById("chart-kpis-volume");
    if (volumeCanvas) {
      if (this.instances["kpis-volume"]) this.instances["kpis-volume"].destroy();
      const ctx = volumeCanvas.getContext("2d");
      this.instances["kpis-volume"] = new Chart(ctx, {
        type: "bar",
        data: {
          labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
          datasets: [{
            label: "Total Log Ingestions (k)",
            data: [22.4, 25.1, 24.8, 28.2, 24.8, 14.5, 12.1],
            backgroundColor: "#3498db",
            borderWidth: 0,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" } },
            y: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" } }
          }
        }
      });
    }

    const tpCanvas = document.getElementById("chart-kpis-tprate");
    if (tpCanvas) {
      if (this.instances["kpis-tprate"]) this.instances["kpis-tprate"].destroy();
      const ctx = tpCanvas.getContext("2d");
      this.instances["kpis-tprate"] = new Chart(ctx, {
        type: "line",
        data: {
          labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
          datasets: [{
            label: "True Positive %",
            data: [82.3, 85.0, 84.6, 88.1, 89.4, 91.2, 88.5],
            borderColor: "#10ac84",
            backgroundColor: "rgba(16, 172, 132, 0.05)",
            borderWidth: 2.5,
            fill: true,
            tension: 0.15
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" } },
            y: { grid: { color: "#1a2336" }, ticks: { color: "#94a3b8" }, max: 100, min: 70 }
          }
        }
      });
    }
  },

  initWallTelemetryChart() {
    const wallCanvas = document.getElementById("chart-wall-telemetry");
    if (wallCanvas) {
      if (this.instances["wall-telemetry"]) this.instances["wall-telemetry"].destroy();
      
      const ctx = wallCanvas.getContext("2d");
      const labels = Array.from({length: 15}, (_, i) => `${15 - i}s ago`);
      const dashboardChart = this.instances["live-alerts"];
      const currentData = dashboardChart ? [...dashboardChart.data.datasets[0].data] : [12, 19, 14, 15, 23, 11, 8, 12, 17, 21, 26, 18, 15, 22, 28];
      
      this.instances["wall-telemetry"] = new Chart(ctx, {
        type: "line",
        data: {
          labels: labels,
          datasets: [{
            data: currentData,
            borderColor: "#ff4c4c",
            backgroundColor: "rgba(255, 76, 76, 0.05)",
            borderWidth: 3,
            tension: 0.3,
            fill: true,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "#1c2638" }, ticks: { color: "#94a3b8", font: { size: 12 } } },
            y: { grid: { color: "#1c2638" }, ticks: { color: "#94a3b8", font: { size: 12 } }, min: 0, max: 40 }
          }
        }
      });
    }
  }
};

// 5. RENDERING ROUTINES FOR DASHBOARD
function renderDashboardAlerts() {
  const container = document.getElementById("dashboard-recent-alerts-body");
  if (!container) return;
  container.innerHTML = "";
  
  const displayAlerts = STATE.alerts.slice(0, 5);
  displayAlerts.forEach(alert => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
      <td style="font-weight: 600;">${alert.title}</td>
      <td><code style="font-family: var(--font-mono); font-size: 0.8rem;">${alert.asset}</code></td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">${alert.time.slice(11, 19)}</td>
      <td><span style="font-size:0.75rem; text-transform:uppercase; font-weight:700; color:${getStatusColor(alert.status)}">${alert.status}</span></td>
    `;
    tr.addEventListener("click", () => {
      window.location.hash = `#/alerts?id=${alert.id}`;
    });
    container.appendChild(tr);
  });

  const actorContainer = document.getElementById("dashboard-actor-list");
  if (actorContainer) {
    actorContainer.innerHTML = "";
    STATE.actors.forEach(actor => {
      const li = document.createElement("li");
      li.className = "actor-item";
      li.innerHTML = `
        <div class="actor-info-left">
          <span class="actor-name">${actor.name}</span>
          <span class="actor-campaign">${actor.campaigns}</span>
        </div>
        <span class="badge badge-${actor.level.toLowerCase()}">${actor.level.toUpperCase()}</span>
      `;
      actorContainer.appendChild(li);
    });
  }
}

function getStatusColor(status) {
  switch (status) {
    case "new": return "var(--color-info)";
    case "investigating": return "var(--color-medium)";
    case "escalated": return "var(--color-critical)";
    case "fp": return "var(--text-muted)";
    default: return "#fff";
  }
}

// 6. ALERTS PAGE ROUTINES
async function renderAlertsQueueTable() {
  const container = document.getElementById("alerts-queue-body");
  if (!container) return;
  container.innerHTML = "";

  // Read query params setup
  const selectedSeverities = Array.from(document.querySelectorAll(".filter-severity:checked")).map(el => el.value);
  const tiOnly = document.getElementById("filter-ti-match").checked;

  let queryStr = "?";
  selectedSeverities.forEach(s => queryStr += `severity=${s}&`);
  if (tiOnly) queryStr += "tiMatched=true&";

  // Reload alerts from backend API with parameters
  const alertsList = await fetchAlertsFromApi(queryStr);

  if (alertsList.length === 0) {
    container.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 40px;">No alerts match the active queue filter scope.</td></tr>`;
    return;
  }

  alertsList.forEach(alert => {
    const tr = document.createElement("tr");
    if (alert.id === STATE.selectedAlertId) {
      tr.className = "selected-row";
    }
    tr.innerHTML = `
      <td><input type="checkbox" class="alert-checkbox" data-id="${alert.id}"></td>
      <td><span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
      <td>
        <div style="font-weight: 600;">${alert.title}</div>
        <div class="text-xs text-muted">${alert.system} · ID: ${alert.eventId}</div>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary);">${alert.time.slice(11, 19)} <span class="text-muted">(${alert.time.slice(0, 10)})</span></td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem;">${alert.source} → ${alert.dest.length > 20 ? alert.dest.slice(0,18)+'...' : alert.dest}</td>
      <td><code style="font-family: var(--font-mono); font-size: 0.8rem; background-color: var(--bg-app); padding: 3px 6px; border-radius: 4px; border: 1px solid var(--border-color);">${alert.asset}</code></td>
    `;
    tr.addEventListener("click", (e) => {
      if (e.target.type === "checkbox") return;
      STATE.selectedAlertId = alert.id;
      document.querySelectorAll("#alerts-table tr").forEach(r => r.classList.remove("selected-row"));
      tr.classList.add("selected-row");
      openAlertDetailDrawer(alert);
    });
    container.appendChild(tr);
  });

  const params = new URLSearchParams(window.location.hash.split("?")[1]);
  const queryId = params.get("id");
  if (queryId && STATE.selectedAlertId !== queryId) {
    const matched = STATE.alerts.find(a => a.id === queryId);
    if (matched) {
      STATE.selectedAlertId = queryId;
      openAlertDetailDrawer(matched);
      window.history.replaceState(null, null, "#/alerts");
      setTimeout(() => {
        const rows = document.querySelectorAll("#alerts-queue-body tr");
        rows.forEach((r, idx) => {
          if (alertsList[idx] && alertsList[idx].id === queryId) r.classList.add("selected-row");
        });
      }, 100);
    }
  }
}

function openAlertDetailDrawer(alert) {
  document.getElementById("drawer-empty-view").classList.add("hidden");
  const detailView = document.getElementById("drawer-detail-view");
  detailView.classList.remove("hidden");

  document.getElementById("detail-id").innerText = alert.id;
  document.getElementById("detail-title").innerText = alert.title;
  document.getElementById("detail-description").innerText = alert.description;
  
  const sevBadge = document.getElementById("detail-severity-badge");
  sevBadge.className = `badge badge-${alert.severity}`;
  sevBadge.innerText = alert.severity.toUpperCase();

  const segments = detailView.querySelectorAll(".btn-segment");
  segments.forEach(btn => {
    btn.classList.remove("active");
    if (btn.getAttribute("data-status") === alert.status) {
      btn.classList.add("active");
    }
  });

  document.getElementById("detail-threat-actor").innerText = alert.threatIntel.actor;
  document.getElementById("detail-ti-confidence").innerText = alert.threatIntel.confidence;
  document.getElementById("detail-malware-family").innerText = alert.threatIntel.malware;
  const tiConfidenceEl = document.getElementById("detail-ti-confidence");
  if (alert.severity === "critical") {
    tiConfidenceEl.className = "ti-value text-critical";
  } else {
    tiConfidenceEl.className = "ti-value text-high";
  }

  const tagsContainer = document.getElementById("detail-mitre-tags");
  tagsContainer.innerHTML = "";
  alert.mitre.forEach(m => {
    const span = document.createElement("span");
    span.className = "tag-mitre";
    span.innerText = m;
    tagsContainer.appendChild(span);
  });

  const entitiesContainer = document.getElementById("detail-entities-list");
  entitiesContainer.innerHTML = "";
  alert.entities.forEach(ent => {
    const row = document.createElement("div");
    row.className = "entity-row";
    let iconName = "cpu";
    if (ent.class === "host") iconName = "server";
    else if (ent.class === "ip") iconName = "globe";
    else if (ent.class === "user") iconName = "user-check";
    else if (ent.class === "file") iconName = "file-warning";
    else if (ent.class === "process") iconName = "terminal";
    
    row.innerHTML = `
      <i data-lucide="${iconName}"></i>
      <div class="entity-info">
        <span class="entity-val">${ent.val}</span>
        <span class="entity-class">${ent.class.toUpperCase()} · ${ent.role}</span>
      </div>
    `;
    entitiesContainer.appendChild(row);
  });

  renderAlertTimeline(alert);
  lucide.createIcons();
}

function renderAlertTimeline(alert) {
  const timelineContainer = document.getElementById("detail-timeline");
  timelineContainer.innerHTML = "";
  alert.timeline.forEach((evt, idx) => {
    const div = document.createElement("div");
    div.className = "timeline-event";
    const isLast = idx === alert.timeline.length - 1;
    div.innerHTML = `
      <span class="timeline-marker ${isLast ? 'active' : ''} ${alert.severity === 'critical' && isLast ? 'critical' : ''}"></span>
      <div class="timeline-meta">
        <span class="timeline-title">${evt.title}</span>
        <span class="timeline-time">${evt.time}</span>
      </div>
      <div class="timeline-details">${evt.details}</div>
    `;
    timelineContainer.appendChild(div);
  });
}

// 7. ENTITY GRAPH Explorer
const EntityGraphEngine = {
  zoom: 1,
  panX: 0,
  panY: 0,
  isDragging: false,
  draggedNode: null,
  dragStartX: 0,
  dragStartY: 0,

  nodes: [
    { id: "dc01", label: "DC-01.rebel.ops", class: "host", x: 400, y: 250, ti: true },
    { id: "ip_src", label: "10.0.4.15", class: "ip", x: 250, y: 180 },
    { id: "ip_mal", label: "185.220.101.5", class: "ip", x: 550, y: 200, ti: true },
    { id: "user_sys", label: "SYSTEM", class: "user", x: 300, y: 320 },
    { id: "proc_lsass", label: "lsass.exe", class: "process", x: 480, y: 350 },
    
    { id: "ws_legal", label: "WS-LEGAL-04", class: "host", x: 220, y: 400 },
    { id: "file_zip", label: "Legal_Arch.zip", class: "file", x: 100, y: 480 },
    { id: "proc_lb", label: "lb3.exe", class: "process", x: 200, y: 520, ti: true },
    { id: "user_jdoe", label: "j.doe-legal", class: "user", x: 350, y: 480 },

    { id: "domain_ad", label: "REBEL.OPS AD", class: "domain", x: 650, y: 350 },
    { id: "alert_cs", label: "SOC-2026-0001", class: "alert", x: 500, y: 100, ti: true },
    { id: "alert_lb", label: "SOC-2026-0002", class: "alert", x: 120, y: 320, ti: true },
    
    { id: "aws_prod", label: "AWS-Production", class: "domain", x: 700, y: 500 },
    { id: "user_dev", label: "dev_user_ops", class: "user", x: 550, y: 520 }
  ],

  edges: [
    { source: "ip_src", target: "dc01", label: "Assigned To" },
    { source: "dc01", target: "ip_mal", label: "Exfil Traffic" },
    { source: "dc01", target: "user_sys", label: "Local Admin" },
    { source: "user_sys", target: "proc_lsass", label: "Spawned By" },
    { source: "proc_lsass", target: "domain_ad", label: "Domain Process" },
    
    { source: "ws_legal", target: "user_jdoe", label: "User Session" },
    { source: "user_jdoe", target: "file_zip", label: "Modified" },
    { source: "proc_lb", target: "file_zip", label: "Encrypted" },
    { source: "ws_legal", target: "proc_lb", label: "Executed" },

    { source: "dc01", target: "alert_cs", label: "Raised" },
    { source: "ws_legal", target: "alert_lb", label: "Raised" },
    { source: "ip_mal", target: "alert_cs", label: "IOC Correlation" },
    { source: "proc_lb", target: "alert_lb", label: "IOC Correlation" },

    { source: "aws_prod", target: "user_dev", label: "Assumed Role" },
    { source: "user_dev", target: "domain_ad", label: "Trust Access" }
  ],

  activePath: null,

  initGraph() {
    this.populateDropdowns();
    this.renderGraph();
    this.setupListeners();
    this.updateStats();
  },

  populateDropdowns() {
    const startSelect = document.getElementById("graph-path-start");
    const endSelect = document.getElementById("graph-path-end");
    if (!startSelect || !endSelect) return;

    startSelect.innerHTML = `<option value="">-- Choose Source Node --</option>`;
    endSelect.innerHTML = `<option value="">-- Choose Target Node --</option>`;

    const sorted = [...this.nodes].sort((a,b) => a.label.localeCompare(b.label));
    sorted.forEach(node => {
      const opt = `<option value="${node.id}">${node.label} (${node.class.toUpperCase()})</option>`;
      startSelect.innerHTML += opt;
      endSelect.innerHTML += opt;
    });

    if (STATE.selectedAlertId) {
      const activeAlert = STATE.alerts.find(a => a.id === STATE.selectedAlertId);
      if (activeAlert) {
        const alertNode = this.nodes.find(n => n.label === activeAlert.id);
        const targetNode = this.nodes.find(n => n.label === activeAlert.asset.split(".")[0]);
        if (alertNode) startSelect.value = alertNode.id;
        if (targetNode) endSelect.value = targetNode.id;
        
        if (alertNode && targetNode) {
          setTimeout(() => this.findPath(alertNode.id, targetNode.id), 300);
        }
      }
    }
  },

  updateStats() {
    const activeClasses = Array.from(document.querySelectorAll(".graph-node-filter:checked")).map(el => el.value);
    const visibleNodes = this.nodes.filter(n => activeClasses.includes(n.class));
    const visibleNodeIds = visibleNodes.map(n => n.id);
    const visibleEdges = this.edges.filter(e => visibleNodeIds.includes(e.source) && visibleNodeIds.includes(e.target));

    document.getElementById("graph-stat-nodes").innerText = visibleNodes.length;
    document.getElementById("graph-stat-edges").innerText = visibleEdges.length;

    const tiCount = visibleNodes.filter(n => n.ti).length;
    document.getElementById("graph-stat-ti").innerText = `${tiCount} Matches`;
  },

  renderGraph() {
    const svg = document.getElementById("entity-graph-svg");
    const edgesGroup = document.getElementById("svg-edges");
    const nodesGroup = document.getElementById("svg-nodes");
    if (!svg || !edgesGroup || !nodesGroup) return;

    edgesGroup.innerHTML = "";
    nodesGroup.innerHTML = "";

    const activeClasses = Array.from(document.querySelectorAll(".graph-node-filter:checked")).map(el => el.value);
    const visibleNodes = this.nodes.filter(n => activeClasses.includes(n.class));
    const visibleNodeIds = visibleNodes.map(n => n.id);
    const visibleEdges = this.edges.filter(e => visibleNodeIds.includes(e.source) && visibleNodeIds.includes(e.target));

    visibleEdges.forEach(edge => {
      const sourceNode = this.nodes.find(n => n.id === edge.source);
      const targetNode = this.nodes.find(n => n.id === edge.target);
      if (!sourceNode || !targetNode) return;

      const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
      const dx = targetNode.x - sourceNode.x;
      const dy = targetNode.y - sourceNode.y;
      
      let pathString = `M ${sourceNode.x} ${sourceNode.y} Q ${(sourceNode.x + targetNode.x)/2 + (dy*0.1)} ${(sourceNode.y + targetNode.y)/2 - (dx*0.1)} ${targetNode.x} ${targetNode.y}`;
      if (edge.label === "Raised" || edge.label === "Exfil Traffic") {
        pathString = `M ${sourceNode.x} ${sourceNode.y} L ${targetNode.x} ${targetNode.y}`;
      }

      line.setAttribute("d", pathString);
      line.setAttribute("class", "edge-line");
      
      let isEdgeHighlighted = false;
      if (this.activePath) {
        for (let i = 0; i < this.activePath.length - 1; i++) {
          if ((this.activePath[i] === edge.source && this.activePath[i+1] === edge.target) ||
              (this.activePath[i] === edge.target && this.activePath[i+1] === edge.source)) {
            isEdgeHighlighted = true;
          }
        }
      }

      if (isEdgeHighlighted) {
        line.setAttribute("class", "edge-line path-highlight");
        line.setAttribute("marker-end", "url(#arrow-highlight)");
      } else {
        line.setAttribute("marker-end", "url(#arrow)");
      }

      edgesGroup.appendChild(line);

      const midX = (sourceNode.x + targetNode.x) / 2;
      const midY = (sourceNode.y + targetNode.y) / 2;
      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", midX);
      text.setAttribute("y", midY - 6);
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("class", "edge-label");
      text.textContent = edge.label;
      edgesGroup.appendChild(text);
    });

    visibleNodes.forEach(node => {
      const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
      group.setAttribute("class", "node-group");
      group.setAttribute("style", "cursor: grab;");
      group.setAttribute("data-id", node.id);

      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", node.x);
      circle.setAttribute("cy", node.y);
      circle.setAttribute("r", node.class === "alert" ? "20" : "16");
      
      let color = "#3498db";
      if (node.class === "host") color = "#00d2ff";
      else if (node.class === "ip") color = "#3498db";
      else if (node.class === "user") color = "#10ac84";
      else if (node.class === "domain") color = "#f1c40f";
      else if (node.class === "file") color = "#ff9f43";
      else if (node.class === "process") color = "#ff4c4c";
      else if (node.class === "alert") color = "#9b59b6";

      circle.setAttribute("fill", "#101520");
      circle.setAttribute("stroke", color);
      circle.setAttribute("stroke-width", "2");

      let isNodeHighlighted = false;
      if (this.activePath && this.activePath.includes(node.id)) {
        isNodeHighlighted = true;
      }

      if (isNodeHighlighted) {
        circle.setAttribute("class", "node-circle path-highlight");
      } else {
        circle.setAttribute("class", "node-circle");
      }

      if (node.ti) {
        circle.setAttribute("stroke-dasharray", "3,3");
      }

      group.appendChild(circle);

      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", node.x);
      text.setAttribute("y", node.y + (node.class === "alert" ? 34 : 30));
      text.setAttribute("text-anchor", "middle");
      text.setAttribute("class", "node-label");
      text.textContent = node.label;
      group.appendChild(text);

      nodesGroup.appendChild(group);
    });

    const zoomGroup = document.getElementById("svg-zoom-group");
    if (zoomGroup) {
      zoomGroup.setAttribute("transform", `translate(${this.panX}, ${this.panY}) scale(${this.zoom})`);
    }
  },

  setupListeners() {
    const svg = document.getElementById("entity-graph-svg");
    if (!svg) return;

    svg.addEventListener("mousedown", (e) => {
      const nodeEl = e.target.closest(".node-group");
      if (nodeEl) {
        const id = nodeEl.getAttribute("data-id");
        this.draggedNode = this.nodes.find(n => n.id === id);
        this.isDragging = true;
        
        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const svgPt = pt.matrixTransform(svg.getScreenCTM().inverse());
        
        this.dragStartX = svgPt.x - this.draggedNode.x;
        this.dragStartY = svgPt.y - this.draggedNode.y;
        
        nodeEl.setAttribute("style", "cursor: grabbing;");
      } else {
        this.isDragging = false;
        this.draggedNode = null;
        this.panActive = true;
        this.panStartX = e.clientX - this.panX;
        this.panStartY = e.clientY - this.panY;
      }
    });

    svg.addEventListener("mousemove", (e) => {
      if (this.isDragging && this.draggedNode) {
        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const svgPt = pt.matrixTransform(svg.getScreenCTM().inverse());

        this.draggedNode.x = svgPt.x - this.dragStartX;
        this.draggedNode.y = svgPt.y - this.dragStartY;
        this.renderGraph();
      } else if (this.panActive) {
        this.panX = e.clientX - this.panStartX;
        this.panY = e.clientY - this.panY;
        this.renderGraph();
      }
    });

    const stopDrag = () => {
      this.isDragging = false;
      this.draggedNode = null;
      this.panActive = false;
      document.querySelectorAll(".node-group").forEach(el => el.setAttribute("style", "cursor: grab;"));
    };

    svg.addEventListener("mouseup", stopDrag);
    svg.addEventListener("mouseleave", stopDrag);

    document.getElementById("graph-zoom-in").onclick = () => { this.zoom *= 1.2; this.renderGraph(); };
    document.getElementById("graph-zoom-out").onclick = () => { this.zoom /= 1.2; this.renderGraph(); };
    document.getElementById("graph-reset").onclick = () => { this.zoom = 1; this.panX = 0; this.panY = 0; this.renderGraph(); };

    document.querySelectorAll(".graph-node-filter").forEach(el => {
      el.addEventListener("change", () => {
        this.renderGraph();
        this.updateStats();
      });
    });

    svg.addEventListener("click", (e) => {
      const nodeEl = e.target.closest(".node-group");
      if (nodeEl) {
        const id = nodeEl.getAttribute("data-id");
        const node = this.nodes.find(n => n.id === id);
        if (node) {
          const relations = this.edges
            .filter(ed => ed.source === node.id || ed.target === node.id)
            .map(ed => {
              const other = ed.source === node.id ? this.nodes.find(n => n.id === ed.target) : this.nodes.find(n => n.id === ed.source);
              return `${ed.label} → ${other.label}`;
            }).join(", ");
          
          document.getElementById("graph-hud-text").innerHTML = `
            <strong>Selected Entity:</strong> ${node.label} (${node.class.toUpperCase()})<br>
            <strong>Relations:</strong> ${relations || 'None'}<br>
            ${node.ti ? '<span class="text-critical">Matches Threat Intel indicators!</span>' : ''}
          `;
        }
      }
    });

    document.getElementById("btn-find-path").onclick = () => {
      const start = document.getElementById("graph-path-start").value;
      const end = document.getElementById("graph-path-end").value;
      if (start && end) {
        this.findPath(start, end);
      }
    };

    document.getElementById("btn-clear-path").onclick = () => {
      this.activePath = null;
      document.getElementById("btn-clear-path").classList.add("hidden");
      this.renderGraph();
    };
  },

  findPath(startId, endId) {
    const queue = [[startId]];
    const visited = new Set([startId]);
    let pathFound = null;

    while (queue.length > 0) {
      const currentPath = queue.shift();
      const node = currentPath[currentPath.length - 1];

      if (node === endId) {
        pathFound = currentPath;
        break;
      }

      const neighbors = [];
      this.edges.forEach(edge => {
        if (edge.source === node && !visited.has(edge.target)) {
          neighbors.push(edge.target);
        } else if (edge.target === node && !visited.has(edge.source)) {
          neighbors.push(edge.source);
        }
      });

      neighbors.forEach(n => {
        visited.add(n);
        queue.push([...currentPath, n]);
      });
    }

    if (pathFound) {
      this.activePath = pathFound;
      document.getElementById("btn-clear-path").classList.remove("hidden");
      
      const pathLabels = pathFound.map(id => this.nodes.find(n => n.id === id).label).join(" → ");
      document.getElementById("graph-hud-text").innerHTML = `
        <span class="text-success"><strong>Attack Path Mapped:</strong></span><br>
        <span style="font-size:0.7rem; font-family:var(--font-mono);">${pathLabels}</span>
      `;
      this.renderGraph();
    } else {
      document.getElementById("graph-hud-text").innerHTML = `
        <span class="text-critical"><strong>Path Finder Alert:</strong></span> No connected path found between selected entities.
      `;
    }
  }
};

// 8. MITRE ATT&CK HEATMAP ROUTINES
const MITRE_FRAMEWORK = {
  tactics: [
    { id: "TA0043", name: "Reconnaissance", techniques: [{ id: "T1595", name: "Active Scanning", count: 8 }, { id: "T1589", name: "Gather Victim Identity", count: 3 }] },
    { id: "TA0042", name: "Resource Dev", techniques: [{ id: "T1583", name: "Acquire Infrastructure", count: 2 }] },
    { id: "TA0001", name: "Initial Access", techniques: [{ id: "T1566.001", name: "Spearphishing Email Attachment", count: 18 }, { id: "T1133", name: "External Remote Services", count: 5 }] },
    { id: "TA0002", name: "Execution", techniques: [{ id: "T1059.001", name: "PowerShell", count: 23 }, { id: "T1204.002", name: "User Execution File", count: 12 }, { id: "T1059.003", name: "Command Line", count: 7 }] },
    { id: "TA0003", name: "Persistence", techniques: [{ id: "T1543.003", name: "Windows Service creation", count: 4 }, { id: "T1078.004", name: "Cloud Account credentials", count: 2 }] },
    { id: "TA0004", name: "Privilege Escalation", techniques: [{ id: "T1078.002", name: "Domain Accounts", count: 8 }, { id: "T1547.001", name: "Registry Run Keys", count: 4 }] },
    { id: "TA0005", name: "Defense Evasion", techniques: [{ id: "T1562.001", name: "Disable Security Tools", count: 14 }, { id: "T1140", name: "Deobfuscate Files/Info", count: 10 }, { id: "T1070", name: "Clear Indicator Logs", count: 3 }] },
    { id: "TA0006", name: "Credential Access", techniques: [{ id: "T1003.001", name: "LSASS Memory Dump", count: 21 }, { id: "T1110.003", name: "Password Spraying", count: 16 }] },
    { id: "TA0007", name: "Discovery", techniques: [{ id: "T1018", name: "Remote System Discovery", count: 4 }, { id: "T1082", name: "System Information Discovery", count: 3 }] },
    { id: "TA0008", name: "Lateral Movement", techniques: [{ id: "T1021.002", name: "SMB/Windows Admin Shares", count: 11 }, { id: "T1072", name: "Software Deployment", count: 2 }] },
    { id: "TA0009", name: "Collection", techniques: [{ id: "T1114", name: "Email Collection", count: 6 }, { id: "T1005", name: "Local Data Collection", count: 4 }] },
    { id: "TA0010", name: "Exfiltration", techniques: [{ id: "T1048.002", name: "Exfiltration Over SFTP Protocol", count: 15 }, { id: "T1041", name: "Exfiltration Over C2 Channel", count: 12 }] },
    { id: "TA0011", name: "Command and Control", techniques: [{ id: "T1071.004", name: "DNS C2 Beacons", count: 19 }, { id: "T1090.003", name: "Multi-hop Proxy", count: 6 }] },
    { id: "TA0040", name: "Impact", techniques: [{ id: "T1486", name: "Data Encrypted for Impact", count: 15 }, { id: "T1489", name: "Service Stop", count: 2 }] }
  ]
};

function renderMitreMatrix() {
  const container = document.getElementById("mitre-matrix-table-container");
  if (!container) return;
  container.innerHTML = "";

  MITRE_FRAMEWORK.tactics.forEach(tactic => {
    const col = document.createElement("div");
    col.className = "mitre-tactic-column";
    
    col.innerHTML = `
      <div class="mitre-tactic-header">
        <span class="tactic-name">${tactic.name}</span>
        <span class="tactic-code">${tactic.id}</span>
      </div>
      <div class="mitre-cells-list"></div>
    `;

    const list = col.querySelector(".mitre-cells-list");
    tactic.techniques.forEach(tech => {
      const cell = document.createElement("div");
      
      let levelClass = "level-none";
      if (tech.count >= 16) levelClass = "level-high";
      else if (tech.count >= 6) levelClass = "level-med";
      else if (tech.count >= 1) levelClass = "level-low";

      cell.className = `mitre-technique-cell ${levelClass}`;
      cell.innerHTML = `
        <span class="tech-name">${tech.name}</span>
        <div class="tech-footer">
          <span class="tech-id">${tech.id}</span>
          <span class="tech-badge">${tech.count}</span>
        </div>
      `;

      cell.addEventListener("click", () => {
        const matched = STATE.alerts.find(a => a.mitre.includes(tech.id) || a.mitre.some(m => m.startsWith(tech.id.split(".")[0])));
        if (matched) {
          window.location.hash = `#/alerts?id=${matched.id}`;
        } else {
          window.location.hash = `#/alerts`;
        }
      });

      list.appendChild(cell);
    });

    container.appendChild(col);
  });
}

// 9. THREAT HUNTING WORKBENCH
function initHuntingWorkbench() {
  const queryList = document.getElementById("hunting-saved-queries");
  if (!queryList) return;
  queryList.innerHTML = "";

  STATE.huntingQueries.forEach(query => {
    const li = document.createElement("li");
    li.className = "query-item";
    li.innerHTML = `
      <div class="query-title">${query.title}</div>
      <div class="query-meta">
        <span class="query-meta-item font-mono text-info">${query.version}</span>
        <span class="query-meta-item badge badge-medium">${query.tag}</span>
        <span class="query-meta-item ml-auto font-bold">${query.results} results</span>
      </div>
      <div class="query-desc">${query.desc}</div>
    `;
    li.addEventListener("click", () => {
      document.querySelectorAll(".query-item").forEach(el => el.classList.remove("active"));
      li.classList.add("active");
      
      const queryStr = getMockQueryString(query.title);
      document.getElementById("hunting-query-input").value = queryStr;
      runHuntQueryOnBackend(queryStr);
    });
    queryList.appendChild(li);
  });

  document.getElementById("btn-run-hunt").onclick = () => {
    const val = document.getElementById("hunting-query-input").value;
    runHuntQueryOnBackend(val);
  };
}

function getMockQueryString(title) {
  switch (title) {
    case "Cobalt Strike Beacon Patterns": return `process.name:"lsass.exe" AND network.destination:"185.220.101.5"`;
    case "LSASS Memory Dump Attempts": return `process.name:"rundll32.exe" AND file.path:"C:\\Temp\\lsass.dmp"`;
    case "Tor Exit Node Connections": return `network.destination:"109.163.220.129" OR network.destination:"203.0.113.88"`;
    case "Suspicious PowerShell Scripts": return `process.name:"powershell.exe" AND process.command:"*bypass*"`;
    case "Ransomware File Extensions": return `file.extension:".lockbit" OR file.entropy > 7.5`;
    case "AWS Privilege Escalation Logs": return `cloud.provider:"aws" AND event.action:"AssumeRole"`;
    default: return `severity:"critical"`;
  }
}

async function runHuntQueryOnBackend(queryStr) {
  const emptyState = document.getElementById("hunting-empty-state");
  const resultsView = document.getElementById("hunting-results-view");
  if (!emptyState || !resultsView) return;

  if (!queryStr || queryStr.trim() === "") {
    emptyState.classList.remove("hidden");
    resultsView.classList.add("hidden");
    document.getElementById("hunting-results-count").innerText = "0 Results";
    return;
  }

  emptyState.classList.add("hidden");
  resultsView.classList.remove("hidden");

  try {
    const res = await fetch("/api/hunting/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: queryStr })
    });
    if (res.ok) {
      const results = await res.json();
      document.getElementById("hunting-results-count").innerText = `${results.length} Results`;
      
      const tbody = document.getElementById("hunting-results-table-body");
      tbody.innerHTML = "";
      if (results.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No telemetry log matching query query fields found.</td></tr>`;
      } else {
        results.forEach(item => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><span class="badge badge-${item.severity}">${item.severity.toUpperCase()}</span></td>
            <td style="font-weight:600;">${item.title}</td>
            <td style="font-family: var(--font-mono); font-size:0.8rem; color:var(--text-secondary);">${item.time.slice(11, 19)}</td>
            <td><code>${item.asset}</code></td>
            <td style="font-family: var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${item.id}</td>
          `;
          tr.onclick = () => window.location.hash = `#/alerts?id=${item.id}`;
          tbody.appendChild(tr);
        });
      }
      initHuntingHistogram(results.length);
    }
  } catch (err) {
    console.error("Error executing hunt query on backend:", err);
  }
}

function initHuntingHistogram(resultsCount) {
  const canvas = document.getElementById("chart-hunting-histogram");
  if (!canvas) return;

  if (ChartsEngine.instances["hunting-histogram"]) {
    ChartsEngine.instances["hunting-histogram"].destroy();
  }

  const ctx = canvas.getContext("2d");
  const data = Array.from({length: 24}, () => resultsCount > 0 ? Math.floor(Math.random() * (resultsCount * 2)) + 1 : 0);
  const labels = Array.from({length: 24}, (_, i) => `${i}:00`);

  ChartsEngine.instances["hunting-histogram"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Detections Spike",
        data: data,
        backgroundColor: "rgba(0, 210, 255, 0.4)",
        borderColor: "#00d2ff",
        borderWidth: 1,
        borderRadius: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#64748b", font: { size: 8 } } },
        y: { grid: { color: "#162030" }, ticks: { display: false } }
      }
    }
  });
}

// 10. CAMPAIGNS DETECTION VIEW
function renderCampaignsGrid() {
  const container = document.getElementById("campaigns-cards-container");
  if (!container) return;
  container.innerHTML = "";

  STATE.campaigns.forEach(camp => {
    const card = document.createElement("div");
    card.className = `campaign-card glow-${camp.severity}`;
    
    const actorBadges = camp.actors.map(act => `<span class="actor-capsule">${act}</span>`).join("");
    const mitreBadges = camp.mitre.map(m => `<span class="tag-mitre">${m}</span>`).join("");

    card.innerHTML = `
      <div class="campaign-card-header">
        <div class="campaign-title-group">
          <h3>${camp.title}</h3>
          <div class="campaign-status-row">
            <span class="campaign-status-dot ${camp.status}"></span>
            <span class="campaign-status-text">${camp.status}</span>
          </div>
        </div>
        <span class="badge badge-${camp.severity}">${camp.severity.toUpperCase()}</span>
      </div>
      <div class="campaign-card-body">
        <p class="campaign-desc">${camp.desc}</p>
        <div class="campaign-stats-mini">
          <div class="campaign-stat-box">
            <span class="lbl">Alerts</span>
            <span class="val text-critical">${camp.alerts}</span>
          </div>
          <div class="campaign-stat-box">
            <span class="lbl">IOCs</span>
            <span class="val text-high">${camp.iocs}</span>
          </div>
          <div class="campaign-stat-box">
            <span class="lbl">Assets</span>
            <span class="val text-info">${camp.assets}</span>
          </div>
        </div>
        <div class="campaign-vectors">
          <h4>Correlated Threat Actors:</h4>
          <div class="actor-capsules">${actorBadges}</div>
        </div>
        <div class="campaign-vectors">
          <h4>Mitre ATT&CK Map:</h4>
          <div class="ti-tags">${mitreBadges}</div>
        </div>

        <div class="campaign-details-expander hidden" id="campaign-exp-${camp.id}">
          <div class="timeline mt-3" style="padding-left:14px; border-left:1px solid var(--border-color)">
            ${camp.timeline.map(e => `
              <div class="timeline-event" style="padding-bottom:10px;">
                <div class="timeline-meta">
                  <span class="timeline-title" style="font-size:0.75rem;">${e.details}</span>
                  <span class="timeline-time" style="font-size:0.65rem;">${e.date}</span>
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>
      <div class="campaign-card-footer">
        <button class="btn-card-expand" data-id="${camp.id}">
          <span>View Chronology Timeline</span>
          <i data-lucide="chevron-down" style="width:14px; height:14px;"></i>
        </button>
      </div>
    `;

    const expandBtn = card.querySelector(".btn-card-expand");
    expandBtn.addEventListener("click", () => {
      const details = card.querySelector(`#campaign-exp-${camp.id}`);
      const isHidden = details.classList.contains("hidden");
      if (isHidden) {
        details.classList.remove("hidden");
        expandBtn.querySelector("span").innerText = "Collapse Timeline View";
        expandBtn.querySelector("i").setAttribute("data-lucide", "chevron-up");
      } else {
        details.classList.add("hidden");
        expandBtn.querySelector("span").innerText = "View Chronology Timeline";
        expandBtn.querySelector("i").setAttribute("data-lucide", "chevron-down");
      }
      lucide.createIcons();
    });

    container.appendChild(card);
  });
  
  lucide.createIcons();
}

// 11. COMPLIANCE & EXECUTIVE REPORT BUILDER
function renderComplianceChecklist() {
  const container = document.getElementById("compliance-checklist-body");
  if (!container) return;
  container.innerHTML = "";

  STATE.compliancePCI.forEach(item => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td width="320">
        <span class="req-item-id">${item.req}</span>
        <span class="req-item-name">${item.name}</span>
      </td>
      <td>
        <span class="badge badge-${item.status}">${item.status.toUpperCase()}</span>
      </td>
      <td>
        ${item.alerts > 0 ? `<span class="text-semibold text-critical">${item.alerts} Active Alerts</span>` : '<span class="text-success">0 Incidents</span>'}
      </td>
    `;
    container.appendChild(tr);
  });
}

function renderReportBlocks() {
  const container = document.getElementById("report-blocks-draft");
  const picker = document.getElementById("report-widget-picker");
  if (!container || !picker) return;

  container.innerHTML = "";
  
  const labelsMap = {
    "summary": "Alert Summary Dashboard & SLA metrics",
    "mitre": "MITRE ATT&CK Framework coverage heatmap",
    "iocs": "Top Threat Intelligence Indicators (IOCs)",
    "mttd-mttr": "Mean Time to Detect (MTTD) & Respond (MTTR) SLA Trends",
    "actors": "Security Threat Actors & Campaign matrix",
    "risk": "Endpoint Assets Risk and Vulnerability matrix",
    "timeline": "Chronological Incident Alert Timeline",
    "feed": "AlienVault OTX Threat Intel feed integrity"
  };

  STATE.activeReportBlocks.forEach(blockId => {
    const item = document.createElement("div");
    item.className = "report-block-item";
    item.setAttribute("data-block", blockId);
    item.innerHTML = `
      <i data-lucide="grip-vertical" class="grip-icon"></i>
      <span>${labelsMap[blockId]}</span>
      <button class="btn-remove-block"><i data-lucide="trash-2" class="icon-sm"></i></button>
    `;

    item.querySelector(".btn-remove-block").onclick = () => {
      STATE.activeReportBlocks = STATE.activeReportBlocks.filter(b => b !== blockId);
      renderReportBlocks();
    };

    container.appendChild(item);
  });

  picker.querySelectorAll(".btn-widget-select").forEach(btn => {
    const type = btn.getAttribute("data-widget");
    if (STATE.activeReportBlocks.includes(type)) {
      btn.classList.add("added");
    } else {
      btn.classList.remove("added");
    }
  });

  lucide.createIcons();
}

function setupComplianceActions() {
  const picker = document.getElementById("report-widget-picker");
  if (!picker) return;

  picker.querySelectorAll(".btn-widget-select").forEach(btn => {
    btn.onclick = () => {
      const type = btn.getAttribute("data-widget");
      if (STATE.activeReportBlocks.includes(type)) {
        STATE.activeReportBlocks = STATE.activeReportBlocks.filter(b => b !== type);
      } else {
        STATE.activeReportBlocks.push(type);
      }
      renderReportBlocks();
    };
  });

  document.getElementById("btn-export-pdf").onclick = () => simulateReportGeneration("Executive SOC Performance Report.pdf");
  document.getElementById("btn-export-html").onclick = () => simulateReportGeneration("Executive_SOC_Dashboard.html");

  const schedContainer = document.getElementById("compliance-scheduled-list");
  if (schedContainer) {
    schedContainer.innerHTML = "";
    STATE.scheduledReports.forEach(sched => {
      const div = document.createElement("div");
      div.className = "sched-report-item";
      div.innerHTML = `
        <div class="sched-report-info">
          <span class="sched-report-title">${sched.title}</span>
          <span class="sched-report-timing">${sched.timing}</span>
        </div>
        <span class="badge badge-success">ACTIVE</span>
      `;
      schedContainer.appendChild(div);
    });
  }
}

function simulateReportGeneration(filename) {
  const spinner = document.getElementById("modal-spinner-overlay");
  const title = document.getElementById("modal-spinner-title");
  if (!spinner) return;

  title.innerText = `Compiling Draft Report details...`;
  spinner.classList.remove("hidden");

  setTimeout(() => {
    title.innerText = `Finalizing ${filename} format layout...`;
    
    setTimeout(() => {
      spinner.classList.add("hidden");
      
      const blob = new Blob([`SentinelPulse Executive Report Draft\nCompiled: ${new Date().toISOString()}\nDocument Content Sections:\n${STATE.activeReportBlocks.join("\n")}`], {type: "text/plain"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }, 1000);

  }, 1200);
}

// 12. WALL MODE PRESENTATION CYCLE
let wallCarouselInterval = null;
const WALL_ROTATION_SECS = 12;

function initWallMode() {
  stopWallMode();
  document.body.style.overflow = "hidden";
  
  STATE.activeWallTab = "critical";
  STATE.wallPaused = false;
  document.getElementById("wall-play-state").innerText = "pause rotation";
  
  updateWallTabsUI();
  updateWallSlidesUI();
  initWallLiveClock();

  wallCarouselInterval = setInterval(() => {
    if (!STATE.wallPaused) {
      cycleWallTab();
    }
  }, WALL_ROTATION_SECS * 1000);
}

function cycleWallTab() {
  const tabs = ["critical", "volume", "mitre", "kpis"];
  let currIdx = tabs.indexOf(STATE.activeWallTab);
  let nextIdx = (currIdx + 1) % tabs.length;
  STATE.activeWallTab = tabs[nextIdx];
  
  updateWallTabsUI();
  updateWallSlidesUI();
}

function updateWallTabsUI() {
  document.querySelectorAll(".wall-tab").forEach(tab => {
    tab.classList.remove("active");
    if (tab.getAttribute("data-wall-tab") === STATE.activeWallTab) {
      tab.classList.add("active");
    }
  });
}

async function updateWallSlidesUI() {
  document.querySelectorAll(".wall-view-slide").forEach(slide => {
    slide.classList.remove("active-slide");
  });

  const activeSlideId = `wall-slide-${STATE.activeWallTab}`;
  const slide = document.getElementById(activeSlideId);
  if (slide) slide.classList.add("active-slide");

  if (STATE.activeWallTab === "critical") {
    await fetchAlertsFromApi();
    renderWallCriticalCards();
  } else if (STATE.activeWallTab === "volume") {
    ChartsEngine.initWallTelemetryChart();
    renderWallSeverityStats();
  } else if (STATE.activeWallTab === "mitre") {
    renderWallMitreMatrix();
  }
}

function stopWallMode() {
  if (wallCarouselInterval) {
    clearInterval(wallCarouselInterval);
    wallCarouselInterval = null;
  }
  document.body.style.overflow = "auto";
}

function initWallLiveClock() {
  if (window.wallClockInterval) clearInterval(window.wallClockInterval);
  
  const clockEl = document.getElementById("wall-live-clock");
  const updateClock = () => {
    const now = new Date();
    clockEl.innerText = now.toTimeString().split(" ")[0];
  };
  updateClock();
  window.wallClockInterval = setInterval(updateClock, 1000);
}

function renderWallCriticalCards() {
  const container = document.getElementById("wall-critical-cards");
  if (!container) return;
  container.innerHTML = "";

  const criticalAlerts = STATE.alerts.filter(a => a.severity === "critical");
  criticalAlerts.forEach(alert => {
    const card = document.createElement("div");
    card.className = "wall-card-critical";
    card.innerHTML = `
      <div class="wall-card-header">
        <span class="wall-card-id">${alert.id}</span>
        <span class="wall-card-confidence">Confidence: ${alert.threatIntel.confidence}</span>
      </div>
      <h3 class="wall-card-title">${alert.title}</h3>
      <div class="wall-card-details">
        <div class="wall-detail-item">
          <span class="lbl">Impacted Asset:</span>
          <span class="val">${alert.asset}</span>
        </div>
        <div class="wall-detail-item">
          <span class="lbl">Malware Family:</span>
          <span class="val">${alert.threatIntel.malware}</span>
        </div>
        <div class="wall-detail-item">
          <span class="lbl">Source → Dest:</span>
          <span class="val">${alert.source} → ${alert.dest.length > 15 ? alert.dest.slice(0,14)+'...' : alert.dest}</span>
        </div>
        <div class="wall-detail-item">
          <span class="lbl">System:</span>
          <span class="val">${alert.system}</span>
        </div>
      </div>
      <div class="wall-tags-flex">
        ${alert.mitre.map(m => `<span class="tag-mitre">${m}</span>`).join("")}
      </div>
    `;
    container.appendChild(card);
  });
}

function renderWallSeverityStats() {
  const container = document.getElementById("wall-severity-metrics");
  if (!container) return;
  container.innerHTML = "";

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  STATE.alerts.forEach(a => counts[a.severity] = (counts[a.severity] || 0) + 1);

  const items = [
    { label: "Critical Priority", count: counts.critical, class: "text-critical" },
    { label: "High Priority", count: counts.high, class: "text-high" },
    { label: "Medium Priority", count: counts.medium, class: "text-medium" },
    { label: "Low Priority", count: counts.low, class: "text-low" },
    { label: "Informational Detections", count: counts.info, class: "text-info" }
  ];

  items.forEach(item => {
    const row = document.createElement("div");
    row.className = "wall-metric-row";
    row.innerHTML = `
      <span class="wall-metric-label"><span class="status-dot online" style="background-color: currentColor; box-shadow:none;"></span>${item.label}</span>
      <span class="wall-metric-val ${item.class}">${item.count}</span>
    `;
    row.style.color = getSeverityColorHex(item.class);
    container.appendChild(row);
  });
}

function getSeverityColorHex(className) {
  if (className.includes("critical")) return "var(--color-critical)";
  if (className.includes("high")) return "var(--color-high)";
  if (className.includes("medium")) return "var(--color-medium)";
  if (className.includes("low")) return "var(--color-low)";
  return "var(--color-info)";
}

function renderWallMitreMatrix() {
  const container = document.getElementById("wall-mitre-coverage-container");
  const statsContainer = document.getElementById("wall-mitre-hud-stats");
  if (!container || !statsContainer) return;
  
  container.innerHTML = "";

  MITRE_FRAMEWORK.tactics.forEach(tactic => {
    const col = document.createElement("div");
    col.className = "mitre-tactic-column";
    col.innerHTML = `
      <div class="mitre-tactic-header" style="min-height:54px; padding:6px;">
        <span class="tactic-name" style="font-size:0.65rem;">${tactic.name}</span>
      </div>
      <div class="mitre-cells-list"></div>
    `;

    const list = col.querySelector(".mitre-cells-list");
    tactic.techniques.forEach(tech => {
      const cell = document.createElement("div");
      let levelClass = "level-none";
      if (tech.count >= 16) levelClass = "level-high";
      else if (tech.count >= 6) levelClass = "level-med";
      else if (tech.count >= 1) levelClass = "level-low";

      cell.className = `mitre-technique-cell ${levelClass}`;
      cell.innerHTML = `
        <span class="tech-name">${tech.name}</span>
        <div class="tech-footer">
          <span class="tech-id" style="font-size:0.55rem;">${tech.id}</span>
          <span class="tech-badge" style="font-size:0.55rem; padding: 0px 3px;">${tech.count}</span>
        </div>
      `;
      list.appendChild(cell);
    });

    container.appendChild(col);
  });

  statsContainer.innerHTML = `
    <div class="wall-hud-stat-item"><span>Tactics Mapping:</span> <span>14 Enterprise Tactics</span></div>
    <div class="wall-hud-stat-item"><span>Active Mapped Alerts:</span> <span>438 Mapped Detections</span></div>
    <div class="wall-hud-stat-item"><span>Active Health Score:</span> <span class="text-success">73% Posture Coverage</span></div>
  `;
}

function setupKeyboardShortcutListeners() {
  window.addEventListener("keydown", (e) => {
    const wallView = document.getElementById("view-wall");
    if (wallView && !wallView.classList.contains("hidden")) {
      if (e.code === "Space") {
        e.preventDefault();
        STATE.wallPaused = !STATE.wallPaused;
        
        const label = document.getElementById("wall-play-state");
        if (STATE.wallPaused) {
          label.innerText = "resume rotation";
          label.style.color = "var(--color-high)";
        } else {
          label.innerText = "pause rotation";
          label.style.color = "inherit";
        }
      }
    }
  });

  document.querySelectorAll(".wall-tab").forEach(tab => {
    tab.onclick = () => {
      STATE.activeWallTab = tab.getAttribute("data-wall-tab");
      STATE.wallPaused = true;
      
      const label = document.getElementById("wall-play-state");
      label.innerText = "resume rotation";
      label.style.color = "var(--color-high)";

      updateWallTabsUI();
      updateWallSlidesUI();
    };
  });

  document.getElementById("btn-exit-wall-mode").onclick = () => {
    window.location.hash = "#/";
  };
}

// 13. DYNAMIC POLLING INTERVAL
let alertsPollingInterval = null;
function startAlertsPolling() {
  if (alertsPollingInterval) clearInterval(alertsPollingInterval);
  alertsPollingInterval = setInterval(async () => {
    // Record current lists to compare
    const oldIds = new Set(STATE.alerts.map(a => a.id));
    
    // Fetch latest alerts
    const freshAlerts = await fetchAlertsFromApi();
    
    let isNewAlertAdded = false;
    freshAlerts.forEach(a => {
      if (!oldIds.has(a.id)) {
        isNewAlertAdded = true;
      }
    });

    if (isNewAlertAdded) {
      // Re-trigger view rendering
      const activeHash = window.location.hash || "#/";
      const routeName = activeHash.replace("#/", "").split("?")[0] || "dashboard";
      
      if (routeName === "dashboard") {
        renderDashboardAlerts();
        ChartsEngine.initDashboardCharts();
      } else if (routeName === "alerts") {
        renderAlertsQueueTable();
      } else if (routeName === "wall") {
        updateWallSlidesUI();
      }
      
      // Update counters in elements
      await fetchKpisFromApi();
    }
  }, 4000);
}

// 14. SIMULATED MODAL ACTIONS HANDLER
function setupSimulateModal() {
  const modal = document.getElementById("modal-create-alert");
  const form = document.getElementById("form-create-alert");
  const closeBtn = document.getElementById("btn-close-create-modal");
  const cancelBtn = document.getElementById("btn-cancel-create-modal");
  
  if (!modal || !form) return;

  // Open triggers
  document.querySelectorAll(".btn-trigger-simulate, #btn-trigger-simulate").forEach(btn => {
    btn.onclick = () => {
      modal.classList.remove("hidden");
    };
  });

  // Close triggers
  const hideModal = () => modal.classList.add("hidden");
  if (closeBtn) closeBtn.onclick = hideModal;
  if (cancelBtn) cancelBtn.onclick = hideModal;

  // Form submit
  form.onsubmit = async (e) => {
    e.preventDefault();
    const title = document.getElementById("sim-title").value;
    const severity = document.getElementById("sim-severity").value;
    const system = document.getElementById("sim-system").value;
    const asset = document.getElementById("sim-asset").value;
    const source = document.getElementById("sim-source").value;
    const dest = document.getElementById("sim-dest").value;
    const tiMatched = document.getElementById("sim-ti").checked;
    const description = document.getElementById("sim-desc").value;

    await simulateAlertOnBackend({
      title,
      severity,
      system,
      asset,
      source,
      dest,
      tiMatched,
      description
    });
    
    // Clear form
    form.reset();
  };
}

// 15. INITIALIZATION
document.addEventListener("DOMContentLoaded", () => {
  Router.init();
  
  const dClock = document.getElementById("dashboard-clock");
  if (dClock) {
    const updateDashboardClock = () => {
      dClock.innerText = `Last updated: ${new Date().toLocaleTimeString()}`;
    };
    updateDashboardClock();
    setInterval(updateDashboardClock, 10000);
  }

  const refreshDashBtn = document.getElementById("refresh-dashboard");
  if (refreshDashBtn) {
    refreshDashBtn.onclick = async () => {
      await fetchAlertsFromApi();
      await fetchKpisFromApi();
      renderDashboardAlerts();
      ChartsEngine.initDashboardCharts();
    };
  }

  const toggleBtn = document.getElementById("toggle-sidebar");
  const sidebar = document.querySelector(".sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.onclick = () => {
      const isCollapsed = sidebar.style.width === "0px";
      sidebar.style.width = isCollapsed ? "var(--sidebar-width)" : "0px";
      sidebar.style.overflow = isCollapsed ? "visible" : "hidden";
    };
  }

  document.querySelectorAll(".filter-severity").forEach(cb => {
    cb.addEventListener("change", () => renderAlertsQueueTable());
  });
  const tiToggle = document.getElementById("filter-ti-match");
  if (tiToggle) tiToggle.addEventListener("change", () => renderAlertsQueueTable());
  
  const selectAllAlerts = document.getElementById("select-all-alerts");
  if (selectAllAlerts) {
    selectAllAlerts.addEventListener("change", (e) => {
      document.querySelectorAll(".alert-checkbox").forEach(cb => {
        cb.checked = e.target.checked;
      });
    });
  }

  const closeDrawerBtn = document.getElementById("close-detail-drawer");
  if (closeDrawerBtn) {
    closeDrawerBtn.onclick = () => {
      document.getElementById("drawer-detail-view").classList.add("hidden");
      document.getElementById("drawer-empty-view").classList.remove("hidden");
      STATE.selectedAlertId = null;
      document.querySelectorAll("#alerts-table tr").forEach(r => r.classList.remove("selected-row"));
    };
  }

  // Segmented triage status handlers
  document.querySelectorAll(".alert-status-control .btn-segment").forEach(btn => {
    btn.onclick = async () => {
      const status = btn.getAttribute("data-status");
      if (STATE.selectedAlertId) {
        await updateAlertStatus(STATE.selectedAlertId, status);
      }
    };
  });

  const btnInvestigate = document.getElementById("btn-action-investigate");
  if (btnInvestigate) {
    btnInvestigate.onclick = () => {
      if (STATE.selectedAlertId) {
        window.location.hash = "#/graph";
      }
    };
  }

  const btnEscalate = document.getElementById("btn-action-escalate");
  if (btnEscalate) {
    btnEscalate.onclick = async () => {
      if (STATE.selectedAlertId) {
        await updateAlertStatus(STATE.selectedAlertId, "escalated");
      }
    };
  }

  const btnFp = document.getElementById("btn-action-fp");
  if (btnFp) {
    btnFp.onclick = async () => {
      if (STATE.selectedAlertId) {
        await updateAlertStatus(STATE.selectedAlertId, "fp");
      }
    };
  }

  setupComplianceActions();
  setupSimulateModal();
  setupKeyboardShortcutListeners();
});
