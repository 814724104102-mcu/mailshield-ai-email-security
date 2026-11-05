/* ==========================================================================
   MailShield AI - Client Operations & Visualizations
   ========================================================================== */

let threatGauge = null;

document.addEventListener("DOMContentLoaded", function () {
  initThreatGauge();
  setupDropzone();
  loadStats();
  // Generate initial crypto keys so Crypto Studio is immediately testable
  generateKeypair();
});

// Initialize Chart.js Gauge
function initThreatGauge() {
  const ctx = document.getElementById("threatGaugeChart").getContext("2d");
  threatGauge = new Chart(ctx, {
    type: "doughnut",
    data: {
      datasets: [{
        data: [0, 100],
        backgroundColor: ["#10b981", "#1e293b"],
        borderWidth: 0,
        circumference: 240,
        rotation: 240,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: "75%",
      plugins: {
        tooltip: { enabled: false }
      }
    }
  });
}

function updateThreatGauge(score) {
  let color = "#10b981"; // Safe
  if (score >= 70) {
    color = "#f43f5e"; // Malicious
  } else if (score >= 35) {
    color = "#f59e0b"; // Warning
  }

  threatGauge.data.datasets[0].data = [score, 100 - score];
  threatGauge.data.datasets[0].backgroundColor = [color, "#1e293b"];
  threatGauge.update();

  const scoreEl = document.getElementById("res-threat-score");
  scoreEl.textContent = Math.round(score);
  scoreEl.style.color = color;
}

// 1-Click Scenario Loader
async function loadSampleScenario(id) {
  try {
    const res = await fetch(`/api/samples/${id}`);
    if (!res.ok) throw new Error("Failed to load sample");
    const data = await res.json();

    document.getElementById("input-sender").value = data.sender || "";
    document.getElementById("input-reply-to").value = data.reply_to || "";
    document.getElementById("input-subject").value = data.subject || "";
    document.getElementById("input-body").value = data.body || "";
    document.getElementById("input-attachments").value = data.attachments || "";

    if (data.auth_results) {
      const authSel = document.getElementById("input-auth");
      if (data.auth_results.includes("spf=fail")) {
        authSel.value = "spf=fail dkim=fail dmarc=fail";
      } else if (data.auth_results.includes("spf=neutral")) {
        authSel.value = "spf=neutral dkim=none dmarc=none";
      } else {
        authSel.value = "spf=pass dkim=pass dmarc=pass";
      }
    }

    // Auto-trigger scan
    document.getElementById("btn-scan").click();
  } catch (err) {
    console.error("Error loading sample:", err);
  }
}

// Setup EML Drag and Drop
function setupDropzone() {
  const dropzone = document.getElementById("eml-dropzone");
  const fileInput = document.getElementById("eml-file-input");

  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      handleEmlUpload({ target: fileInput });
    }
  });
}

// Handle .EML File Upload
async function handleEmlUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("eml_file", file);

  const btn = document.getElementById("btn-scan");
  const originalHtml = btn.innerHTML;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Inspecting ${file.name}...`;
  btn.disabled = true;

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      body: formData
    });
    const result = await res.json();

    // Populate inputs from result meta
    if (result.meta) {
      document.getElementById("input-sender").value = result.meta.sender || "";
      document.getElementById("input-subject").value = result.meta.subject || "";
      document.getElementById("input-reply-to").value = result.meta.reply_to || "";
    }

    renderScanResults(result);
    loadStats();
  } catch (err) {
    alert("Error inspecting EML file: " + err.message);
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

// Handle Form Scan Submit
async function handleScanSubmit(event) {
  event.preventDefault();

  const payload = {
    sender: document.getElementById("input-sender").value,
    reply_to: document.getElementById("input-reply-to").value,
    auth_results: document.getElementById("input-auth").value,
    subject: document.getElementById("input-subject").value,
    body: document.getElementById("input-body").value,
    attachments: document.getElementById("input-attachments").value
  };

  const btn = document.getElementById("btn-scan");
  const originalHtml = btn.innerHTML;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Analyzing multi-vectors...`;
  btn.disabled = true;

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    renderScanResults(result);
    loadStats();
  } catch (err) {
    alert("Error performing scan: " + err.message);
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

// Render Results into UI
function renderScanResults(data) {
  document.getElementById("scan-placeholder").style.display = "none";
  document.getElementById("scan-results").style.display = "block";

  // 1. Update Gauge & Verdict Banner
  updateThreatGauge(data.threat_score);

  const verdictBadge = document.getElementById("res-verdict-badge");
  verdictBadge.className = `badge-verdict verdict-${data.verdict}`;
  verdictBadge.innerHTML = `<i class="fa-solid fa-${data.verdict === 'QUARANTINE' ? 'ban' : (data.verdict === 'WARN' ? 'triangle-exclamation' : 'check-circle')}"></i> ${data.verdict}`;

  document.getElementById("res-action-desc").textContent = data.action_desc;
  document.getElementById("res-meta-summary").textContent = `Subject: "${data.meta.subject || 'N/A'}" | From: ${data.meta.sender || 'Unknown'}`;

  // Critical Alerts
  const critContainer = document.getElementById("res-critical-alerts-container");
  const critList = document.getElementById("res-critical-alerts-list");
  critList.innerHTML = "";
  if (data.critical_flags && data.critical_flags.length > 0) {
    critContainer.style.display = "block";
    data.critical_flags.forEach(flag => {
      const li = document.createElement("li");
      li.textContent = flag;
      critList.appendChild(li);
    });
  } else {
    critContainer.style.display = "none";
  }

  // 2. Vector 1: ML Phishing & Urgency
  const ml = data.components.ml_analysis;
  document.getElementById("res-ml-confidence").textContent = `${ml.confidence_score}% Phishing`;
  document.getElementById("res-ml-prob-val").textContent = `${ml.confidence_score}%`;
  document.getElementById("res-ml-bar").style.width = `${ml.confidence_score}%`;

  document.getElementById("res-urgency-val").textContent = `${ml.urgency_score}%`;
  document.getElementById("res-urgency-bar").style.width = `${ml.urgency_score}%`;

  const xaiContainer = document.getElementById("res-xai-tokens");
  xaiContainer.innerHTML = "";
  if (ml.top_risk_features && ml.top_risk_features.length > 0) {
    ml.top_risk_features.forEach(feat => {
      const badge = document.createElement("span");
      badge.className = "xai-badge";
      badge.textContent = `${feat.word} (+${feat.weight})`;
      xaiContainer.appendChild(badge);
    });
  } else if (ml.urgency_triggers && ml.urgency_triggers.length > 0) {
    ml.urgency_triggers.forEach(trig => {
      const badge = document.createElement("span");
      badge.className = "xai-badge";
      badge.textContent = trig;
      xaiContainer.appendChild(badge);
    });
  } else {
    xaiContainer.innerHTML = '<span class="text-muted italic">No high-risk keywords detected</span>';
  }

  // 3. Vector 2: Header & Authentication
  const hdr = data.components.header_analysis;
  document.getElementById("res-header-score").textContent = `Risk: ${hdr.spoof_score}/100`;
  document.getElementById("res-sender-domain").textContent = hdr.sender_domain || "N/A";

  const setAuthBadge = (id, label, status) => {
    const el = document.getElementById(id);
    el.textContent = `${label}: ${status}`;
    el.className = `badge ${status === 'PASS' ? 'bg-success' : (status === 'FAIL' ? 'bg-danger' : 'bg-secondary')}`;
  };
  setAuthBadge("badge-spf", "SPF", hdr.spf_status);
  setAuthBadge("badge-dkim", "DKIM", hdr.dkim_status);
  setAuthBadge("badge-dmarc", "DMARC", hdr.dmarc_status);

  const hdrAlerts = document.getElementById("res-header-alerts");
  if (hdr.alerts && hdr.alerts.length > 0) {
    hdrAlerts.innerHTML = hdr.alerts.map(a =>
      `<div class="text-${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'danger' : 'warning'} mb-1">
        <i class="fa-solid fa-circle-exclamation me-1"></i> ${a.message}
      </div>`
    ).join("");
  } else {
    hdrAlerts.innerHTML = '<span class="text-success"><i class="fa-solid fa-shield-check me-1"></i> Headers authentic & aligned.</span>';
  }

  // 4. Vector 3: URL Inspection
  const urlRes = data.components.url_analysis;
  document.getElementById("res-url-count").textContent = `${urlRes.total_urls} URLs`;
  document.getElementById("res-url-bad-count").textContent = urlRes.suspicious_urls;

  const urlList = document.getElementById("res-url-list");
  if (urlRes.url_details && urlRes.url_details.length > 0) {
    urlList.innerHTML = urlRes.url_details.map(u => {
      const isBad = u.is_suspicious;
      return `<div class="p-2 mb-1 rounded" style="background-color: ${isBad ? 'rgba(244, 63, 94, 0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 2px solid ${isBad ? '#f43f5e' : '#10b981'};">
        <div class="d-flex justify-content-between">
          <span class="text-break font-monospace small ${isBad ? 'text-danger fw-bold' : 'text-info'}">${u.url}</span>
          <span class="badge ${isBad ? 'bg-danger' : 'bg-success'}">${u.risk_score}/100</span>
        </div>
        ${u.anchor_text ? `<div class="text-muted" style="font-size: 0.7rem;">Anchor Text: "${u.anchor_text}"</div>` : ''}
        ${u.reasons.length ? `<div class="text-danger" style="font-size: 0.72rem;">${u.reasons.join(" ")}</div>` : ''}
      </div>`;
    }).join("");
  } else {
    urlList.innerHTML = '<span class="text-muted">No embedded URLs found.</span>';
  }

  // 5. Vector 4: Attachments
  const attRes = data.components.attachment_analysis;
  document.getElementById("res-attach-count").textContent = `${attRes.total_attachments} Files`;
  document.getElementById("res-attach-bad-count").textContent = attRes.dangerous_attachments;

  const attList = document.getElementById("res-attach-list");
  if (attRes.details && attRes.details.length > 0) {
    attList.innerHTML = attRes.details.map(a => {
      const isBad = a.is_dangerous;
      return `<div class="p-2 mb-1 rounded" style="background-color: ${isBad ? 'rgba(244, 63, 94, 0.1)' : 'rgba(255,255,255,0.03)'}; border-left: 2px solid ${isBad ? '#f43f5e' : '#10b981'};">
        <div class="d-flex justify-content-between align-items-center">
          <span class="fw-bold ${isBad ? 'text-danger' : 'text-light'}">${a.filename}</span>
          <span class="badge ${isBad ? 'bg-danger' : 'bg-success'}">${a.threat_label}</span>
        </div>
        <div class="text-muted font-monospace" style="font-size: 0.7rem;">SHA-256: ${a.sha256_hash ? a.sha256_hash.substring(0, 24) + '...' : 'N/A'}</div>
        ${a.alerts.length ? `<div class="text-danger" style="font-size: 0.72rem;">${a.alerts.map(al => al.message).join(" ")}</div>` : ''}
      </div>`;
    }).join("");
  } else {
    attList.innerHTML = '<span class="text-muted">No attachments detected.</span>';
  }
}

// Load Quarantine Records
async function loadQuarantine() {
  try {
    const res = await fetch("/api/quarantine");
    const records = await res.json();

    const badge = document.getElementById("quarantine-count-badge");
    badge.textContent = records.length;

    const tbody = document.getElementById("quarantine-table-body");
    if (records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-muted">Quarantine Vault is clean. No threats isolated.</td></tr>';
      return;
    }

    tbody.innerHTML = records.map(r => `
      <tr>
        <td>#${r.id}</td>
        <td class="small text-muted">${r.timestamp}</td>
        <td class="font-monospace small text-truncate" style="max-width: 150px;" title="${r.sender}">${r.sender}</td>
        <td class="fw-bold text-truncate" style="max-width: 180px;" title="${r.subject}">${r.subject}</td>
        <td><span class="badge bg-danger">${r.threat_score}/100</span></td>
        <td class="small text-danger text-truncate" style="max-width: 220px;" title="${r.reason}">${r.reason}</td>
        <td><span class="badge ${r.status === 'RELEASED' ? 'bg-secondary' : 'bg-warning text-dark'}">${r.status}</span></td>
        <td>
          <div class="btn-group btn-group-sm">
            ${r.status !== 'RELEASED' ? `<button class="btn btn-outline-success btn-sm" onclick="executeQuarantineAction(${r.id}, 'release')" title="Release to inbox"><i class="fa-solid fa-envelope-circle-check"></i></button>` : ''}
            <button class="btn btn-outline-danger btn-sm" onclick="executeQuarantineAction(${r.id}, 'delete')" title="Purge threat"><i class="fa-solid fa-trash-can"></i></button>
          </div>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error loading quarantine:", err);
  }
}

async function executeQuarantineAction(id, action) {
  try {
    const res = await fetch(`/api/quarantine/${id}/action`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action })
    });
    const result = await res.json();
    loadQuarantine();
    loadStats();
  } catch (err) {
    alert("Error performing action: " + err.message);
  }
}

// Load SOC Stats
async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("stat-total").textContent = data.total_scanned;
    document.getElementById("stat-quarantined").textContent = data.quarantined;
    document.getElementById("stat-warned").textContent = data.warned;
    document.getElementById("stat-clean").textContent = data.clean;

    const badge = document.getElementById("quarantine-count-badge");
    badge.textContent = data.quarantined;

    const tbody = document.getElementById("recent-scans-table-body");
    if (data.recent_activity && data.recent_activity.length > 0) {
      tbody.innerHTML = data.recent_activity.map(s => `
        <tr>
          <td>#${s.id}</td>
          <td class="small text-muted">${s.timestamp}</td>
          <td class="small text-truncate" style="max-width: 140px;">${s.sender}</td>
          <td class="small text-truncate" style="max-width: 200px;">${s.subject}</td>
          <td><span class="badge ${s.threat_score >= 70 ? 'bg-danger' : (s.threat_score >= 35 ? 'bg-warning text-dark' : 'bg-success')}">${s.threat_score}</span></td>
          <td><span class="badge-verdict verdict-${s.verdict}" style="padding: 2px 8px; font-size: 0.75rem;">${s.verdict}</span></td>
        </tr>
      `).join("");
    } else {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center py-3 text-muted">No scan history recorded yet.</td></tr>';
    }
  } catch (err) {
    console.error("Error loading stats:", err);
  }
}

// --- Crypto Studio Functions ---

async function generateKeypair() {
  try {
    const res = await fetch("/api/crypto/generate-keys", { method: "POST" });
    const keys = await res.json();
    document.getElementById("crypto-pubkey").value = keys.public_key;
    document.getElementById("crypto-privkey").value = keys.private_key;
  } catch (err) {
    alert("Key generation error: " + err.message);
  }
}

async function executeEncrypt() {
  const plaintext = document.getElementById("enc-plaintext").value;
  const publicKey = document.getElementById("crypto-pubkey").value;

  if (!plaintext || !publicKey) {
    alert("Please provide both plaintext and recipient public key.");
    return;
  }

  try {
    const res = await fetch("/api/crypto/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plaintext, public_key: publicKey })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    document.getElementById("enc-ciphertext").value = data.ciphertext;
    // Auto populate decrypt input for convenience
    document.getElementById("dec-ciphertext-input").value = data.ciphertext;
  } catch (err) {
    alert("Encryption failed: " + err.message);
  }
}

async function executeDecrypt() {
  const ciphertext = document.getElementById("dec-ciphertext-input").value;
  const privateKey = document.getElementById("crypto-privkey").value;

  if (!ciphertext || !privateKey) {
    alert("Please provide ciphertext and your private key.");
    return;
  }

  try {
    const res = await fetch("/api/crypto/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext, private_key: privateKey })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    document.getElementById("dec-plaintext-output").value = data.plaintext;
  } catch (err) {
    alert("Decryption failed: " + err.message);
  }
}

async function executeSign() {
  const message = document.getElementById("sign-message-input").value;
  const privateKey = document.getElementById("crypto-privkey").value;

  if (!message || !privateKey) {
    alert("Please enter message and sender private key.");
    return;
  }

  try {
    const res = await fetch("/api/crypto/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, private_key: privateKey })
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    document.getElementById("sign-output").value = data.signature;
  } catch (err) {
    alert("Signing failed: " + err.message);
  }
}

function tamperSignatureMessage() {
  const input = document.getElementById("sign-message-input");
  input.value += " [TAMPERED BY ATTACKER]";
  alert("Message altered! Now click 'Verify Signature with Public Key' to observe signature verification rejection.");
}

async function executeVerifySignature() {
  const message = document.getElementById("sign-message-input").value;
  const signature = document.getElementById("sign-output").value;
  const publicKey = document.getElementById("crypto-pubkey").value;

  const banner = document.getElementById("verify-status-banner");

  if (!message || !signature || !publicKey) {
    alert("Please ensure message, signature, and public key are populated.");
    return;
  }

  try {
    const res = await fetch("/api/crypto/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, signature, public_key: publicKey })
    });
    const data = await res.json();

    if (data.valid) {
      banner.innerHTML = `<div class="alert alert-success py-2 px-3 small border-0">
        <i class="fa-solid fa-circle-check me-2"></i><strong>AUTHENTIC:</strong> ${data.message}
      </div>`;
    } else {
      banner.innerHTML = `<div class="alert alert-danger py-2 px-3 small border-0">
        <i class="fa-solid fa-circle-xmark me-2"></i><strong>TAMPER DETECTED:</strong> ${data.message}
      </div>`;
    }
  } catch (err) {
    alert("Verification error: " + err.message);
  }
}
