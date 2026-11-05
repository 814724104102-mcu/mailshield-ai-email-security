"""
MailShield AI - Web Application & Security Operations Center (SOC) Server
"""
import os
import sqlite3
import json
import time
from flask import Flask, render_template, request, jsonify

from core.aggregator import SecurityAggregator
from core.crypto_suite import CryptoSuite

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "mailshield.db")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

aggregator = SecurityAggregator()

def init_db():
    """Initialize SQLite database for quarantine and audit logs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            subject TEXT,
            threat_score REAL,
            threat_level TEXT,
            verdict TEXT,
            details_json TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            timestamp TEXT,
            sender TEXT,
            subject TEXT,
            threat_score REAL,
            threat_level TEXT,
            reason TEXT,
            details_json TEXT,
            status TEXT DEFAULT 'QUARANTINED'
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieve SOC metrics."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scanned = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'QUARANTINE'")
    quarantined = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'WARN'")
    warned = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'DELIVER'")
    clean = cursor.fetchone()[0]

    cursor.execute("SELECT id, timestamp, sender, subject, threat_score, threat_level, verdict FROM scans ORDER BY id DESC LIMIT 5")
    recent = []
    for row in cursor.fetchall():
        recent.append({
            "id": row[0],
            "timestamp": row[1],
            "sender": row[2],
            "subject": row[3],
            "threat_score": row[4],
            "threat_level": row[5],
            "verdict": row[6]
        })

    conn.close()

    return jsonify({
        "total_scanned": total_scanned,
        "quarantined": quarantined,
        "warned": warned,
        "clean": clean,
        "recent_activity": recent
    })

@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    """Analyze email from JSON payload or uploaded .eml file."""
    sender = ""
    subject = ""
    body = ""
    reply_to = ""
    auth_results = ""
    received = ""
    attachments = []

    # Case 1: File Upload (.eml)
    if 'eml_file' in request.files and request.files['eml_file'].filename:
        file = request.files['eml_file']
        raw_bytes = file.read()
        parsed = aggregator.parse_eml_bytes(raw_bytes)
        sender = parsed.get("from", "")
        subject = parsed.get("subject", "")
        body = parsed.get("body", "")
        reply_to = parsed.get("reply_to", "")
        auth_results = parsed.get("auth_results", "")
        received = parsed.get("received", "")
        attachments = parsed.get("attachments", [])
    # Case 2: JSON payload
    elif request.is_json:
        data = request.get_json()
        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        reply_to = data.get("reply_to", "")
        auth_results = data.get("auth_results", "")
        received = data.get("received", "")
        raw_att = data.get("attachments", [])
        if isinstance(raw_att, str):
            attachments = [x.strip() for x in raw_att.split(",") if x.strip()]
        else:
            attachments = raw_att
    else:
        # Form data
        sender = request.form.get("sender", "")
        subject = request.form.get("subject", "")
        body = request.form.get("body", "")
        reply_to = request.form.get("reply_to", "")
        auth_results = request.form.get("auth_results", "")
        received = request.form.get("received", "")
        raw_att = request.form.get("attachments", "")
        attachments = [x.strip() for x in raw_att.split(",") if x.strip()]

    # Run analysis
    result = aggregator.analyze_email(
        subject=subject,
        sender=sender,
        body=body,
        reply_to=reply_to,
        auth_results=auth_results,
        received=received,
        attachments=attachments
    )

    # Save to SQLite database
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (timestamp, sender, subject, threat_score, threat_level, verdict, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        sender or "Unknown Sender",
        subject or "(No Subject)",
        result["threat_score"],
        result["threat_level"],
        result["verdict"],
        json.dumps(result)
    ))
    scan_id = cursor.lastrowid

    # If quarantined, add to quarantine table
    if result["verdict"] == "QUARANTINE":
        reason = ", ".join(result.get("critical_flags", [])) or f"High threat score ({result['threat_score']}/100)"
        cursor.execute("""
            INSERT INTO quarantine (scan_id, timestamp, sender, subject, threat_score, threat_level, reason, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            timestamp,
            sender or "Unknown Sender",
            subject or "(No Subject)",
            result["threat_score"],
            result["threat_level"],
            reason,
            json.dumps(result)
        ))

    conn.commit()
    conn.close()

    result["scan_id"] = scan_id
    result["timestamp"] = timestamp
    return jsonify(result)

@app.route("/api/samples", methods=["GET"])
def get_samples():
    """List available pre-configured test scenarios."""
    samples = [
        {
            "id": 1,
            "filename": "sample_1_legitimate.eml",
            "title": "Corporate Project Roadmap",
            "type": "Legitimate",
            "badge": "success",
            "description": "Authentic company email with valid SPF/DKIM authentication and harmless links."
        },
        {
            "id": 2,
            "filename": "sample_2_paypal_phishing.eml",
            "title": "PayPal Account Suspension",
            "type": "Phishing & Spoofing",
            "badge": "danger",
            "description": "Urgent lockout threat, typosquatting domain (paypa1-update.xyz), and deceptive link pointing to a raw IP address."
        },
        {
            "id": 3,
            "filename": "sample_3_ceo_wire_fraud.eml",
            "title": "Confidential CEO Wire Request",
            "type": "BEC Fraud",
            "badge": "warning",
            "description": "Business Email Compromise (BEC) with sender impersonation, high-pressure urgency, and redirect Reply-To."
        },
        {
            "id": 4,
            "filename": "sample_4_invoice_malware.eml",
            "title": "Overdue Invoice #98231",
            "type": "Malicious Payload",
            "badge": "danger",
            "description": "Debt collection pressure carrying a double-extension executable attachment (.pdf.exe)."
        }
    ]
    return jsonify(samples)

@app.route("/api/samples/<int:sample_id>", methods=["GET"])
def load_sample(sample_id):
    """Load and parse sample email content by ID."""
    filenames = {
        1: "sample_1_legitimate.eml",
        2: "sample_2_paypal_phishing.eml",
        3: "sample_3_ceo_wire_fraud.eml",
        4: "sample_4_invoice_malware.eml"
    }
    filename = filenames.get(sample_id)
    if not filename:
        return jsonify({"error": "Sample not found"}), 404

    file_path = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File does not exist"}), 404

    with open(file_path, "rb") as f:
        parsed = aggregator.parse_eml_bytes(f.read())

    # Format attachments as list of filenames for UI
    att_names = [a["filename"] for a in parsed.get("attachments", [])]

    return jsonify({
        "sender": parsed.get("from", ""),
        "subject": parsed.get("subject", ""),
        "body": parsed.get("body", ""),
        "reply_to": parsed.get("reply_to", ""),
        "auth_results": parsed.get("auth_results", ""),
        "received": parsed.get("received", ""),
        "attachments": ", ".join(att_names)
    })

@app.route("/api/quarantine", methods=["GET"])
def get_quarantine():
    """List quarantined emails."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, scan_id, timestamp, sender, subject, threat_score, threat_level, reason, status
        FROM quarantine
        ORDER BY id DESC
    """)
    records = []
    for row in cursor.fetchall():
        records.append({
            "id": row[0],
            "scan_id": row[1],
            "timestamp": row[2],
            "sender": row[3],
            "subject": row[4],
            "threat_score": row[5],
            "threat_level": row[6],
            "reason": row[7],
            "status": row[8]
        })
    conn.close()
    return jsonify(records)

@app.route("/api/quarantine/<int:q_id>/action", methods=["POST"])
def quarantine_action(q_id):
    """Perform action on quarantined email (release or delete)."""
    data = request.get_json() or {}
    action = data.get("action", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if action == "release":
        cursor.execute("UPDATE quarantine SET status = 'RELEASED' WHERE id = ?", (q_id,))
        message = "Email released from quarantine to user mailbox."
    elif action == "delete":
        cursor.execute("DELETE FROM quarantine WHERE id = ?", (q_id,))
        message = "Quarantined threat permanently purged."
    else:
        conn.close()
        return jsonify({"error": "Invalid action"}), 400

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": message})

# --- Cryptographic API Endpoints ---

@app.route("/api/crypto/generate-keys", methods=["POST"])
def crypto_generate_keys():
    """Generate RSA 2048-bit keypair."""
    try:
        keys = CryptoSuite.generate_keypair()
        return jsonify(keys)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    """Encrypt plaintext with RSA/AES hybrid envelope."""
    data = request.get_json() or {}
    plaintext = data.get("plaintext", "")
    public_key = data.get("public_key", "")

    if not plaintext or not public_key:
        return jsonify({"error": "Both plaintext and public_key are required"}), 400

    try:
        ciphertext_b64 = CryptoSuite.encrypt_message(plaintext, public_key)
        return jsonify({
            "ciphertext": ciphertext_b64,
            "algorithm": "AES-256-GCM + RSA-2048-OAEP (SHA-256)"
        })
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 400

@app.route("/api/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    """Decrypt ciphertext envelope using RSA private key."""
    data = request.get_json() or {}
    ciphertext_b64 = data.get("ciphertext", "")
    private_key = data.get("private_key", "")

    if not ciphertext_b64 or not private_key:
        return jsonify({"error": "Both ciphertext and private_key are required"}), 400

    try:
        plaintext = CryptoSuite.decrypt_message(ciphertext_b64, private_key)
        return jsonify({
            "plaintext": plaintext,
            "status": "Decryption successful"
        })
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

@app.route("/api/crypto/sign", methods=["POST"])
def crypto_sign():
    """Sign email message using RSA-PSS SHA-256."""
    data = request.get_json() or {}
    message = data.get("message", "")
    private_key = data.get("private_key", "")

    if not message or not private_key:
        return jsonify({"error": "Both message and private_key are required"}), 400

    try:
        signature = CryptoSuite.sign_message(message, private_key)
        return jsonify({
            "signature": signature,
            "algorithm": "RSA-PSS (SHA-256, 2048-bit)"
        })
    except Exception as e:
        return jsonify({"error": f"Signing failed: {str(e)}"}), 400

@app.route("/api/crypto/verify", methods=["POST"])
def crypto_verify():
    """Verify digital signature."""
    data = request.get_json() or {}
    message = data.get("message", "")
    signature = data.get("signature", "")
    public_key = data.get("public_key", "")

    if not message or not signature or not public_key:
        return jsonify({"error": "Message, signature, and public_key are all required"}), 400

    result = CryptoSuite.verify_signature(message, signature, public_key)
    return jsonify(result)

if __name__ == "__main__":
    print("======================================================")
    print("  MailShield AI - Email Security System SOC Gateway  ")
    print("  Running at: http://127.0.0.1:5000                   ")
    print("======================================================")
    app.run(host="127.0.0.1", port=5000, debug=True)
