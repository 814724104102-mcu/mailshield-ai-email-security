# MailShield AI - Intelligent Email Security & Threat Defense System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Cryptography](https://img.shields.io/badge/Security-RSA%20%2B%20AES--256--GCM-green.svg)](https://cryptography.io/)
[![Status](https://img.shields.io/badge/Tests-10%2F10%20Passing-brightgreen.svg)]()

> **MailShield AI** is an advanced, multi-layered **Email Security Gateway and Security Operations Center (SOC)** mini-project. It detects phishing attacks, sender spoofing, malicious links, and dangerous attachment payloads while offering an interactive **Cryptographic Suite** for end-to-end email privacy and non-repudiation.

---

## 📑 Table of Contents
1. [Key Features](#-key-features)
2. [System Architecture](#-system-architecture)
3. [Multi-Vector Defense Pipeline](#-multi-vector-defense-pipeline)
4. [Mathematical & Cryptographic Formulations](#-mathematical--cryptographic-formulations)
5. [Project Structure](#-project-structure)
6. [Installation & Setup](#-installation--setup)
7. [Running the Application](#-running-the-application)
8. [Testing & Verification](#-testing--verification)
9. [Pre-Loaded Demo Scenarios](#-pre-loaded-demo-scenarios)
10. [Viva Voce & Interview Q&A](#-viva-voce--interview-qa)

---

## 🛡️ Key Features

- **Machine Learning Phishing & Spam Classifier**:
  - Natural Language Processing (NLP) with **TF-IDF Vectorization** (1-2 n-grams, sublinear term frequency).
  - Balanced **Logistic Regression** model trained on benign and phishing communications.
  - **Explainable AI (XAI)**: Identifies and visualizes exact suspicious tokens that influenced the threat decision.
  - Psychological urgency and panic heuristic scoring.

- **Header Authentication & Spoofing Inspector**:
  - RFC 822 MIME header deconstruction (`From`, `Reply-To`, `Authentication-Results`, `Received`).
  - **Display-Name Impersonation Detection**: Flags attempts where the display name mimics a brand (e.g., `"PayPal Support"`) while the sender domain is unrelated.
  - **Typosquatting & Homoglyph Detection**: Employs **Levenshtein Distance** algorithms to flag lookalike domains (`paypa1.com`, `g00gle.com`, `apple-security-check.com`).
  - Full **SPF**, **DKIM**, and **DMARC** validation status tracking.

- **Malicious URL & Hyperlink Radar**:
  - Regex-based extraction of plaintext links and HTML anchor tags.
  - **Anchor Text Mismatch Detection**: Catches phishing links where the visible label shows a genuine website (e.g., `https://paypal.com`) while the destination `href` routes to an attacker IP or malicious server.
  - **High-Risk TLD & Shortener Flagging**: Flags abusive TLDs (`.xyz`, `.top`, `.tk`, `.click`, `.ru`) and shortened redirectors (`bit.ly`, `tinyurl.com`).
  - Raw IP address hostname detection.

- **Attachment & Payload Sandbox**:
  - High-risk extension detection (`.exe`, `.scr`, `.vbs`, `.bat`, `.ps1`, `.iso`).
  - **Double-Extension Exploit Protection**: Identifies disguised files such as `Invoice_2026.pdf.exe`.
  - Macro-enabled document detection (`.docm`, `.xlsm`).
  - **SHA-256 and MD5 Cryptographic Hashing** with simulated Threat Intelligence reputation lookup.

- **Cryptographic Studio (Confidentiality & Non-Repudiation)**:
  - **RSA-2048 Keypair Generator**: Exports standard PEM-formatted public and private keys.
  - **Hybrid Encryption**: Combines symmetric **AES-256-GCM** (speed & authenticated encryption) with **RSA-OAEP (SHA-256)** for secure session key exchange.
  - **Digital Signatures**: **RSA-PSS (SHA-256)** message signing and verification with a live tamper demonstration.

- **Interactive SOC Security Dashboard**:
  - Real-time **Threat Score Gauge** (0 to 100) and automated action verdict (**DELIVER**, **WARN**, or **QUARANTINE**).
  - Isolated **Quarantine Sandbox Vault** with Release and Purge controls.
  - Live SOC statistics and audit logs stored in an embedded SQLite database.
  - 1-Click Demo Scenarios for instant testing.

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                         MailShield AI Security Pipeline                           |
+-----------------------------------------------------------------------------------+

                    [ Inbound Email: .EML / Raw Text / MIME ]
                                      |
                                      v
                       +-----------------------------+
                       |    RFC 822 MIME Parser      |
                       |  (Headers, Body, Attach)    |
                       +-----------------------------+
                                      |
        +-----------------------------+-----------------------------+
        |                             |                             |
        v                             v                             v
+------------------+          +------------------+          +------------------+
| Header Analyzer  |          |  NLP & ML Engine |          | Link & Payload   |
| - SPF/DKIM/DMARC |          |  - TF-IDF Matrix |          | - Anchor Audit   |
| - Display Spoof  |          |  - Logistic Reg. |          | - IP / TLD Check |
| - Levenshtein    |          |  - Urgency Heur. |          | - Double-Ext.    |
|   Homoglyphs     |          |  - XAI Features  |          | - SHA-256 Hash   |
+------------------+          +------------------+          +------------------+
        |                             |                             |
        +-----------------------------+-----------------------------+
                                      |
                                      v
                       +-----------------------------+
                       |  Composite Threat Engine    |
                       |  Weighted Score (0 - 100)   |
                       |  Critical Security Overrides|
                       +-----------------------------+
                                      |
             +------------------------+------------------------+
             |                                                 |
             v                                                 v
    [ Score < 35: DELIVER ]                           [ Score >= 70: QUARANTINE ]
    (Safe to Inbox)                                   (Isolated in Sandbox Vault)
             |                                                 |
             v                                                 v
    [ Score 35-69: WARN ]                             [ Cryptographic Verification ]
    (Inject Security Warning)                         (RSA-PSS & Hybrid AES-GCM)
```

---

## 🔬 Multi-Vector Defense Pipeline

| Defense Layer | Primary Vectors Inspected | Critical Override Thresholds |
|---|---|---|
| **1. Header & Identity** | SPF / DKIM / DMARC verification, Display-name spoofing, Homoglyph & Levenshtein lookalike brand domains. | DMARC failure + Display Spoofing triggers immediate quarantine ($Score \ge 90$). |
| **2. NLP Content & ML** | TF-IDF vocabulary weights, urgency keywords ("within 24 hours", "account suspended", "unauthorized access"). | High phishing probability pushes threat score above 80. |
| **3. URL & Hyperlinks** | Anchor text vs destination mismatch, raw IP addresses, suspicious TLDs (`.xyz`, `.top`), URL shorteners. | Visible trusted domain label hiding malicious IP triggers immediate quarantine ($Score \ge 88$). |
| **4. Attachment Payload** | Double extensions (`.pdf.exe`), macro-enabled formats (`.docm`), binary scripts, SHA-256 fingerprinting. | Double-extension exploit or known malware hash triggers maximum threat ($Score \ge 95$). |

---

## 📐 Mathematical & Cryptographic Formulations

### 1. TF-IDF (Term Frequency - Inverse Document Frequency)
Used to vectorize email text by rewarding words that characterize phishing threats:
$$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \log\left(\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|}\right) + 1$$
Where:
- $\text{TF}(t, d)$ utilizes sublinear term frequency: $1 + \log(\text{count}(t, d))$ for $\text{count} > 0$.
- $D$ is the document corpus.

### 2. Levenshtein Distance (Typosquatting Detection)
Computes the minimum number of single-character edits (insertions, deletions, substitutions) required to change string $a$ into string $b$:
$$\operatorname{lev}(a, b) = \begin{cases}
  |a| & \text{if } |b| = 0, \\
  |b| & \text{if } |a| = 0, \\
  \operatorname{lev}(\operatorname{tail}(a), \operatorname{tail}(b)) & \text{if } a[0] = b[0], \\
  1 + \min \begin{cases}
    \operatorname{lev}(\operatorname{tail}(a), b) \\
    \operatorname{lev}(a, \operatorname{tail}(b)) \\
    \operatorname{lev}(\operatorname{tail}(a), \operatorname{tail}(b))
  \end{cases} & \text{otherwise.}
\end{cases}$$
If $\operatorname{lev}(\text{domain\_root}, \text{brand\_root}) = 1$, a lookalike spoofing attack is detected.

### 3. Hybrid Cryptography
To resolve RSA's message-size limit ($k \le 214$ bytes for RSA-2048 with OAEP SHA-256), MailShield uses a hybrid cryptosystem:
1. Generate ephemeral session key: $K \leftarrow \{0, 1\}^{256}$
2. Encrypt message body: $C = \text{AES-256-GCM}_{K}(IV, \text{Plaintext})$
3. Encrypt session key: $C_{K} = \text{RSA-OAEP-Encrypt}(PubK_{\text{recipient}}, K)$
4. Output cryptographic envelope: $E = (C_{K}, IV, C, Tag)$

---

## 📂 Project Structure

```
MINI PRJ/
├── app.py                         # Flask web application & REST API routes
├── mailshield.db                  # Embedded SQLite database for quarantine and audit logs
├── requirements.txt               # Dependencies
├── README.md                      # Comprehensive project documentation & viva guide
├── core/                          # Security Engine Package
│   ├── __init__.py                # Package exports
│   ├── ml_detector.py             # TF-IDF + Logistic Regression NLP classifier & XAI
│   ├── header_analyzer.py         # SPF/DKIM/DMARC, homoglyph & spoofing analyzer
│   ├── url_scanner.py             # Anchor mismatch, IP host & malicious TLD scanner
│   ├── attachment_scanner.py      # Double-extension, macro & SHA-256 payload scanner
│   ├── crypto_suite.py            # RSA-2048 & AES-256-GCM hybrid encryption & signatures
│   └── aggregator.py              # Multi-vector threat scoring & .EML parser
├── samples/                       # Pre-configured Real-World .EML Test Cases
│   ├── sample_1_legitimate.eml    # Valid corporate sync with authentic headers
│   ├── sample_2_paypal_phishing.eml # Urgent lockout, lookalike domain & raw IP link
│   ├── sample_3_ceo_wire_fraud.eml  # Business Email Compromise (BEC) wire transfer
│   └── sample_4_invoice_malware.eml # Overdue invoice with double-extension payload (.pdf.exe)
├── static/
│   ├── css/
│   │   └── style.css              # Cyber SOC dark-mode stylesheet & animations
│   └── js/
│       └── main.js                # Chart.js gauge, API calls & Crypto Studio interactions
├── templates/
│   └── index.html                 # Modern Security Operations Center web dashboard
└── tests/                         # Automated Unit & Integration Tests
    ├── test_security_engines.py   # Unit tests for all detection engines (6 tests)
    └── test_api_endpoints.py      # Integration tests for Flask endpoints & crypto (4 tests)
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.

### 1. Navigate to Project Directory
```bash
cd "/Users/mugil/Downloads/MINI PRJ"
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Running the Application

Start the MailShield AI Security Gateway server:
```bash
python3 app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Testing & Verification

Run the complete automated test suite (10 test cases covering all modules):
```bash
python3 -m unittest discover tests
```

Expected output:
```
..........
----------------------------------------------------------------------
Ran 10 tests in 0.365s

OK
```

---

## 🎯 Pre-Loaded Demo Scenarios

Click the scenario buttons on top of the dashboard for instant demonstration:

1. **Scenario 1: Corporate Project Roadmap (Clean)**
   - *Sender*: `"Sarah Jenkins" <sjenkins@techcorp-solutions.com>`
   - *Characteristics*: SPF: PASS, DKIM: PASS, DMARC: PASS, no urgency, safe links.
   - *Verdict*: **DELIVER** (Threat Score: ~0 - 15)

2. **Scenario 2: PayPal Account Suspension (Phishing)**
   - *Sender*: `"PayPal Security Center" <service-notice@paypa1-update.xyz>`
   - *Characteristics*: Typosquatting homoglyph domain (`paypa1`), high urgency ("suspended within 24 hours"), Anchor mismatch (`https://paypal.com` linking to `http://185.220.101.5/login`).
   - *Verdict*: **QUARANTINE** (Threat Score: ~90 - 95)

3. **Scenario 3: CEO Urgent Wire Transfer (BEC Fraud)**
   - *Sender*: `"David Henderson, CEO" <dhenderson@acme-corporate-executive.com>`
   - *Characteristics*: High-pressure CEO impersonation, confidential wire transfer request ($84,500), Reply-To pointing to an external address.
   - *Verdict*: **WARN / QUARANTINE** (Threat Score: ~70 - 75)

4. **Scenario 4: Overdue Malware Invoice (Payload Attack)**
   - *Sender*: `"Global Billing Department" <accounting@quickinvoicing-service.top>`
   - *Characteristics*: SPF/DMARC failure, high-risk `.top` TLD, attached double-extension exploit `Overdue_Invoice_INV98231.pdf.exe`.
   - *Verdict*: **QUARANTINE** (Threat Score: ~95 - 100)

---

## 🎓 Viva Voce & Interview Q&A

### Q1: What is the primary difference between SPF, DKIM, and DMARC?
**Answer**:
- **SPF (Sender Policy Framework)**: A DNS TXT record listing authorized IP addresses permitted to send mail for a specific domain. It checks the envelope sender (`Return-Path`).
- **DKIM (DomainKeys Identified Mail)**: Provides a public-key cryptographic signature in the email header. The recipient verifies this signature against the sender's public key in DNS to guarantee the message was not modified in transit.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Enforces domain alignment between the visible `From:` header and the SPF/DKIM domains. It instructs the receiving server on what policy to execute (`none`, `quarantine`, `reject`) if validation fails.

### Q2: What is Display Name Spoofing and why is it dangerous?
**Answer**:
Display Name Spoofing occurs when an attacker writes a trusted identity in the display name field (e.g. `From: "Microsoft Account Team" <attacker98@gmail.com>`). Because mobile and web email clients often display only the name and hide the raw email address, victims are easily deceived. MailShield AI analyzes the display name for brand keywords and verifies whether the domain belongs to that brand.

### Q3: What is a Double-Extension Exploit?
**Answer**:
By default, operating systems like Windows hide known file extensions. Attackers name executable binaries like `Q3_Financial_Statement.pdf.exe`. The victim sees `Q3_Financial_Statement.pdf` with an Adobe PDF icon. When clicked, the operating system executes the `.exe` code. MailShield AI splits all extension components and catches dangerous extensions disguised behind document names.

### Q4: Why use Hybrid Encryption (AES-GCM + RSA) instead of pure RSA?
**Answer**:
RSA asymmetric cryptography is computationally demanding and strictly constrained by key length ($k \le \text{KeySize} - \text{PaddingOverhead}$). For instance, an RSA-2048 key with OAEP padding can only encrypt messages up to 214 bytes. In Hybrid Encryption, we generate an ephemeral 256-bit AES key to encrypt the entire email and attachments at high speed, then encrypt only the 32-byte AES key using RSA.

### Q5: How does MailShield AI provide Explainable AI (XAI)?
**Answer**:
Many ML models act as black boxes. MailShield AI transforms input text into TF-IDF vector space, correlates the active token weights with the learned Logistic Regression coefficients, and extracts the top positive contributors (e.g., `suspended`, `immediately`, `unauthorized`). These tokens are visually presented to the analyst as evidence badges.
