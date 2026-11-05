"""
Security Aggregator for MailShield AI
Integrates ML phishing detection, header spoofing analysis, URL inspection,
and attachment payload scanning into a unified Threat Score and action decision.
Also provides RFC 822 .eml parsing.
"""
import email
from email import policy
from email.parser import BytesParser, Parser

from .ml_detector import PhishingDetector
from .header_analyzer import HeaderAnalyzer
from .url_scanner import URLScanner
from .attachment_scanner import AttachmentScanner

class SecurityAggregator:
    def __init__(self):
        self.ml_detector = PhishingDetector()
        self.header_analyzer = HeaderAnalyzer()
        self.url_scanner = URLScanner()
        self.attachment_scanner = AttachmentScanner()

    def parse_eml_bytes(self, raw_bytes: bytes) -> dict:
        """Parse raw RFC 822 .eml bytes into structured dictionary."""
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return self._extract_msg_fields(msg)

    def parse_eml_str(self, raw_str: str) -> dict:
        """Parse RFC 822 email string into structured dictionary."""
        msg = Parser(policy=policy.default).parsestr(raw_str)
        return self._extract_msg_fields(msg)

    def _extract_msg_fields(self, msg) -> dict:
        subject = msg.get("Subject", "")
        from_hdr = msg.get("From", "")
        to_hdr = msg.get("To", "")
        reply_to = msg.get("Reply-To", "")
        date_hdr = msg.get("Date", "")
        auth_results = msg.get("Authentication-Results", "")
        received = " ".join(msg.get_all("Received", []))

        # Extract body (plain and html)
        body_parts = []
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if filename or "attachment" in content_disposition:
                    file_payload = part.get_payload(decode=True)
                    attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "bytes": file_payload
                    })
                elif part.get_content_type() in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_parts.append(payload.decode('utf-8', errors='ignore'))
                        except Exception:
                            pass
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body_parts.append(payload.decode('utf-8', errors='ignore'))
                except Exception:
                    pass

        full_body = "\n".join(body_parts)

        return {
            "subject": subject,
            "from": from_hdr,
            "to": to_hdr,
            "reply_to": reply_to,
            "date": date_hdr,
            "auth_results": auth_results,
            "received": received,
            "body": full_body,
            "attachments": attachments
        }

    def analyze_email(self,
                      subject: str = "",
                      sender: str = "",
                      body: str = "",
                      reply_to: str = "",
                      auth_results: str = "",
                      received: str = "",
                      attachments: list = None) -> dict:
        """
        Perform complete multi-layered security assessment on email components.
        """
        if attachments is None:
            attachments = []

        # 1. ML Phishing & Content Analysis (Subject + Body)
        combined_text = f"{subject}\n\n{body}"
        ml_result = self.ml_detector.analyze(combined_text)

        # 2. Header & Spoofing Analysis
        header_result = self.header_analyzer.analyze(
            from_header=sender,
            reply_to=reply_to,
            auth_results=auth_results,
            received=received
        )

        # 3. Malicious Link Inspection
        url_result = self.url_scanner.scan(body)

        # 4. Attachment Security Scan
        attachment_result = self.attachment_scanner.scan_attachments(attachments)

        # 5. Composite Threat Calculation
        score_ml = ml_result["confidence_score"]
        score_header = header_result["spoof_score"]
        score_url = url_result["overall_url_score"]
        score_attach = attachment_result["overall_attachment_score"]

        # Base weighted calculation
        composite_score = (
            (score_ml * 0.35) +
            (score_header * 0.25) +
            (score_url * 0.25) +
            (score_attach * 0.15)
        )

        critical_flags = []

        # Override conditions for high-severity threats:
        # Check attachment double extension or known malware
        for att in attachment_result.get("details", []):
            if att.get("is_double_extension") or att.get("risk_score", 0) >= 95:
                critical_flags.append(f"High-threat malicious attachment detected: {att['filename']}")
                composite_score = max(composite_score, 95.0)

        # Check deceptive anchor mismatch (e.g. text says paypal, link is evil)
        for u in url_result.get("url_details", []):
            if any("Deceptive link mismatch" in r for r in u.get("reasons", [])):
                critical_flags.append(f"Deceptive link spoofing detected: {u['url']}")
                composite_score = max(composite_score, 88.0)

        # Check DMARC failure with display name spoofing
        if header_result.get("dmarc_status") == "FAIL" and header_result.get("is_spoofed"):
            critical_flags.append("DMARC authentication failed with high-confidence domain impersonation")
            composite_score = max(composite_score, 90.0)

        final_threat_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Threat Level & Action
        if final_threat_score >= 70.0:
            threat_level = "CRITICAL" if final_threat_score >= 85.0 else "HIGH"
            verdict = "QUARANTINE"
            action_desc = "Block email and route to isolated Security Quarantine Sandbox."
            verdict_color = "danger"
        elif final_threat_score >= 35.0:
            threat_level = "MEDIUM"
            verdict = "WARN"
            action_desc = "Inject external security warning banner into message header."
            verdict_color = "warning"
        else:
            threat_level = "LOW"
            verdict = "DELIVER"
            action_desc = "Safe for delivery to user inbox."
            verdict_color = "success"

        return {
            "threat_score": final_threat_score,
            "threat_level": threat_level,
            "verdict": verdict,
            "action_desc": action_desc,
            "verdict_color": verdict_color,
            "critical_flags": critical_flags,
            "summary": {
                "ml_phishing_score": score_ml,
                "header_spoof_score": score_header,
                "url_risk_score": score_url,
                "attachment_risk_score": score_attach
            },
            "components": {
                "ml_analysis": ml_result,
                "header_analysis": header_result,
                "url_analysis": url_result,
                "attachment_analysis": attachment_result
            },
            "meta": {
                "subject": subject,
                "sender": sender,
                "reply_to": reply_to
            }
        }
