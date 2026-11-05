"""
Attachment & Payload Inspector for Email Security
Detects dangerous executables, double extensions, macro-enabled documents,
computes cryptographic hashes, and provides threat intelligence verdicts.
"""
import hashlib
import os

DANGEROUS_EXTENSIONS = {
    # High-risk executables & scripts
    "exe": {"risk": 95, "desc": "Windows Executable binary"},
    "scr": {"risk": 95, "desc": "Screensaver Executable binary"},
    "bat": {"risk": 90, "desc": "Windows Batch command script"},
    "cmd": {"risk": 90, "desc": "Windows Command script"},
    "vbs": {"risk": 90, "desc": "Visual Basic script"},
    "js":  {"risk": 85, "desc": "JavaScript file"},
    "ps1": {"risk": 90, "desc": "PowerShell command script"},
    "hta": {"risk": 95, "desc": "HTML Application executable"},
    "msi": {"risk": 90, "desc": "Windows Installer package"},
    "iso": {"risk": 80, "desc": "Disk image container (often used to bypass scanners)"},
    "img": {"risk": 80, "desc": "Disk image container"},
    "cpl": {"risk": 90, "desc": "Control panel item executable"},
    "jar": {"risk": 75, "desc": "Java executable archive"},

    # Medium-risk macro-enabled office documents
    "docm": {"risk": 75, "desc": "Word Macro-Enabled document"},
    "xlsm": {"risk": 75, "desc": "Excel Macro-Enabled spreadsheet"},
    "pptm": {"risk": 75, "desc": "PowerPoint Macro-Enabled presentation"},
}

KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test.Malware.EICAR.Generic",
    "5d41402abc4b2a76b9719d911017c592": "Trojan.Agent.Dropper",
    "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789530d": "Ransomware.LockBit.Payload"
}

class AttachmentScanner:
    def __init__(self):
        pass

    def inspect_attachment(self, filename: str, file_bytes: bytes = None) -> dict:
        """Inspect a single email attachment for malware risks."""
        alerts = []
        risk_score = 0
        clean_name = filename.strip()
        lower_name = clean_name.lower()

        # Split extensions
        parts = lower_name.split(".")
        primary_ext = parts[-1] if len(parts) > 1 else ""

        # 1. Double extension detection (e.g. invoice.pdf.exe or report.docx.vbs)
        is_double_ext = False
        if len(parts) > 2:
            fake_ext = parts[-2]
            if fake_ext in ["pdf", "docx", "xlsx", "txt", "jpg", "png"] and primary_ext in DANGEROUS_EXTENSIONS:
                is_double_ext = True
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "DOUBLE_EXTENSION_EXPLOIT",
                    "message": f"Double extension exploit detected: '{clean_name}'. Disguised as .{fake_ext} but actually executable .{primary_ext}."
                })
                risk_score += 90

        # 2. Dangerous Extension Check
        if primary_ext in DANGEROUS_EXTENSIONS:
            info = DANGEROUS_EXTENSIONS[primary_ext]
            alerts.append({
                "severity": "HIGH" if info["risk"] >= 80 else "MEDIUM",
                "type": "DANGEROUS_FILE_EXTENSION",
                "message": f"High-risk file extension .{primary_ext} ({info['desc']}). Often carries malware payloads."
            })
            risk_score = max(risk_score, info["risk"])

        # 3. Hash computation if bytes provided
        md5_hash = ""
        sha256_hash = ""
        threat_label = "CLEAN"

        if file_bytes is not None:
            md5_hash = hashlib.md5(file_bytes).hexdigest()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        else:
            # Generate deterministic hash from filename string for simulation
            sim_bytes = clean_name.encode('utf-8')
            md5_hash = hashlib.md5(sim_bytes).hexdigest()
            sha256_hash = hashlib.sha256(sim_bytes).hexdigest()

        # 4. Threat Intelligence Lookup
        if sha256_hash in KNOWN_MALICIOUS_HASHES or md5_hash in KNOWN_MALICIOUS_HASHES:
            threat_name = KNOWN_MALICIOUS_HASHES.get(sha256_hash) or KNOWN_MALICIOUS_HASHES.get(md5_hash)
            threat_label = f"MALICIOUS: {threat_name}"
            alerts.append({
                "severity": "CRITICAL",
                "type": "KNOWN_THREAT_SIGNATURE",
                "message": f"Cryptographic hash matches known threat signature in Threat Intelligence: {threat_name}."
            })
            risk_score = 100
        elif risk_score >= 80:
            threat_label = "SUSPICIOUS_PAYLOAD"
        elif risk_score >= 40:
            threat_label = "MEDIUM_RISK"

        final_score = min(100, risk_score)

        return {
            "filename": clean_name,
            "extension": primary_ext,
            "is_double_extension": is_double_ext,
            "risk_score": final_score,
            "threat_label": threat_label,
            "is_dangerous": final_score >= 50,
            "md5_hash": md5_hash,
            "sha256_hash": sha256_hash,
            "alerts": alerts
        }

    def scan_attachments(self, attachments_list: list) -> dict:
        """Scan a list of attachments (each can be a string filename or dict with filename and bytes)."""
        if not attachments_list:
            return {
                "total_attachments": 0,
                "dangerous_attachments": 0,
                "overall_attachment_score": 0,
                "details": []
            }

        inspected = []
        for att in attachments_list:
            if isinstance(att, dict):
                res = self.inspect_attachment(att.get("filename", "unknown"), att.get("bytes", None))
            else:
                res = self.inspect_attachment(str(att))
            inspected.append(res)

        dangerous_count = sum(1 for a in inspected if a["is_dangerous"])
        max_score = max((a["risk_score"] for a in inspected), default=0)

        return {
            "total_attachments": len(inspected),
            "dangerous_attachments": dangerous_count,
            "overall_attachment_score": max_score,
            "details": inspected
        }
