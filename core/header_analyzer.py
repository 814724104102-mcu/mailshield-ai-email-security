"""
Header & Spoofing Analyzer for Email Security
Analyzes MIME headers, SPF/DKIM/DMARC status, display-name spoofing, and lookalike domains.
"""
import re
from email.utils import parseaddr

TRUSTED_BRANDS = {
    "paypal": ["paypal.com", "paypal-communication.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "dhl": ["dhl.com", "dhl-usa.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "irs": ["irs.gov"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.net", "docusign.com"]
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

class HeaderAnalyzer:
    def __init__(self):
        pass

    def extract_domain(self, email_address: str) -> str:
        """Extract domain from an email address."""
        if not email_address or "@" not in email_address:
            return ""
        return email_address.split("@")[-1].strip().lower()

    def analyze(self, from_header: str, reply_to: str = "", auth_results: str = "", received: str = "") -> dict:
        """
        Analyze headers for spoofing, brand impersonation, and authentication failures.
        """
        display_name, email_addr = parseaddr(from_header)
        sender_domain = self.extract_domain(email_addr)
        reply_to_display, reply_to_addr = parseaddr(reply_to)
        reply_to_domain = self.extract_domain(reply_to_addr)

        alerts = []
        spoof_score = 0  # 0 to 100 scale

        # 1. Display Name Spoofing Check
        lower_name = display_name.lower()
        impersonated_brand = None

        for brand, valid_domains in TRUSTED_BRANDS.items():
            if brand in lower_name:
                impersonated_brand = brand
                if not any(sender_domain.endswith(vd) for vd in valid_domains):
                    alerts.append({
                        "type": "DISPLAY_NAME_SPOOFING",
                        "severity": "HIGH",
                        "message": f"Display name impersonates '{brand.title()}', but actual sender domain is '{sender_domain}'."
                    })
                    spoof_score += 45
                break

        # 2. Typosquatting / Lookalike / Homoglyph Domain Detection
        clean_sender_root = sender_domain.split(".")[0] if "." in sender_domain else sender_domain
        # Replace common homoglyphs (0 -> o, 1 -> l)
        homoglyph_normalized = clean_sender_root.replace("0", "o").replace("1", "l").replace("vv", "w")

        for brand, valid_domains in TRUSTED_BRANDS.items():
            brand_root = valid_domains[0].split(".")[0]
            # Check for hyphenated tricks like paypal-verify.com
            if brand in clean_sender_root and not any(sender_domain.endswith(vd) for vd in valid_domains):
                alerts.append({
                    "type": "DECEPTIVE_BRAND_DOMAIN",
                    "severity": "HIGH",
                    "message": f"Sender domain '{sender_domain}' deceptively contains brand name '{brand.title()}'."
                })
                spoof_score += 40
                break

            # Check edit distance (Levenshtein)
            dist = levenshtein_distance(clean_sender_root, brand_root)
            norm_dist = levenshtein_distance(homoglyph_normalized, brand_root)

            if (dist == 1 or norm_dist == 0 or (norm_dist == 1 and len(brand_root) > 4)) and clean_sender_root != brand_root:
                alerts.append({
                    "type": "TYPOSQUATTING_DOMAIN",
                    "severity": "CRITICAL",
                    "message": f"Lookalike/Typosquatting domain detected: '{sender_domain}' mimics legitimate brand '{brand_root}.com'."
                })
                spoof_score += 55
                break

        # 3. Reply-To Mismatch Check
        if reply_to_domain and reply_to_domain != sender_domain:
            alerts.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "MEDIUM",
                "message": f"Reply-To domain '{reply_to_domain}' does not match From domain '{sender_domain}'. Responses will be redirected."
            })
            spoof_score += 25

        # 4. Authentication Inspection (SPF / DKIM / DMARC)
        combined_auth = (auth_results + " " + received).lower()

        spf_status = "PASS"
        dkim_status = "PASS"
        dmarc_status = "PASS"

        if "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
            spf_status = "FAIL"
            alerts.append({
                "type": "SPF_FAILURE",
                "severity": "HIGH",
                "message": "SPF validation failed: Sender IP is not authorized to send mail for this domain."
            })
            spoof_score += 30
        elif "spf=neutral" in combined_auth or "spf=none" in combined_auth:
            spf_status = "NEUTRAL"

        if "dkim=fail" in combined_auth:
            dkim_status = "FAIL"
            alerts.append({
                "type": "DKIM_FAILURE",
                "severity": "HIGH",
                "message": "DKIM cryptographic signature verification failed: Email content may have been modified in transit."
            })
            spoof_score += 30
        elif "dkim=none" in combined_auth:
            dkim_status = "NONE"

        if "dmarc=fail" in combined_auth:
            dmarc_status = "FAIL"
            alerts.append({
                "type": "DMARC_FAILURE",
                "severity": "CRITICAL",
                "message": "DMARC policy check failed: Domain alignment failed for SPF and DKIM."
            })
            spoof_score += 35

        final_score = min(100, spoof_score)

        return {
            "display_name": display_name,
            "sender_email": email_addr,
            "sender_domain": sender_domain,
            "reply_to": reply_to_addr,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "spoof_score": final_score,
            "is_spoofed": final_score >= 40,
            "alerts": alerts
        }
