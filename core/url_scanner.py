"""
Malicious Link & URL Inspector for Email Security
Analyzes embedded URLs, anchor mismatches, IP-based links, deceptive subdomains, and suspicious TLDs.
"""
import re
from urllib.parse import urlparse

HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work",
    "link", "country", "stream", "bid", "racing", "download", "review"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly"
}

PHISHING_PATH_PATTERNS = [
    r"login", r"signin", r"verify", r"account", r"suspended",
    r"update-billing", r"security", r"banking", r"confirm", r"password-reset"
]

class URLScanner:
    def __init__(self):
        # Regex to match URLs in plaintext
        self.url_regex = re.compile(
            r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d+)?(?:/[^\s<>"\'\)]*)?',
            re.IGNORECASE
        )
        # Regex to match HTML anchor tags <a href="...">text</a>
        self.anchor_regex = re.compile(
            r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )
        # Regex for IP addresses as hosts
        self.ip_regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def extract_urls_and_anchors(self, text: str) -> list:
        """Extract URLs and any associated anchor text from content."""
        items = []
        seen = set()

        # 1. HTML Anchors
        for match in self.anchor_regex.finditer(text):
            href = match.group(1).strip()
            anchor_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
            if href and href not in seen:
                items.append({"url": href, "anchor_text": anchor_text, "from_anchor": True})
                seen.add(href)

        # 2. Plaintext URLs
        for match in self.url_regex.finditer(text):
            url = match.group(0).strip()
            if url not in seen:
                items.append({"url": url, "anchor_text": "", "from_anchor": False})
                seen.add(url)

        return items

    def inspect_url(self, item: dict) -> dict:
        """Inspect a single URL for phishing indicators."""
        url = item["url"]
        anchor_text = item.get("anchor_text", "")

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path.lower()

        reasons = []
        risk_score = 0

        # Check IP address host
        if self.ip_regex.match(hostname):
            reasons.append("URL uses a raw IP address instead of a legitimate domain name.")
            risk_score += 45

        # Check URL shortener
        if hostname.lower() in URL_SHORTENERS:
            reasons.append(f"URL uses known link shortener ({hostname}) to disguise destination.")
            risk_score += 25

        # Check High-Risk TLD
        tld = hostname.split(".")[-1].lower() if "." in hostname else ""
        if tld in HIGH_RISK_TLDS:
            reasons.append(f"URL uses high-abuse top-level domain (.{tld}).")
            risk_score += 35

        # Check Anchor Text Mismatch (e.g. Anchor says https://paypal.com but href is evil.com)
        if anchor_text:
            anchor_parsed = urlparse(anchor_text if anchor_text.startswith("http") else "http://" + anchor_text)
            anchor_host = anchor_parsed.hostname or ""
            if anchor_host and "." in anchor_host and anchor_host != hostname:
                reasons.append(f"Deceptive link mismatch: Visible text shows '{anchor_host}' but link directs to '{hostname}'.")
                risk_score += 55

        # Check for deceptive brand in subdomain (e.g., paypal.com.attacker.xyz)
        subdomains = hostname.split(".")
        if len(subdomains) > 3:
            reasons.append(f"Excessive subdomains ({hostname}) commonly used in phishing campaigns.")
            risk_score += 20
        if any(brand in hostname and not hostname.endswith(f"{brand}.com") for brand in ["paypal", "apple", "google", "microsoft", "chase"]):
            reasons.append(f"Lookalike brand name detected in subdomain or path ({hostname}).")
            risk_score += 40

        # Check phishing keywords in path
        matched_paths = [p for p in PHISHING_PATH_PATTERNS if re.search(p, path)]
        if matched_paths:
            reasons.append(f"Suspicious path targeting credentials: {', '.join(matched_paths)}.")
            risk_score += 20

        final_risk = min(100, risk_score)

        return {
            "url": url,
            "anchor_text": anchor_text,
            "hostname": hostname,
            "risk_score": final_risk,
            "is_suspicious": final_risk >= 30,
            "reasons": reasons
        }

    def scan(self, text: str) -> dict:
        """Scan all URLs in the email text."""
        extracted = self.extract_urls_and_anchors(text)
        results = [self.inspect_url(item) for item in extracted]

        if not results:
            return {
                "total_urls": 0,
                "suspicious_urls": 0,
                "max_url_risk": 0,
                "overall_url_score": 0,
                "url_details": []
            }

        suspicious_count = sum(1 for r in results if r["is_suspicious"])
        max_risk = max((r["risk_score"] for r in results), default=0)

        # Overall URL score based on max risk + penalty for quantity of bad URLs
        overall_score = min(100, max_risk + (suspicious_count - 1) * 10 if suspicious_count > 1 else max_risk)

        return {
            "total_urls": len(results),
            "suspicious_urls": suspicious_count,
            "max_url_risk": max_risk,
            "overall_url_score": overall_score,
            "url_details": results
        }
