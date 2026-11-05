"""
MailShield AI - Core Security Engine Package
"""
from .ml_detector import PhishingDetector
from .header_analyzer import HeaderAnalyzer
from .url_scanner import URLScanner
from .attachment_scanner import AttachmentScanner
from .crypto_suite import CryptoSuite
from .aggregator import SecurityAggregator

__all__ = [
    "PhishingDetector",
    "HeaderAnalyzer",
    "URLScanner",
    "AttachmentScanner",
    "CryptoSuite",
    "SecurityAggregator"
]
