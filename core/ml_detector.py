"""
ML-based Phishing and Spam Detector with Explainable AI (XAI)
"""
import os
import re
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")

# Rich synthetic dataset representing real-world benign vs. phishing emails
TRAINING_DATA = [
    # Legitimate (0)
    ("Team meeting rescheduled to tomorrow 10am in Conference Room B", 0),
    ("Weekly sprint notes: Backend API endpoints completed and deployed to staging", 0),
    ("Quarterly financial report is attached for your review. Please check page 4.", 0),
    ("Lunch plans today? Pizza place near the office has a discount.", 0),
    ("GitHub: Pull request #42 approved and merged into main branch", 0),
    ("Your monthly electricity bill is ready. Amount: $45.20. Auto-pay scheduled.", 0),
    ("Project timeline update: We are ahead of schedule for milestone 3", 0),
    ("Thank you for your order! Your package has shipped with tracking number 94001000", 0),
    ("Customer support ticket #8921 has been marked as resolved", 0),
    ("HR Announcement: Annual open enrollment for health benefits begins next Monday", 0),
    ("Invitation: Design Review - New User Onboarding flow on Thursday at 3 PM", 0),
    ("Code review requested for authentication refactor in PR 108", 0),
    ("Your flight itinerary for Chicago conference is confirmed. Confirmation code: ZX92K", 0),
    ("Here are the lecture slides from yesterday's computer networks class", 0),
    ("System maintenance scheduled for this Saturday between 2 AM and 4 AM UTC", 0),
    ("Notes from our conversation yesterday regarding the software architecture", 0),
    ("Receipt for your recent purchase at the bookstore. Thank you for your business.", 0),
    ("Welcome to our newsletter! Here are top technology stories of the week", 0),
    ("The shared drive folder permissions have been updated as requested", 0),
    ("Can we review the slide deck before the client presentation this afternoon?", 0),
    ("Hi John, could you please sign off on the design specs when you get a chance?", 0),
    ("Reminder: Submit your expense reports by end of week for processing", 0),

    # Phishing (1)
    ("URGENT: Your PayPal account has been suspended! Verify your identity immediately", 1),
    ("Immediate action required: Unauthorized login detected from Russia. Reset password now", 1),
    ("You have won $1,000,000 in the International Google Lottery! Claim your prize today", 1),
    ("SECURITY ALERT: Your Microsoft 365 password expires in 2 hours. Keep current password here", 1),
    ("Dear customer, your bank account is temporarily locked. Click here to confirm credentials", 1),
    ("IRS Notice: You have an unpaid tax refund of $4,850. Submit your SSN to claim", 1),
    ("URGENT Wire Transfer Request: Please execute payment to vendor immediately. Keep confidential.", 1),
    ("DHL Delivery Failed: We were unable to deliver your parcel. Download shipping label to reschedule", 1),
    ("Your Apple ID has been compromised. Verify your billing credit card information now", 1),
    ("Netflix Payment Declined: Update your payment information within 24 hours to avoid cancellation", 1),
    ("Crypto Giveaway! Send 0.1 ETH and get 1.0 ETH back instantly from Elon Musk", 1),
    ("Security Notice: Unusual activity on Chase Bank account. Unlock your account via this link", 1),
    ("Invoice Overdue: Your company owes $14,950. Open the attached macro-enabled document to review", 1),
    ("Final warning: Mailbox storage 99% full. Upgrade quota now or all incoming mail will be deleted", 1),
    ("Amazon Security: Suspicious purchase of $1,299 iPhone from IP 185.220.101.5. Cancel order now", 1),
    ("Attention Employee: Mandatory COVID relief bonus of $2,500. Enter direct deposit information", 1),
    ("Urgent: Please purchase 5 Apple gift cards for the team right away. I am in a board meeting.", 1),
    ("DocuSign: Important contract pending your electronic signature. Click to access secure portal", 1),
    ("Dropbox: A confidential file has been shared with you. Sign in with your work email to view", 1),
    ("Wells Fargo alert: Restricted access until you verify your debit card PIN and CVV", 1),
    ("Action required: Confirm your social security number to avoid immediate account termination", 1),
    ("Exclusive investment offer: Guaranteed 300% weekly return on Bitcoin trading platform", 1),
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "unauthorized", "action required",
    "within 24 hours", "locked", "compromised", "verify your identity",
    "claim your prize", "wire transfer", "confidential", "final warning",
    "overdue", "reset password", "ssn", "debit card", "pin", "gift card"
]

class PhishingDetector:
    def __init__(self):
        self.pipeline = None
        self._load_or_train()

    def _train(self):
        """Train TF-IDF + Logistic Regression model with balanced class weights."""
        texts = [item[0] for item in TRAINING_DATA]
        labels = [item[1] for item in TRAINING_DATA]

        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                lowercase=True,
                stop_words="english",
                sublinear_tf=True
            )),
            ("clf", LogisticRegression(
                C=2.0,
                class_weight="balanced",
                max_iter=500,
                random_state=42
            ))
        ])
        self.pipeline.fit(texts, labels)
        try:
            joblib.dump(self.pipeline, MODEL_PATH)
        except Exception:
            pass

    def _load_or_train(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.pipeline = joblib.load(MODEL_PATH)
                return
            except Exception:
                pass
        self._train()

    def analyze(self, text: str) -> dict:
        """
        Analyze email content for phishing probability, urgency score,
        and explainable keyword contributions.
        """
        if not text or not text.strip():
            return {
                "phishing_probability": 0.0,
                "confidence_score": 0.0,
                "is_phishing": False,
                "urgency_score": 0.0,
                "urgency_triggers": [],
                "top_risk_features": []
            }

        clean_text = text.strip()
        lower_text = clean_text.lower()

        # 1. ML Probability
        probs = self.pipeline.predict_proba([clean_text])[0]
        prob_phishing = float(probs[1])

        # 2. Heuristic Urgency Analysis
        matched_urgency = [kw for kw in URGENCY_KEYWORDS if re.search(r'\b' + re.escape(kw) + r'\b', lower_text)]
        urgency_score = min(1.0, len(matched_urgency) * 0.25)

        # 3. Blended ML + Urgency confidence
        final_probability = min(1.0, max(0.0, (prob_phishing * 0.75) + (urgency_score * 0.25)))

        # 4. Explainable AI (XAI) feature importance
        tfidf = self.pipeline.named_steps["tfidf"]
        clf = self.pipeline.named_steps["clf"]
        feature_names = np.array(tfidf.get_feature_names_out())
        coefs = clf.coef_[0]

        # Transform single input text to get active non-zero features
        vec = tfidf.transform([clean_text]).toarray()[0]
        active_indices = np.where(vec > 0)[0]

        risk_features = []
        for idx in active_indices:
            weight = coefs[idx] * vec[idx]
            if weight > 0:  # Positively contributed to Phishing
                risk_features.append({
                    "word": feature_names[idx],
                    "weight": round(float(weight), 3)
                })

        risk_features.sort(key=lambda x: x["weight"], reverse=True)
        top_features = risk_features[:6]

        return {
            "phishing_probability": round(final_probability, 4),
            "confidence_score": round(final_probability * 100, 1),
            "is_phishing": final_probability >= 0.50,
            "urgency_score": round(urgency_score * 100, 1),
            "urgency_triggers": matched_urgency,
            "top_risk_features": top_features
        }
