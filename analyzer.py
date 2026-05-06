import re
import requests
from urllib.parse import urlparse

class PhishingAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'bank', 'secure', 'update',
            'account', 'auth', 'confirm', 'free', 'bonus',
            'password', 'signin', 'payment', 'billing', 'support'
        ]

        self.brands = [
            'google', 'facebook', 'amazon', 'apple',
            'microsoft', 'paypal', 'netflix', 'instagram',
            'twitter', 'ebay', 'dropbox', 'linkedin',
            'youtube', 'whatsapp', 'github', 'telegram',
            'spotify', 'snapchat', 'tiktok', 'reddit',
            'pinterest', 'yahoo'
        ]

        self.suspicious_tlds = [
            '.xyz', '.ru', '.tk', '.ml', '.ga', '.cf',
            '.gq', '.pw', '.top', '.click', '.work', '.loan',
            '.info'
        ]

        self.official_sites = {
            "google": "https://www.google.com",
            "facebook": "https://www.facebook.com",
            "amazon": "https://www.amazon.com",
            "apple": "https://www.apple.com",
            "microsoft": "https://www.microsoft.com",
            "paypal": "https://www.paypal.com",
            "netflix": "https://www.netflix.com",
            "instagram": "https://www.instagram.com",
            "twitter": "https://x.com",
            "linkedin": "https://www.linkedin.com",
            "youtube": "https://www.youtube.com",
            "whatsapp": "https://www.whatsapp.com",
            "github": "https://github.com",
            "tiktok": "https://www.tiktok.com",
            "yahoo": "https://www.yahoo.com"
        }

    def expand_url(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            return requests.get(url, timeout=3, allow_redirects=True).url
        except:
            return url

    def normalize(self, text):
        for a, b in [('0','o'), ('1','l'), ('3','e'), ('5','s')]:
            text = text.replace(a, b)
        return text

    def analyze(self, url):
        result = {
            'score': 0,
            'status': 'Safe',
            'reasons': [],
            'original_url': url,
            'expanded_url': url,
            'suggested_url': None
        }

        if not url.strip():
            return result

        expanded = self.expand_url(url)
        result['expanded_url'] = expanded

        parsed = urlparse(expanded)
        domain = parsed.netloc.lower().replace("www.", "")
        base = domain.split('.')[0]

        raw_url = url.lower()
        normalized = self.normalize(domain)
        normalized_base = normalized.split('.')[0]

        score = 0
        reasons = set()
        is_critical = False

        # 🔴 Critical checks
        if '@' in url:
            score += 35
            is_critical = True
            reasons.add("Contains '@' symbol")

        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            score += 40
            is_critical = True
            reasons.add("Uses IP address")

        # 🔹 Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            score += 10
            reasons.add("Suspicious TLD")

        # 🔹 Keywords
        keyword_hits = [k for k in self.suspicious_keywords if k in raw_url]
        if keyword_hits:
            score += 15 if len(keyword_hits) == 1 else 25
            reasons.add("Suspicious keywords detected")

        # 🔹 Repeated characters
        if re.search(r'(.)\1{2,}', domain):
            score += 15
            reasons.add("Unusual repeated characters")

        # 🔴 Brand detection
        for brand in self.brands:
            if brand in normalized_base:

                legit_domain = f"{brand}.com"

                if domain == legit_domain:
                    continue

                # substitution (strong signal)
                if brand != base:
                    score += 35
                    is_critical = True
                    reasons.add(f"Character substitution impersonation ({brand})")

                else:
                    score += 20
                    reasons.add(f"Possible brand impersonation ({brand})")

                result['suggested_url'] = self.official_sites.get(brand)

                # brand + keyword combo
                if keyword_hits:
                    score += 20
                    is_critical = True
                    reasons.add(f"Brand + keyword phishing pattern ({brand})")

                break

        # 🔧 SOFT CAP to avoid unrealistic 100
        if not is_critical:
            score = min(score, 85)
        else:
            score = min(score, 100)

        # 🔴 FINAL CLASSIFICATION
        if is_critical or score >= 75:
            status = "Dangerous"
        elif score >= 30:
            status = "Suspicious"
        else:
            status = "Safe"

        result['score'] = score
        result['status'] = status
        result['reasons'] = list(reasons)

        return result