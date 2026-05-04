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
            '.gq', '.pw', '.top', '.click', '.work', '.loan'
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
            return requests.get(url, timeout=5, allow_redirects=True).url
        except:
            return url

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
        domain = parsed.netloc.lower()

        if domain.startswith('www.'):
            domain = domain[4:]

        raw_url = url.lower()

        score = 0
        reasons = set()
        is_critical = False

        # 🔥 Normalize for substitution detection
        normalized = domain.replace('0', 'o').replace('1', 'l')

        # 🔴 Critical checks
        if '@' in url:
            score += 40
            is_critical = True
            reasons.add("URL contains '@' symbol (possible phishing redirection)")

        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            score += 50
            is_critical = True
            reasons.add("Uses IP address instead of domain (high risk)")

        # 🔹 Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            score += 15
            reasons.add("Suspicious top-level domain")

        # 🔹 Keywords
        keyword_hits = [k for k in self.suspicious_keywords if k in raw_url]
        if keyword_hits:
            score += 20 if len(keyword_hits) == 1 else 30
            reasons.add(", ".join(keyword_hits))

        # 🔴 Repeated characters (letters only, not digits like 00)
        repeated_added = False
        if re.search(r'([a-z])\1+', domain):
            score += 30
            reasons.add("Possible brand impersonation using repeated characters")
            repeated_added = True

        # 🔴 Detect substitution FIRST (critical)
        for brand in self.brands:
            if normalized == f"{brand}.com" and domain != normalized:
                score += 50
                is_critical = True
                reasons.add(f"Possible brand impersonation using character substitution ({brand})")
                result['suggested_url'] = self.official_sites.get(brand)
                break
        else:
            # 🔴 Brand detection
            for brand in self.brands:
                if brand in normalized or brand in domain:

                    # skip only exact legit domain
                    if domain == f"{brand}.com":
                        continue

                    result['suggested_url'] = self.official_sites.get(brand)

                    if domain != normalized:
                        score += 50
                        is_critical = True
                        reasons.add(f"Possible brand impersonation using character substitution ({brand})")
                    else:
                        if not repeated_added:
                            score += 20
                        reasons.add(f"Possible brand impersonation ({brand})")

                    break

        # 🔹 Cap score
        score = min(score, 100)

        # 🔹 Final classification
        if is_critical or score >= 70:
            status = "Dangerous"
        elif score >= 30:
            status = "Suspicious"
        else:
            status = "Safe"

        result['score'] = score
        result['status'] = status
        result['reasons'] = list(reasons)

        return result