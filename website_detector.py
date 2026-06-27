def analyze_website(url):

    score = 0
    reasons = []

    brands = ["amazon", "google", "paypal", "microsoft"]

    if "amaz0n" in url:
        score += 40
        reasons.append("Brand impersonation detected")

    if not url.startswith("https"):
        score += 20
        reasons.append("No HTTPS")

    return score, reasons