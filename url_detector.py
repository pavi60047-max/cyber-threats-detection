def analyze_url(url):

    score = 0
    reasons = []

    if not url.startswith("https"):
        score += 20
        reasons.append("No HTTPS")

    suspicious = [
        "login",
        "verify",
        "secure",
        "update",
        "bank"
    ]

    for word in suspicious:

        if word in url.lower():

            score += 15
            reasons.append(word)

    return score, reasons