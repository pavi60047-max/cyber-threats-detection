def analyze_email(sender, subject, body):

    score = 0
    reasons = []

    keywords = [
        "urgent",
        "verify",
        "password",
        "bank",
        "click here",
        "account suspended",
        "update account"
    ]

    content = (subject + " " + body).lower()

    for word in keywords:
        if word in content:
            score += 10
            reasons.append(word)

    if "http://" in body:
        score += 20
        reasons.append("Non-secure URL found")

    if sender.endswith("@gmail.com"):
        score += 10
        reasons.append("Personal email sender")

    return score, reasons