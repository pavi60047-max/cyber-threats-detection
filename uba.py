import pandas as pd

def load_logs():

    df = pd.read_csv(
        "data/user_logs.csv"
    )

    scores = []

    for _, row in df.iterrows():

        score = 0

        # Night Login
        if row["login_time"] >= 22 or row["login_time"] <= 5:
            score += 20

        # Failed Login
        if row["failed_logins"] > 5:
            score += 30

        # Unknown Device
        if row["device"] == "Unknown":
            score += 25

        # High File Access
        if row["file_access"] > 100:
            score += 30

        scores.append(score)

    df["Risk_Score"] = scores

    return df