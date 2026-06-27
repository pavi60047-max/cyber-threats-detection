import pandas as pd

def authenticate(username, password):
    users = pd.read_csv("data/users.csv")

    match = users[
        (users["username"] == username) &
        (users["password"] == password)
    ]

    if len(match) > 0:
        return match.iloc[0]["role"]

    return None