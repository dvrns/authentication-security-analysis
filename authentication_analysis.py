import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import jwt
from datetime import timedelta

if not os.path.exists("charts"):
    os.makedirs("charts")

print("Loading dataset...")
df = pd.read_csv("auth_events.csv", parse_dates=["timestamp"])

df["hour"] = df["timestamp"].dt.hour

print("\n BASIC STATISTICS")
print("\nEvent Types:\n", df["event_type"].value_counts())
print("\nStatus Counts:\n", df["status"].value_counts())
print("\nAuthentication Methods:\n", df["auth_method"].value_counts())

print("\nFAILED AUTHENTICATIONS PER USER")
failures = df[df["status"] == "FAIL"]
failure_count = failures.groupby("user").size().sort_values(ascending=False)
print(failure_count)

print("\nUser with most ACCESS_DENIED:")
access_denied = df[df["event_type"] == "ACCESS_DENIED"]
print(access_denied["user"].value_counts().head(1))

print("\nOFF-HOURS LOGINS (00:00-05:00)")
off_hours = df[
    (df["event_type"] == "LOGIN") &
    (df["hour"] >= 0) &
    (df["hour"] < 5)
]

print(off_hours[["timestamp", "user", "country", "src_ip"]])

print("\nIMPOSSIBLE TRAVEL DETECTION")

def detect_impossible_travel(user_df):
    user_df = user_df.sort_values("timestamp")
    alerts = []

    for i in range(1, len(user_df)):
        prev = user_df.iloc[i-1]
        curr = user_df.iloc[i]

        if prev["country"] != curr["country"]:
            time_diff = curr["timestamp"] - prev["timestamp"]
            if time_diff < timedelta(hours=2):
                alerts.append(curr)

    return pd.DataFrame(alerts)

login_df = df[df["event_type"] == "LOGIN"]
impossible_travel = (
    login_df.groupby("user", group_keys=False)
    .apply(detect_impossible_travel)
)

if not impossible_travel.empty:
    print(impossible_travel.reset_index(drop=True)[["timestamp","country","src_ip"]])
else:
    print("No impossible travel detected.")

print("\nTOKEN REPLAY DETECTION ")

token_ips = df.groupby("session_token")["src_ip"].nunique()
replayed_tokens = token_ips[token_ips > 1].index.tolist()

print(f"Tokens used from multiple IPs: {len(replayed_tokens)}")

if replayed_tokens:
    print(df[df["session_token"].isin(replayed_tokens)]
          [["timestamp","user","src_ip","event_type","session_token"]])

print("\nTOKEN USED AFTER LOGOUT")

logout_times = df[df["event_type"]=="LOGOUT"].groupby("session_token")["timestamp"].max()

post_logout_events = []

for token, logout_time in logout_times.items():
    after_logout = df[
        (df["session_token"] == token) &
        (df["timestamp"] > logout_time)
    ]
    if not after_logout.empty:
        post_logout_events.append(after_logout)

if post_logout_events:
    post_logout_df = pd.concat(post_logout_events)
    print(post_logout_df[["timestamp","user","src_ip","event_type","session_token"]])
else:
    print("No token usage after logout detected.")

print("\nTOKEN COUNTRY CHANGE CHECK")

token_country = df.groupby("session_token")["country"].nunique()
country_change_tokens = token_country[token_country > 1].index.tolist()

print(f"Tokens used from multiple countries: {len(country_change_tokens)}")
jwt_events = df[df["auth_method"].isin(["SSO_JWT", "JWT"])].copy()

if jwt_events.empty:
    print("No JWT-based events found (auth_method is not SSO_JWT/JWT).")
else:
    for _, row in jwt_events.iterrows():
        token_str = str(row["session_token"])

        try:
            header = jwt.get_unverified_header(token_str)
            payload = jwt.decode(token_str, options={"verify_signature": False})

            print("\nUser (log):", row["user"])
            print("Algorithm:", header.get("alg"))
            print("Subject (sub):", payload.get("sub"))
            print("Expiry (exp):", payload.get("exp"))


            if header.get("alg") == "none":
                print("Vulnerable JWT detected: alg=none")

            if payload.get("sub") and payload.get("sub") != row["user"]:
                print("Username mismatch: sub != user")

            if payload.get("exp") is not None:
                token_exp = pd.to_datetime(payload["exp"], unit="s", utc=True)
                event_time = pd.to_datetime(row["timestamp"], utc=True)

                if event_time > token_exp:
                    print(" Expired token used!")

        except Exception as e:
            print("\nUser (log):", row["user"])
            print(" Invalid or malformed JWT detected:", e)



print("\nGenerating charts...")

heatmap_data = login_df.pivot_table(
    index="user",
    columns="hour",
    aggfunc="size",
    fill_value=0
)

plt.figure(figsize=(12,6))
sns.heatmap(heatmap_data, cmap="Reds")
plt.title("Login Activity Heatmap")
plt.ylabel("User")
plt.xlabel("Hour of Day")
plt.tight_layout()
plt.savefig("charts/heatmap.png")
plt.close()

plt.figure(figsize=(10,5))

bars = plt.bar(failure_count.index, failure_count.values)

for i, val in enumerate(failure_count.values):
    if val > 5:
        bars[i].set_color("red")

plt.xticks(rotation=45)
plt.title("Authentication Failures Per User")
plt.ylabel("Number of Failures")
plt.tight_layout()
plt.savefig("charts/failures.png")
plt.close()

compromised_user = None

if replayed_tokens:
    suspicious_events = df[df["session_token"].isin(replayed_tokens)]
    compromised_user = suspicious_events["user"].value_counts().idxmax()
else:
    compromised_user = failure_count.index[0] if len(failure_count) > 0 else None

if compromised_user:
    user_events = df[df["user"] == compromised_user].sort_values("timestamp").copy()

    user_events["is_replay_token"] = user_events["session_token"].isin(replayed_tokens)
    y_map = {"LOGIN": 2, "LOGOUT": 1, "ACCESS": 0}
    user_events["y"] = user_events["event_type"].map(y_map).fillna(-1)

    plt.figure(figsize=(12, 4))

    normal = user_events[~user_events["is_replay_token"]]
    plt.scatter(normal["timestamp"], normal["y"], label="Normal events", marker="o")

    suspicious = user_events[user_events["is_replay_token"]]
    if not suspicious.empty:
        plt.scatter(suspicious["timestamp"], suspicious["y"], label="Replay-token events", marker="x", s=80)

    plt.yticks([0, 1, 2], ["ACCESS", "LOGOUT", "LOGIN"])
    plt.xlabel("Time")
    plt.title(f"Timeline of Events for {compromised_user}")
    plt.grid(True, axis="x", linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"charts/timeline_{compromised_user}.png")
    plt.close()

    print(f"Chart 3 saved: charts/timeline_{compromised_user}.png")
else:
    print("Chart 3 skipped: could not determine a user.")
print("Charts saved in /charts folder.")

print("\nANALYSIS COMPLETE")