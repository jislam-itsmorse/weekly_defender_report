from collections import defaultdict, Counter
from datetime import datetime
import requests
import os

# =========================
# CONFIG
# =========================
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("DEFENDER_API_CLIENT_ID")
CLIENT_SECRET = os.getenv("DEFENDER_API_CLIENT_SECRET")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

AUTH_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
API_URL_SCORES = "https://graph.microsoft.com/v1.0/security/secureScores?$top=1"
API_URL_QUERY = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"

# =========================
# STEP 1: Get Access Token
# =========================
def get_access_token():
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }

    response = requests.post(AUTH_URL, data=payload)
    response.raise_for_status()
    return response.json()["access_token"]

# =========================
# STEP 2: Run Optimized KQL Query
# =========================
def run_query(token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    query = """
    EmailEvents
    | where Timestamp > ago(7d)
    | where isnotempty(ThreatTypes)
    | where ThreatTypes has_any ("Phish", "CredentialPhish")
    | extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
    | summarize
        TotalPhish = count(),
        TopDomains = make_list(SenderDomain, 100),
        TopRecipients = make_list(RecipientEmailAddress, 100)
    """

    body = {"query": query}

    response = requests.post(API_URL_QUERY, headers=headers, json=body)
    response.raise_for_status()
    return response.json()

# =========================
# HELPER: Extract value safely
# =========================
def extract_value(val):
    if isinstance(val, dict):
        return val.get("value", 0)
    return val

# =========================
# STEP 3: Get Security Scores
# =========================
def get_security_score(token):
    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(API_URL_SCORES, headers=headers)
    response.raise_for_status()

    data = response.json()["value"][0]

    current = data["currentScore"]
    max_score = data["maxScore"]
    overall_pct = (current / max_score) * 100

    controls = data["controlScores"]
    category_scores = defaultdict(list)

    for c in controls:
        category = c.get("controlCategory")
        pct = c.get("scoreInPercentage", 0)
        category_scores[category].append(pct)

    category_avg = {}
    for category, values in category_scores.items():
        category_avg[category] = round(sum(values) / len(values), 2)

    return overall_pct, current, max_score, category_avg

# =========================
# STEP 4: Send to Slack
# =========================
def send_to_slack(message):
    payload = {"text": message}
    response = requests.post(SLACK_WEBHOOK_URL, json=payload)
    response.raise_for_status()

# =========================
# STEP 5: Main Logic
# =========================
def main():
    token = get_access_token()

    # --- Query phishing insights ---
    query_data = run_query(token)
    results = query_data.get("results", [])

    if results:
        row = results[0]

        phishing_count = extract_value(row.get("TotalPhish", 0))

        domains = row.get("TopDomains", [])
        users = row.get("TopRecipients", [])

        top_domains = Counter(domains).most_common(3)
        top_users = Counter(users).most_common(3)

    else:
        phishing_count = 0
        top_domains = []
        top_users = []

    # --- Secure Score ---
    overall_pct, current, max_score, category_avg = get_security_score(token)

    # --- Build Slack message (IMPROVED UI) ---
    now = datetime.utcnow().strftime("%Y-%m-%d")

    message = f"""
🔐 *Weekly Defender Report* ({now})

*Secure Score:* {overall_pct:.1f}%  _(Top-tier)_

━━━━━━━━━━━━━━
📊 *Benchmark*
Avg: 45–60% | Mature: 65–80% | Top: 80%+
━━━━━━━━━━━━━━

📌 *Key Areas*
Apps: {category_avg.get('Apps', 0):.1f}% | Identity: {category_avg.get('Identity', 0):.1f}%
Data: {category_avg.get('Data', 0):.1f}% | Device: {category_avg.get('Device', 0):.1f}%

━━━━━━━━━━━━━━
🚨 *Threat Activity (7d)*
Phishing Emails: *{phishing_count}*
"""

    # --- Top Domains (compact) ---
    if top_domains:
        domains_str = ", ".join([f"{d} ({c})" for d, c in top_domains])
        message += f"\nTop Domains: {domains_str}"
    else:
        message += "\nTop Domains: None"

    # --- Top Users (compact) ---
    if top_users:
        users_str = ", ".join([f"{u} ({c})" for u, c in top_users])
        message += f"\nTop Targets: {users_str}"
    else:
        message += "\nTop Targets: None"

    # --- Send ---
    send_to_slack(message)

    print("✅ Report sent to Slack successfully!")

# =========================
if __name__ == "__main__":
    main()
