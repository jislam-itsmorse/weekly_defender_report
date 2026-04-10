from collections import defaultdict
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

# =========================
# CONFIG
# =========================
load_dotenv()

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
# STEP 2: Run KQL Query (FIXED → POST)
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
    | summarize count()
    """

    body = {"query": query}

    response = requests.post(API_URL_QUERY, headers=headers, json=body)  # ✅ FIXED
    response.raise_for_status()
    return response.json()

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
    payload = {
        "text": message
    }

    response = requests.post(SLACK_WEBHOOK_URL, json=payload)
    response.raise_for_status()

# =========================
# STEP 5: Main Logic
# =========================
def main():
    token = get_access_token()

    # Get phishing count
    query_data = run_query(token)
    phishing_count = query_data["results"][0][0] if query_data.get("results") else 0

    # Get security score
    overall_pct, current, max_score, category_avg = get_security_score(token)

    # Build Slack message
    now = datetime.utcnow().strftime("%Y-%m-%d")

    message = f"""
🔐 *Weekly Defender Report* ({now})

*Overall Secure Score:* {overall_pct:.2f}% ({current}/{max_score})

*Category Breakdown:*
"""

    for k, v in category_avg.items():
        message += f"\n• {k}: {v}%"

    message += f"\n\n📧 *Phishing Emails (last 7 days):* {phishing_count}"

    # Send
    send_to_slack(message)

    print("Report sent to Slack!")

# =========================
if __name__ == "__main__":
    main()
