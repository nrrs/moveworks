import os # env variables
import datetime # datetime for timestamping
import threading # threading for concurrent processing
import time # time for sleep
import json # json for handling JSON data
import hmac # hmac for verifying Slack requests
import hashlib # hashlib for hashing
import csv # csv for writing CSV files
import argparse # argparse for command line argument parsing
import sys # sys for system-specific parameters and functions
from flask import Flask, request, make_response # Flask for creating the web server
from dotenv import load_dotenv # dotenv for loading environment variables from a .env file
import requests # requests for making HTTP requests
import pandas as pd # pandas for data manipulation and analysis
import shlex # shlex for shell-like parsing of command line arguments

# Initialize the Web API client.
# This expects that you've already set your SLACK_BOT_TOKEN as an environment variable.
# Try to resist the urge to put your token directly in your code; it is best practice not to.
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# Load environment variables from .env file
load_dotenv()

# Create a Flask application instance
app = Flask(__name__)

# Environment variables for Slack and GoRest API
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
GOREST_TOKEN = os.environ["GOREST_TOKEN"]
GOREST_BASE_URL = "https://gorest.co.in/public/v2/users"
# Headers for GoRest API requests
HEADERS = {
    "Authorization": f"Bearer {GOREST_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def verify_slack_request(request):
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = request.headers.get("X-Slack-Signature", "")
    body = request.get_data(as_text=True)
    basestring = f"v0:{timestamp}:{body}"
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(my_signature, slack_signature)


@app.route("/slack/commands", methods=["POST"])

def slack_commands():
    # Uncomment for signature verification in production
    # if not verify_slack_request(request):
    #     return make_response("Unauthorized", 403)

    payload = request.form
    text = payload.get("text", "").strip()
    channel_id = payload.get("channel_id")
    filters = parse_filters(text)

    print(f"Received command: {text} in channel: {channel_id} with filters: {filters}")
    
    if text.startswith("test"):
        # Create threads for concurrent processing 
        thread1 = threading.Thread(target=test_worker_function, args=(channel_id, filters))
        thread1.start() # Start the thread
    elif text.startswith("users"):
        thread1 = threading.Thread(target=users_worker_function, args=(channel_id, filters))
        thread1.start() # Start the threads
    elif text.startswith("domain"):
        filters["columns"] = ["domain", "count"]
        thread1 = threading.Thread(target=domain_worker_function, args=(channel_id, filters))
        thread1.start() # Start the threads

    else:
        return make_response("❌ Unknown command.", 200)
    
    return make_response("🫡 Processing your request!", 200)


def parse_filters(text):
    # Remove the word 'report' and split rest
    parts = shlex.split(text)
    args = parts[1:]  # skip "report"

    filters = {
        "status": "active",  # Default status is 'active'",
        "domain": [], # Default domain is empty list
        "columns": ['id']  # Default columns is empty list
    }

    for arg in args:
        if "=" in arg:
            key, value = arg.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if key == "status":
                filters["status"] = value.lower() 
            elif key == "domain":
                filters["domain"] = value.lower()
            elif key == "columns":
                filters["columns"] = [col.strip() for col in value.split(",")]

    return filters

# Worker Functions

def test_worker_function(channel_id, filters):
    print("Handling Test Worker Function")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%s")
    filename= f"test_report_{timestamp}.csv"
    users = fetch_users(filters)
    write_users_to_csv(users, f"./output/{filename}", filters)
    push_to_slack(channel_id, filename)

def users_worker_function(channel_id, filters):
    print("Handling Report Worker Function")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%s")
    filename= f"users_report_{timestamp}.csv"
    users = fetch_users(filters)
    write_users_to_csv(users, f"./output/{filename}", filters)
    push_to_slack(channel_id, filename)

def domain_worker_function(channel_id, filters):
    print("Handling Domain Worker Function")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%s")
    filename= f"domains_report_{timestamp}.csv"
    users = fetch_users(filters)
    domains = count_domain_extensions(users)
    write_users_to_csv(domains, f"./output/{filename}", filters)
    push_to_slack(channel_id, filename)

# Routine Functions
def fetch_users(filters):
    filtered_users = []
    all_users = []
    page = 1
    max_pages = 1

    print(f"Fetching users with filters: {filters}")

    while page <= max_pages:
        response = requests.get(GOREST_BASE_URL, headers=HEADERS, params={"page": page, "status": filters["status"]})
        if response.status_code != 200:
            print(f"Failed to fetch data: {response.status_code} {response.text}")
            sys.exit(1)

        data = response.json()

        all_users.extend(data)

        if not data:
            break

        for user in all_users:
            if not filters.get("domain"):
                filtered_users = all_users
            else:
                # Create list of domain suffixes from comma-separated string
                email = user.get("email", "").lower()

                domains = [d.strip().lower() for d in filters["domain"].split(",")]
                print(f"Filtering users by domains: {domains}")

                # Check if user email ends with any of the domains
                if any(email.endswith(domain) for domain in domains):
                    filtered_users.append(user)
                    print(f"✅ User {user.get('id')} matches domain filter.")
                else:
                    print(f"❌ User {user.get('id')} does NOT match domain filter.")

        page += 1

    return filtered_users

def count_domain_extensions(users):
    extension_counts = {}

    for user in users:
        email = user.get("email", "")
        if "@" in email:
            domain = email.split("@")[1].lower()
            if "." in domain:
                # Take the last chunk after the last dot
                extension = domain.split(".")[-1]
            else:
                extension = domain
            extension_counts[extension] = extension_counts.get(extension, 0) + 1

    if not extension_counts:
        print("❌ No domain extensions found.")
        return []

    # Convert to list of dicts
    result = [
        {"domain": ext, "count": count}
        for ext, count in sorted(extension_counts.items(), key=lambda x: x[1], reverse=True)
    ]

    return result

def write_users_to_csv(input, csv_file, filters):
    print(f"Write CSV input: {input}")
    fieldnames = filters["columns"]
  
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames,  extrasaction='ignore')
            writer.writeheader()
            writer.writerows(input)
        print(f"Successfully wrote {len(input)} records to {csv_file}")
    except Exception as e:
        print(f"Failed to write CSV: {e}")
        sys.exit(1)

def push_to_slack(channel_id, filename):
    client = WebClient(SLACK_BOT_TOKEN)
    auth_test = client.auth_test()
    bot_user_id = auth_test["user_id"]

    # Join Bot to the channel
    try:
       response = client.conversations_invite(channel=channel_id, users=bot_user_id)
       print(response)
    except SlackApiError as e:
        print(f"Error joining channel: {e}")

    # Upload the file to the channel
    try:
        upload_text_file = client.files_upload_v2(
            channel=channel_id,
            title=f"Active Users Report: {filename}",
            file=f"./output/{filename}",
            initial_comment="Here is the report you requested.",
        )
        print(f"File {filename} uploaded successfully to channel {channel_id}.")
    except SlackApiError as e:
        print(f"Error uploading file: {e.response['error']}")
    
    return

if __name__ == "__main__":
    app.run(port=8000, debug=True)