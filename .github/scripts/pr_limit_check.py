import os
import sys
import requests

def check_pr_limit():
    # Fetch environment variables provided by GitHub Actions
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    username = os.getenv("PR_AUTHOR")
    
    if not token or not repo or not username:
        print("Missing required environment variables.")
        sys.exit(1)

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Query GitHub API for open PRs in this repo
    url = f"https://api.github.com/repos/{repo}/pulls"
    params = {
        "state": "open",
        "per_page": 100
    }

    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Failed to fetch PRs: {response.json()}")
        sys.exit(1)

    pull_requests = response.json()
    
    # Filter and count how many open PRs this specific user has
    user_open_prs = [pr for pr in pull_requests if pr['user']['login'] == username]
    pr_count = len(user_open_prs)

    print(f"User @{username} currently has {pr_count} open PR(s).")

    # If they have MORE than 6 open PRs (including this new one), trigger the close action
    if pr_count > 6:
        print(f"Limit exceeded! Requesting workflow to close and lock this PR.")
        sys.exit(1)
        
    print("PR limit check passed.")
    sys.exit(0)

if __name__ == "__main__":
    check_pr_limit()