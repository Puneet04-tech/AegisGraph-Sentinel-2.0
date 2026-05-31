import os
import sys
import base64
import subprocess
import requests
from openai import OpenAI

GH_TOKEN = os.environ["GH_TOKEN"]
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME", "sanrishi")
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# Add more repos here as you contribute to them
UPSTREAM_REPOS = [
    "Puneet04-tech/AegisGraph-Sentinel-2.0",
    "leonagoel/hybrid-recommender",
]

HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}


def get_open_prs(repo):
    url = f"https://api.github.com/repos/{repo}/pulls"
    params = {"state": "open", "head": f"{GITHUB_USERNAME}:{GITHUB_USERNAME}"}
    resp = requests.get(url, headers=HEADERS, params=params)
    if resp.status_code != 200:
        print(f"Could not get PRs for {repo}: {resp.status_code}")
        return []
    return resp.json()


def get_failed_check_runs(repo, sha):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        return []
    runs = resp.json().get("check_runs", [])
    return [r for r in runs if r.get("conclusion") == "failure"]


def get_failure_logs(repo, details_url):
    # Extract run_id from URL like:
    # https://github.com/owner/repo/actions/runs/12345/job/67890
    try:
        run_id = details_url.split("/runs/")[1].split("/")[0]
    except Exception:
        return ""

    result = subprocess.run(
        ["gh", "run", "view", run_id, "--repo", repo, "--log-failed"],
        capture_output=True,
        text=True,
        env={**os.environ, "GH_TOKEN": GH_TOKEN}
    )
    logs = result.stdout + result.stderr
    # Return last 200 lines to stay within token limits
    lines = logs.strip().split('\n')
    return '\n'.join(lines[-200:])


def get_changed_py_files(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        return []
    return [f["filename"] for f in resp.json()
            if f["filename"].endswith(".py")][:5]


def get_file_content_and_sha(repo, filepath, branch):
    url = f"https://api.github.com/repos/{repo}/contents/{filepath}"
    resp = requests.get(url, headers=HEADERS, params={"ref": branch})
    if resp.status_code != 200:
        return None, None
    data = resp.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return content, data["sha"]


def fix_with_ai(failure_log, filepath, original_code):
    prompt = f"""You are a Python expert. A CI test is failing.

CI FAILURE LOG:
{failure_log}

FILE TO FIX ({filepath}):
{original_code}

Return ONLY the complete fixed Python file.
No explanation, no markdown, no backticks.
If this file is not the cause of the failure, return it unchanged.
Fix only what is necessary to make the failing test pass."""

    response = client.chat.completions.create(
        model="o4-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=4000
    )
    return response.choices[0].message.content.strip()


def push_fix(fork_repo, branch, filepath, fixed_code, file_sha):
    url = f"https://api.github.com/repos/{fork_repo}/contents/{filepath}"
    data = {
        "message": f"fix: auto-fix CI failure in {filepath} via o4-mini [skip ci]",
        "content": base64.b64encode(fixed_code.encode()).decode(),
        "branch": branch,
        "sha": file_sha
    }
    resp = requests.put(url, headers=HEADERS, json=data)
    return resp.status_code in [200, 201]


def main():
    for repo in UPSTREAM_REPOS:
        fork_repo = f"{GITHUB_USERNAME}/{repo.split('/')[1]}"
        print(f"\n🔍 Checking {repo}...")

        prs = get_open_prs(repo)
        print(f"Found {len(prs)} open PRs")

        for pr in prs:
            pr_number = pr["number"]
            branch = pr["head"]["ref"]
            sha = pr["head"]["sha"]
            print(f"\nChecking PR #{pr_number}: {pr['title'][:60]}")

            failed_runs = get_failed_check_runs(repo, sha)
            if not failed_runs:
                print(f"✅ PR #{pr_number}: No failures")
                continue

            print(f"❌ PR #{pr_number}: {len(failed_runs)} failed checks")

            # Get logs from first failed check
            details_url = failed_runs[0].get("details_url", "")
            failure_log = get_failure_logs(repo, details_url)

            if not failure_log:
                print(f"Could not get logs for PR #{pr_number}, skipping")
                continue

            changed_files = get_changed_py_files(repo, pr_number)
            if not changed_files:
                print(f"No Python files changed in PR #{pr_number}")
                continue

            print(f"Changed files: {changed_files}")

            for filepath in changed_files:
                original_code, file_sha = get_file_content_and_sha(
                    fork_repo, filepath, branch
                )
                if not original_code:
                    print(f"Could not read {filepath} from fork")
                    continue

                print(f"🤖 Sending {filepath} to o4-mini...")
                fixed_code = fix_with_ai(failure_log, filepath, original_code)

                if len(fixed_code) < 50:
                    print(f"Response too short, skipping {filepath}")
                    continue

                if fixed_code == original_code:
                    print(f"No changes needed for {filepath}")
                    continue

                success = push_fix(fork_repo, branch, filepath, fixed_code, file_sha)
                if success:
                    print(f"✅ Fix pushed for {filepath} on PR #{pr_number}")
                else:
                    print(f"❌ Failed to push fix for {filepath}")


if __name__ == "__main__":
    main()