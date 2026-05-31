import os
import re
import json
import base64
import subprocess
import requests
from groq import Groq

client_groq = Groq(api_key=os.environ["GROQ_API_KEY"])

GH_TOKEN = os.environ["GH_TOKEN"]
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME", "sanrishi")

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
    params = {"state": "open"}
    resp = requests.get(url, headers=HEADERS, params=params)
    if resp.status_code != 200:
        print(f"Could not get PRs for {repo}: {resp.status_code}")
        return []
    all_prs = resp.json()
    mine = [pr for pr in all_prs
            if pr.get("user", {}).get("login") == GITHUB_USERNAME]
    print(f"Total open PRs: {len(all_prs)}, yours: {len(mine)}")
    return mine


def get_failed_check_runs(repo, sha):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}/check-runs"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        return []
    runs = resp.json().get("check_runs", [])
    return [r for r in runs if r.get("conclusion") == "failure"]


def get_failure_logs(repo, details_url):
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
    lines = logs.strip().split('\n')
    # Keep only last 80 lines to stay under token limit
    return '\n'.join(lines[-80:])


def get_changed_py_files(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        return []
    return [
        f["filename"] for f in resp.json()
        if f["filename"].endswith(".py")
        and not f["filename"].startswith("tests/")
    ][:2]


def get_file_content_and_sha(repo, filepath, branch):
    url = f"https://api.github.com/repos/{repo}/contents/{filepath}"
    resp = requests.get(url, headers=HEADERS, params={"ref": branch})
    if resp.status_code != 200:
        return None, None
    data = resp.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return content, data["sha"]


def extract_failing_window(original_code, failure_log, window=60):
    """
    Find the line numbers mentioned in the traceback and return a
    ±window-line slice of the file around them, with 1-based line numbers.
    Falls back to the first 120 lines if no line numbers are found.
    """
    lines = original_code.splitlines()

    # Collect every "line N" mention from the traceback
    hits = [int(n) for n in re.findall(r'[Ll]ine\s+(\d+)', failure_log)]
    # Only keep hits that are actually inside this file
    hits = [n for n in hits if 1 <= n <= len(lines)]

    if hits:
        center = sum(hits) // len(hits)
        start = max(0, center - window)
        end = min(len(lines), center + window)
    else:
        start = 0
        end = min(120, len(lines))

    numbered = "\n".join(
        f"{start + i + 1}: {line}" for i, line in enumerate(lines[start:end])
    )
    return numbered, start, len(lines)


def apply_line_changes(original_code, changes):
    """
    Apply a list of {"line": N, "new_content": "..."} changes to the original.
    Lines that should be deleted should have new_content set to null/None.
    """
    lines = original_code.splitlines()
    for change in changes:
        ln = change.get("line")
        new_content = change.get("new_content")
        if ln is None or not (1 <= ln <= len(lines)):
            continue
        if new_content is None:
            lines[ln - 1] = None          # mark for deletion
        else:
            lines[ln - 1] = new_content
    return "\n".join(line for line in lines if line is not None)


def fix_with_groq(failure_log, filepath, original_code):
    window_text, window_start, total_lines = extract_failing_window(
        original_code, failure_log
    )

    prompt = f"""A Python CI test is failing. Identify and fix the broken lines.

FAILURE LOG:
{failure_log}

RELEVANT SECTION OF {filepath} (with 1-based line numbers, total file has {total_lines} lines):
{window_text}

Return ONLY a JSON object in exactly this format, nothing else:
{{
  "changes": [
    {{"line": <1-based line number>, "new_content": "<fixed line content>"}}
  ]
}}

Rules:
- Only include lines that must actually change to fix the failure.
- Preserve exact indentation in new_content.
- Do not add, remove, or renumber lines — only replace content of existing lines.
- If no lines in this section need changing, return {{"changes": []}}
- No explanation, no markdown, no backticks — pure JSON only."""

    response = client_groq.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000
    )
    raw = response.choices[0].message.content.strip()

    # Strip markdown fences if model ignored instructions
    raw = re.sub(r'^```[a-z]*\n?', '', raw, flags=re.MULTILINE)
    raw = re.sub(r'```$', '', raw, flags=re.MULTILINE)
    raw = raw.strip()

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        print(f"⚠️  Groq returned non-JSON response, skipping: {raw[:200]}")
        return original_code  # return unchanged — do not push

    changes = result.get("changes", [])
    if not changes:
        print("ℹ️  Groq found no changes needed in the failing section.")
        return original_code

    print(f"🩹 Groq suggests {len(changes)} line change(s): "
          f"lines {[c['line'] for c in changes]}")

    return apply_line_changes(original_code, changes)


def push_fix(fork_repo, branch, filepath, fixed_code, file_sha):
    url = f"https://api.github.com/repos/{fork_repo}/contents/{filepath}"
    data = {
        "message": f"fix: auto-fix CI failure in {filepath} via groq [skip ci]",
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

            details_url = failed_runs[0].get("details_url", "")

            # BUG FIX: this entire block was missing — the file was cut off above
            failure_log = get_failure_logs(repo, details_url)
            if not failure_log.strip():
                print(f"⚠️  PR #{pr_number}: Could not retrieve failure logs, skipping")
                continue

            py_files = get_changed_py_files(repo, pr_number)
            if not py_files:
                print(f"⚠️  PR #{pr_number}: No fixable Python files found in PR diff")
                continue

            print(f"📂 Files to fix: {py_files}")

            for filepath in py_files:
                print(f"🔧 Attempting fix for {filepath}...")

                original_code, file_sha = get_file_content_and_sha(
                    fork_repo, filepath, branch
                )
                if original_code is None:
                    print(f"⚠️  Could not fetch {filepath} from {fork_repo}@{branch}")
                    continue

                fixed_code = fix_with_groq(failure_log, filepath, original_code)

                if fixed_code.strip() == original_code.strip():
                    print(f"ℹ️  No changes suggested for {filepath}")
                    continue

                success = push_fix(fork_repo, branch, filepath, fixed_code, file_sha)
                if success:
                    print(f"✅ Pushed fix for {filepath} to {fork_repo}@{branch}")
                else:
                    print(f"❌ Failed to push fix for {filepath}")

    print("\n✅ CI fixer run complete.")


# BUG FIX: this entry point was missing — without it main() is never called
if __name__ == "__main__":
    main()