import subprocess

issues = range(1702, 1715)
comment_body = "Hey! Please assign me under GSSoC 2026. I want to work on this issue.\n/claim /assign"

for issue_id in issues:
    print(f"Commenting on issue #{issue_id}...")
    try:
        subprocess.run(["gh", "issue", "comment", str(issue_id), "--body", comment_body], check=True)
        print(f"Successfully commented on #{issue_id}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to comment on #{issue_id}: {e}")
