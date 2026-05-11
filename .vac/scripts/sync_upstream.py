#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

UPSTREAM_URL = "https://boringssl.googlesource.com/boringssl"
MIRROR_URL = "https://github.com/google/boringssl.git"
UPSTREAM_REF = "refs/heads/main"

PROVENANCE_PATH = Path(".vac/boringssl-upstream.json")
PATCH_PATH = Path(".vac/patches/fiat-p256-windows.patch")
PR_BODY_PATH = Path(".vac/boringssl-sync-pr-body.md")
PATCHED_PATHS = [Path("third_party/fiat/p256_64.h")]
PROTECTED_WORKFLOW_DIR = Path(".github/workflows")
SENSITIVE_PATHS = ["crypto/", "ssl/", "include/openssl/", "third_party/fiat/"]


def run(args, *, cwd=None, check=True, capture=True):
    print("+ " + shlex.join(str(a) for a in args))
    proc = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
        raise SystemExit(proc.returncode)
    return proc


def print_proc_output(proc):
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)


def git(args, **kwargs):
    return run(["git", *args], **kwargs)


def git_output(args, **kwargs):
    return git(args, **kwargs).stdout.strip()


def set_output(name, value):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as out:
            out.write(f"{name}={value}\n")


def append_summary(text):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write(text)
            out.write("\n")


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def resolve_remote_ref(url, ref):
    output = git_output(["ls-remote", url, ref])
    lines = [line.split() for line in output.splitlines() if line.strip()]
    matches = [parts[0] for parts in lines if len(parts) == 2 and parts[1] == ref]
    if len(matches) != 1:
        fail(f"expected exactly one {ref} from {url}, got {len(matches)}")
    return matches[0]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def short_sha(sha):
    return sha[:12]


def require_clean_tree():
    status = git_output(["status", "--short"])
    if status:
        fail("working tree is not clean before sync:\n" + status)


def verify_patch_against_upstream(upstream_sha):
    repo = Path.cwd()
    tmp = Path(tempfile.mkdtemp(prefix="boringssl-upstream-"))
    worktree = tmp / "upstream"
    try:
        git(["worktree", "add", "--detach", str(worktree), upstream_sha])
        run(["git", "apply", str((repo / PATCH_PATH).resolve())], cwd=worktree)

        for rel_path in PATCHED_PATHS:
            expected = (worktree / rel_path).read_bytes()
            actual = (repo / rel_path).read_bytes()
            if expected != actual:
                fail(
                    f"{rel_path} does not match {PATCH_PATH} applied to "
                    f"upstream {upstream_sha}"
                )
    finally:
        git(["worktree", "remove", "--force", str(worktree)], check=False)
        shutil.rmtree(tmp, ignore_errors=True)


def unmerged_paths():
    output = git_output(["diff", "--name-only", "--diff-filter=U"])
    return [Path(line) for line in output.splitlines() if line.strip()]


def is_protected_workflow_path(path):
    try:
        path.relative_to(PROTECTED_WORKFLOW_DIR)
        return True
    except ValueError:
        return False


def path_exists_at_ref(ref, path):
    return git(["cat-file", "-e", f"{ref}:{path.as_posix()}"], check=False).returncode == 0


def restore_path_from_ref_or_remove(ref, path):
    if path_exists_at_ref(ref, path):
        git(["checkout", ref, "--", str(path)])
        git(["add", str(path)])
    else:
        git(["rm", "-f", "--ignore-unmatch", "--", str(path)])


def replay_local_patch():
    patch_proc = git(["apply", "-3", str(PATCH_PATH)], check=False)
    if patch_proc.returncode == 0:
        git(["add", *[str(path) for path in PATCHED_PATHS]])
        return

    print_proc_output(patch_proc)
    conflicts = unmerged_paths()
    if not conflicts:
        fail("local patch replay failed without producing unmerged paths")

    unexpected = [path for path in conflicts if path not in PATCHED_PATHS]
    if unexpected:
        fail(
            "local patch replay produced conflicts outside known patched paths: "
            + ", ".join(str(path) for path in unexpected)
        )

    for path in conflicts:
        git(["checkout", "--theirs", str(path)])
    git(["add", *[str(path) for path in PATCHED_PATHS]])


def restore_protected_workflow_changes(target_ref):
    output = git_output(["diff", "--name-only", "HEAD", "--", str(PROTECTED_WORKFLOW_DIR)])
    changed = [Path(line) for line in output.splitlines() if line.strip()]
    for path in changed:
        restore_path_from_ref_or_remove(target_ref, path)
    return [str(path) for path in changed]


def resolve_known_conflicts(upstream_sha, target_ref):
    conflicts = unmerged_paths()
    if not conflicts:
        fail("upstream merge failed without producing unmerged paths")

    unexpected = [
        path for path in conflicts
        if path not in PATCHED_PATHS and not is_protected_workflow_path(path)
    ]
    if unexpected:
        fail(
            "upstream merge produced conflicts outside known local paths: "
            + ", ".join(str(path) for path in unexpected)
        )

    workflow_conflicts = [path for path in conflicts if is_protected_workflow_path(path)]
    if workflow_conflicts:
        print(
            "Preserving target branch workflow files for upstream conflicts: "
            + ", ".join(str(path) for path in workflow_conflicts)
        )
        for path in workflow_conflicts:
            restore_path_from_ref_or_remove(target_ref, path)

    patch_conflicts = [path for path in conflicts if path in PATCHED_PATHS]
    if patch_conflicts:
        print(
            "Resolving upstream merge conflicts in known local patch paths: "
            + ", ".join(str(path) for path in patch_conflicts)
        )
        for path in PATCHED_PATHS:
            git(["checkout", upstream_sha, "--", str(path)])
        replay_local_patch()

    remaining = unmerged_paths()
    if remaining:
        fail(
            "known local patch conflict resolution left unmerged paths: "
            + ", ".join(str(path) for path in remaining)
        )


def refresh_patch_file(upstream_sha):
    patch_text = git(["diff", upstream_sha, "--", *[str(path) for path in PATCHED_PATHS]]).stdout
    if not patch_text.strip():
        fail("local patch is empty after replaying against upstream")
    PATCH_PATH.write_text(patch_text, encoding="utf-8")
    git(["add", str(PATCH_PATH)])


def verify_invariants():
    p256 = Path("third_party/fiat/p256_64.h").read_text(encoding="utf-8")
    forbidden = [
        "fiat_p256_adx_mul(",
        "fiat_p256_adx_sqr(",
        "fiat_p256_adx_mul(uint64_t",
        "fiat_p256_adx_sqr(uint64_t",
    ]
    present = [token for token in forbidden if token in p256]
    if present:
        fail(
            "third_party/fiat/p256_64.h appears to contain ADX dispatch again: "
            + ", ".join(present)
        )


def limited_lines(text, limit=100):
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) <= limit:
        return lines
    return lines[:limit] + [f"... truncated {len(lines) - limit} additional lines ..."]


def format_block(lines, empty_text):
    if not lines:
        return empty_text
    return "\n".join(f"- `{line}`" for line in lines)


def commit_subject(sha):
    return git_output(["show", "-s", "--format=%h %s", sha])


def commits_missing_review_metadata(previous_sha, upstream_sha):
    commits = git_output(["rev-list", "--reverse", f"{previous_sha}..{upstream_sha}"])
    missing = []
    for sha in [line for line in commits.splitlines() if line.strip()]:
        body = git_output(["show", "-s", "--format=%B", sha])
        has_review = "Reviewed-on: https://boringssl-review.googlesource.com/" in body
        has_reviewer = "Reviewed-by:" in body
        has_change_id = "Change-Id:" in body
        if not has_review or not has_reviewer or not has_change_id:
            missing.append(commit_subject(sha))
    return missing


def mirror_cross_check_status(upstream_sha, mirror_sha, allow_mirror_mismatch):
    if upstream_sha == mirror_sha:
        return "passed"

    mirror_is_ancestor = git(
        ["merge-base", "--is-ancestor", mirror_sha, upstream_sha],
        check=False,
    ).returncode == 0
    if mirror_is_ancestor:
        behind_count = int(git_output(["rev-list", "--count", f"{mirror_sha}..{upstream_sha}"]))
        commit_word = "commit" if behind_count == 1 else "commits"
        return f"GitHub mirror is behind canonical upstream by {behind_count} {commit_word}"

    if allow_mirror_mismatch:
        return "allowed non-ancestor mismatch by manual input"

    fail(
        "GitHub mirror does not match canonical BoringSSL upstream and is not "
        "an ancestor of it: "
        f"canonical={upstream_sha} mirror={mirror_sha}"
    )


def sensitive_commits(previous_sha, upstream_sha):
    output = git_output(
        [
            "log",
            "--format=%h %s",
            f"{previous_sha}..{upstream_sha}",
            "--",
            *SENSITIVE_PATHS,
        ]
    )
    return limited_lines(output)


def build_pr_body(
    *,
    previous_sha,
    upstream_sha,
    mirror_sha,
    mirror_status,
    fast_forward_status,
    commit_count,
    sensitive,
    missing_metadata,
    skipped_workflow_paths,
):
    sensitive_text = format_block(
        limited_lines("\n".join(sensitive)),
        "No commits in the upstream range touched the monitored paths.",
    )
    missing_text = format_block(
        limited_lines("\n".join(missing_metadata)),
        "No commits in the upstream range were missing the expected review metadata.",
    )
    skipped_workflow_text = format_block(
        limited_lines("\n".join(skipped_workflow_paths)),
        "No upstream workflow changes were skipped.",
    )

    return f"""## Summary
Syncs `vacp2p/boringssl` with BoringSSL upstream `main`.

## Security Review
- Canonical upstream: `{UPSTREAM_URL}` `{UPSTREAM_REF}`
- Previous upstream SHA: `{previous_sha}`
- New upstream SHA: `{upstream_sha}`
- GitHub mirror SHA: `{mirror_sha}`
- Mirror cross-check: {mirror_status}
- Fast-forward ancestry check: {fast_forward_status}
- Upstream commit count: {commit_count}
- Local patch: `{PATCH_PATH}` replayed successfully against the new upstream SHA

### Commits Touching Monitored Crypto Paths
{sensitive_text}

### Commits Missing Expected BoringSSL Review Metadata
{missing_text}

### Upstream Workflow Changes Not Imported
{skipped_workflow_text}

## Manual Review Checklist
- [ ] Review commits touching `crypto/`, `ssl/`, `include/openssl/`, and `third_party/fiat/`.
- [ ] Check BoringSSL security advisories and the upstream README security notes before merge.
- [ ] Confirm skipped upstream workflow changes are not needed for this fork.
- [ ] Confirm the local Windows `fiat_p256` patch is still required and correctly applied.
- [ ] Wait for CI before merging.
"""


def load_provenance():
    if not PROVENANCE_PATH.exists():
        fail(f"{PROVENANCE_PATH} is missing")
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def write_provenance(provenance, previous_sha, upstream_sha, mirror_sha):
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    patch_hash = sha256_file(PATCH_PATH)
    history = provenance.get("sync_history", [])
    history.append(
        {
            "synced_at": now,
            "previous_upstream_sha": previous_sha,
            "new_upstream_sha": upstream_sha,
            "github_mirror_sha": mirror_sha,
            "local_patch_sha256": patch_hash,
        }
    )

    updated = {
        "schema_version": 1,
        "source": {
            "url": UPSTREAM_URL,
            "ref": UPSTREAM_REF,
            "mirror_url": MIRROR_URL,
        },
        "previous_upstream_sha": previous_sha,
        "current_upstream_sha": upstream_sha,
        "last_synced_at": now,
        "local_patch": {
            "description": provenance["local_patch"]["description"],
            "commit": provenance["local_patch"]["commit"],
            "path": str(PATCH_PATH),
            "sha256": patch_hash,
        },
        "last_verification": {
            "github_mirror_sha": mirror_sha,
            "patch_replayed": True,
            "fiat_p256_adx_dispatch_absent": True,
        },
        "sync_history": history,
    }
    PROVENANCE_PATH.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")


def main():
    target_branch = os.environ.get("TARGET_BRANCH", "main")
    sync_branch = os.environ.get("SYNC_BRANCH", "automation/boringssl-upstream-sync")
    allow_mirror_mismatch = parse_bool(os.environ.get("ALLOW_MIRROR_MISMATCH", "false"))

    require_clean_tree()
    provenance = load_provenance()
    previous_sha = provenance["current_upstream_sha"]

    git(["fetch", "--no-tags", "origin", f"+refs/heads/{target_branch}:refs/remotes/origin/{target_branch}"])
    git(["checkout", "-B", sync_branch, f"origin/{target_branch}"])

    upstream_sha = resolve_remote_ref(UPSTREAM_URL, UPSTREAM_REF)
    mirror_sha = resolve_remote_ref(MIRROR_URL, UPSTREAM_REF)
    git(["fetch", "--no-tags", UPSTREAM_URL, f"+{UPSTREAM_REF}:refs/remotes/boringssl-upstream/main"])
    git(["fetch", "--no-tags", MIRROR_URL, f"+{UPSTREAM_REF}:refs/remotes/boringssl-github/main"])

    mirror_status = mirror_cross_check_status(upstream_sha, mirror_sha, allow_mirror_mismatch)

    ff = git(["merge-base", "--is-ancestor", previous_sha, upstream_sha], check=False)
    if ff.returncode != 0:
        fail(
            "new upstream SHA is not a fast-forward from the recorded base: "
            f"{previous_sha} -> {upstream_sha}"
        )
    fast_forward_status = "passed"

    if previous_sha == upstream_sha:
        print("BoringSSL upstream is already current.")
        set_output("has_changes", "false")
        append_summary("BoringSSL upstream is already current.")
        return

    commit_count = git_output(["rev-list", "--count", f"{previous_sha}..{upstream_sha}"])
    sensitive = sensitive_commits(previous_sha, upstream_sha)
    missing_metadata = commits_missing_review_metadata(previous_sha, upstream_sha)

    merge_proc = git(["merge", "--no-ff", "--no-commit", upstream_sha], check=False)
    if merge_proc.returncode != 0:
        print_proc_output(merge_proc)
        resolve_known_conflicts(upstream_sha, f"origin/{target_branch}")
    skipped_workflow_paths = restore_protected_workflow_changes(f"origin/{target_branch}")
    refresh_patch_file(upstream_sha)
    verify_patch_against_upstream(upstream_sha)
    verify_invariants()
    write_provenance(provenance, previous_sha, upstream_sha, mirror_sha)

    git(["add", str(PROVENANCE_PATH)])
    git(["commit", "-m", f"chore: sync BoringSSL upstream to {short_sha(upstream_sha)}"])

    pr_body = build_pr_body(
        previous_sha=previous_sha,
        upstream_sha=upstream_sha,
        mirror_sha=mirror_sha,
        mirror_status=mirror_status,
        fast_forward_status=fast_forward_status,
        commit_count=commit_count,
        sensitive=sensitive,
        missing_metadata=missing_metadata,
        skipped_workflow_paths=skipped_workflow_paths,
    )
    PR_BODY_PATH.write_text(pr_body, encoding="utf-8")

    set_output("has_changes", "true")
    set_output("upstream_sha", upstream_sha)
    set_output("sync_branch", sync_branch)
    set_output("pr_body_path", str(PR_BODY_PATH))
    append_summary(pr_body)


if __name__ == "__main__":
    main()
