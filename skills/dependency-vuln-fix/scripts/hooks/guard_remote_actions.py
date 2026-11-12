#!/usr/bin/env python3
"""PreToolUse hook: force an explicit human approval before anything leaves the machine.

Wired from the skill's frontmatter for Bash and MCP tools. It never blocks silently:
it answers with permissionDecision "ask" (user is prompted) or, for destructive git
history rewrites, "deny". Fails open (exit 0, no output) on malformed input so a hook
bug can never wedge the session.
"""
import json
import re
import sys

ASK_BASH = [
    (r"\bgit\s+push\b", "git push publishes to a remote"),
    (r"\b(gh|glab)\s+(pr|mr)\s+(create|merge|approve|close|reopen|update)\b", "creates/changes a pull or merge request"),
    (r"\b(gh|glab)\s+api\b.*(-X|--method)\s*['\"]?(POST|PUT|PATCH|DELETE)", "writes to the GitHub/GitLab API"),
    (r"\b(gh|glab)\s+issue\s+(create|comment|close)\b", "writes to the issue tracker"),
    (r"\bnpm\s+(publish|deprecate|unpublish)\b", "publishes to a registry"),
    (r"\bmvn\b.*\b(deploy|release:perform)\b", "deploys artifacts to a remote repository"),
    (r"\bnpm\s+audit\s+fix\b.*--force", "`npm audit fix --force` accepts breaking major upgrades blindly"),
    (r"\b(rm|del|Remove-Item)\b.*\b(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)", "deleting a lockfile re-resolves EVERY dependency"),
    (r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|restore\s)", "discards local changes"),
]
DENY_BASH = [
    (r"\bgit\s+push\b.*(--force\b|--force-with-lease\b|\s-f\b)", "force-push is never part of a dependency fix"),
]
MCP_WRITE_VERBS = re.compile(
    r"(create|update|merge|push|dismiss|resolve|comment|delete|approve|close|reopen|edit|add_|set_|upload|fork)", re.I)
MCP_VENDOR = re.compile(r"(github|gitlab)", re.I)


def decision(kind, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": kind,
        "permissionDecisionReason": f"dependency-vuln-fix: {reason}. Confirm you have reviewed the diff and approve."}}))
    sys.exit(0)


def main():
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    tool = event.get("tool_name", "")
    if tool == "Bash":
        cmd = (event.get("tool_input") or {}).get("command", "")
        for rx, why in DENY_BASH:
            if re.search(rx, cmd):
                decision("deny", why)
        for rx, why in ASK_BASH:
            if re.search(rx, cmd):
                decision("ask", why)
    elif tool.startswith("mcp__") and MCP_VENDOR.search(tool) and MCP_WRITE_VERBS.search(tool.split("__")[-1]):
        decision("ask", f"MCP call `{tool}` changes remote GitHub/GitLab state")
    sys.exit(0)


if __name__ == "__main__":
    main()
