#!/usr/bin/env python3
"""IronGuard AI analyzer — LLM-powered deep code vulnerability analysis.

Sends source files to NEAR AI (confidential TEE inference) and asks the model to
find real security vulnerabilities by reasoning about the code — the class of
bugs regex/OSV cannot find (injection, SSRF, auth bypass, unsafe eval, insecure
crypto, hardcoded credentials in context, path traversal, ...).

Privacy: your code goes only to NEAR AI's TEE-attested endpoint. Nothing else.
Auth: reads NEARAI_API_KEY from the env (or ~/.nearai-env).

CLI:  python3 ai_analyze.py <file>        # analyze one file, print findings
"""
import os, re, sys, json, urllib.request

NEARAI_URL = os.environ.get("NEARAI_BASE_URL", "https://cloud-api.near.ai").rstrip("/") + "/v1/chat/completions"
MODEL = os.environ.get("NEARAI_MODEL", "deepseek-ai/DeepSeek-V4-Flash")
MAX_BYTES = 60_000  # per-file cap sent to the model
CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
            ".c", ".cpp", ".cs", ".sh", ".sql"}

SYSTEM = (
    "You are a meticulous application security auditor. You analyze source code and report "
    "ONLY concrete, exploitable security vulnerabilities you can justify from the code itself "
    "(e.g. command/SQL/NoSQL injection, SSRF, path traversal, unsafe deserialization, eval/exec "
    "of untrusted input, insecure crypto, authentication/authorization flaws, hardcoded "
    "credentials, secrets logged). Do NOT invent issues; if the file is clean, return an empty list. "
    "Respond with STRICT JSON only, no prose, no markdown fences: "
    '{"findings":[{"line":<int>,"severity":"critical|high|medium|low","type":"<short>",'
    '"title":"<short>","explanation":"<why it is exploitable>","recommendation":"<fix>"}]}'
)


def _load_key():
    key = os.environ.get("NEARAI_API_KEY")
    if not key:
        envf = os.path.expanduser("~/.nearai-env")
        if os.path.exists(envf):
            m = re.search(r'NEARAI_API_KEY=["\']?([^"\'\n]+)', open(envf).read())
            if m:
                key = m.group(1).strip()
    return key


def analyze_file(path, content, key=None):
    """Return a list of vulnerability findings for one file (LLM reasoning)."""
    key = key or _load_key()
    if not key:
        return [{"_error": "NEARAI_API_KEY not set"}]
    content = content[:MAX_BYTES]
    user = f"File: {path}\n```\n{content}\n```"
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": 1200,
        "stream": False,
    }).encode()
    req = urllib.request.Request(NEARAI_URL, data=body,
                                headers={"Content-Type": "application/json",
                                         "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.load(r)
    except Exception as ex:
        return [{"_error": f"NEAR AI call failed: {ex}"}]
    txt = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
    m = re.search(r"\{.*\}", txt, re.S)  # tolerate stray prose/fences
    if not m:
        return []
    try:
        parsed = json.loads(m.group(0))
    except Exception:
        return [{"_error": "model returned non-JSON", "_raw": txt[:300]}]
    out = []
    for f in parsed.get("findings", []):
        f["path"] = path
        f["source"] = "ai"
        out.append(f)
    return out


def analyze_repo(repo_root, key=None):
    findings = []
    SKIP = {".git", "node_modules", "target", "dist", "build", "venv", ".venv", "__pycache__", ".next", "vendor"}
    for dirpath, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in files:
            if os.path.splitext(f)[1].lower() not in CODE_EXT:
                continue
            fp = os.path.join(dirpath, f)
            try:
                if os.path.getsize(fp) > MAX_BYTES * 3:
                    continue
                content = open(fp, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            findings += [x for x in analyze_file(os.path.relpath(fp, repo_root), content, key) if "_error" not in x]
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: ai_analyze.py <file>")
        sys.exit(1)
    p = sys.argv[1]
    res = analyze_file(p, open(p, encoding="utf-8", errors="ignore").read())
    print(json.dumps(res, indent=2))
