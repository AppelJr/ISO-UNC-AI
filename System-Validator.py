#!/usr/bin/env python3
"""System Validator. Five stages in the order of the compliance flowchart:
Core Tests -> Extended Tests -> Hardware Attestation -> Threat Feed Check -> Signature Update Vest.
PASS needs evidence. NOT RUN is never a pass. Any FAIL rejects. Any NOT RUN leaves the system unvalidated."""
import base64, calendar, hashlib, http.client, importlib.metadata, json, os, platform, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from pipeline import AuditLedger, Policy, sha3, canon

STAGES = [("core", "Core Tests"), ("extended", "Extended Tests"), ("hardware", "Hardware Attestation"), ("threat", "Threat Feed Check"), ("signature", "Signature Update Vest")]
def E(k, v): return {"k": k, "v": str(v)}
def norm(n): return re.sub(r"[-_.]+", "-", str(n).lower())
def _ver(v): return [(0, int(p)) if p.isdigit() else (-1, p.lower()) for p in re.findall(r"\d+|[A-Za-z]+", str(v))]
def vcmp(a, b):
    x, y = _ver(a), _ver(b); n = max(len(x), len(y)); x += [(0, 0)] * (n - len(x)); y += [(0, 0)] * (n - len(y)); return (x > y) - (x < y)

def affected(v, eco, name, ver):
    for a in v.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem", "").lower() != eco.lower() or norm(p.get("name", "")) != norm(name): continue
        if ver in a.get("versions", []): return True
        for r in a.get("ranges", []):
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"): continue
            intro, hit = None, False
            for e in r.get("events", []):
                if "introduced" in e: intro = e["introduced"]
                elif intro is not None and ("fixed" in e or "last_affected" in e):
                    lo_ok = intro == "0" or vcmp(ver, intro) >= 0
                    hit = hit or (lo_ok and (vcmp(ver, e["fixed"]) < 0 if "fixed" in e else vcmp(ver, e["last_affected"]) <= 0)); intro = None
            if intro is not None and (intro == "0" or vcmp(ver, intro) >= 0): hit = True
            if hit: return True
    return False

def _der(b, i=0):
    l = b[i + 1]; j = i + 2
    if l & 0x80: n = l & 0x7F; l = int.from_bytes(b[j:j + n], "big"); j += n
    return b[i], j, j + l
def rsa_pub_from_pem(pem):
    der = base64.b64decode(re.sub(r"-----[^-]+-----|\s", "", pem)); _, s, _e = _der(der); t2, s2, e2 = _der(der, s)
    if t2 == 0x30:
        _, s3, e3 = _der(der, e2); bits = der[s3 + 1:e3]; _, s, _e = _der(bits); _, sn, en = _der(bits, s); n = int.from_bytes(bits[sn:en], "big"); _, se, ee = _der(bits, en); return n, int.from_bytes(bits[se:ee], "big")
    _, s3, e3 = _der(der, e2); return int.from_bytes(der[s2:e2], "big"), int.from_bytes(der[s3:e3], "big")
PFX = bytes.fromhex("3031300d060960864801650304020105000420")
def rsa_ok(n, e, sig, msg):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k: return False
    t = PFX + hashlib.sha256(msg).digest(); m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big"); return k >= len(t) + 11 and m == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t

def core(ctx):
    t = ctx["root"] / "tests" / "test_control_TEST.py"
    if not t.exists(): return "NOT_RUN", [E("tests", "the target has no tests/test_control_TEST.py")]
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-k", "not validator_run and not node_", str(t)], cwd=str(ctx["root"]), capture_output=True, text=True, timeout=240, env={**os.environ, "CONTROL_VALIDATING": "1"})
    last = [l for l in p.stdout.splitlines() if l.strip()][-1:] or [p.stderr[-160:]]
    return ("PASS" if p.returncode == 0 else "FAIL"), [E("command", "pytest -q tests/test_control_TEST.py, core subset"), E("result", last[0])]

def extended(ctx):
    port, rows, root = ctx["port"], [], ctx["root"]
    ctx["ledger"].append("VALIDATOR", "EXTENDED_PROBE", None)  # guarantees a record exists for the tamper test on a fresh install
    def call(m, path, body=None, h=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10); c.request(m, path, body, {"Host": host or "127.0.0.1:" + str(port), **(h or {})}); r = c.getresponse(); return r.status, r.read()
    X = {"X-Control": "1", "Content-Type": "application/json"}
    def conc():
        t0 = time.perf_counter()
        with ThreadPoolExecutor(40) as ex: codes = list(ex.map(lambda _: call("GET", "/api/health")[0], range(40)))
        return all(c == 200 for c in codes) and time.perf_counter() - t0 < 8, "40 parallel health requests, " + str(round(time.perf_counter() - t0, 2)) + " s"
    def tamper():
        recs = ctx["ledger"].path.read_text(encoding="utf-8").splitlines()
        if not recs: return False, "no ledger records to test with"
        d = Path(tempfile.mkdtemp()) / "l.jsonl"; r = json.loads(recs[0]); r["type"] = "FORGED"; d.write_text("\n".join([json.dumps(r)] + recs[1:]) + "\n"); return AuditLedger(d).verify()["valid"] is False, "a changed first record is detected on a copy"
    def no_dispatch():
        s, b = call("POST", "/api/request", json.dumps({"text": "extended test: summarise this sentence"}), X); run = json.loads(b); ev = [r for r in ctx["ledger"].records() if r["run_id"] == run["id"]]
        return s == 200 and not any(r["type"] == "DISPATCH" for r in ev), "a new request sent nothing to any lane before approval"
    def redacts():
        s, b = call("POST", "/api/request", json.dumps({"text": "mail me at jo@example.com about key sk-abcdefghijklmnopqrstuv"}), X); red = json.loads(b)["envelope"]["redacted"]; return "jo@example.com" not in red and "sk-abcdefghijklmnop" not in red, "personal data and secrets are removed from the envelope"
    tests = [("malformed JSON is refused (400)", lambda: (call("POST", "/api/request", "{bad", X)[0] == 400, "")), ("an oversized body is refused (413)", lambda: (call("POST", "/api/request", "x" * 70000, X)[0] == 413, "")),
             ("a change without the control header is refused (403)", lambda: (call("POST", "/api/request", "{}", {"Content-Type": "application/json"})[0] == 403, "")), ("a foreign Host header is refused (403)", lambda: (call("GET", "/api/health", host="evil.example")[0] == 403, "")),
             ("an unknown route is a 404", lambda: (call("GET", "/api/nothing")[0] == 404, "")), ("concurrent load", conc), ("unknown providers are blocked (fail closed)", lambda: (Policy(root).effective("NoSuchProvider")[0] == "block", "")),
             ("ledger tampering is detected", tamper), ("no lane traffic before approval", no_dispatch), ("redaction", redacts)]
    for name, fn in tests:
        t0 = time.perf_counter()
        try: ok, d = fn()
        except Exception as e: ok, d = False, type(e).__name__ + ": " + str(e)[:100]
        rows.append(E(("PASS  " if ok else "FAIL  ") + name, d + " (" + str(round((time.perf_counter() - t0) * 1000)) + " ms)"))
    return ("PASS" if all(r["k"].startswith("PASS") for r in rows) else "FAIL"), rows

def hardware(ctx):
    root, ev = ctx["root"], []
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), platform.processor() or "unknown") if os.path.exists("/proc/cpuinfo") else platform.processor() or "unknown"
    mem = next((l.split()[1] + " kB" for l in open("/proc/meminfo") if l.startswith("MemTotal")), "unknown") if os.path.exists("/proc/meminfo") else "unknown"
    mid = hashlib.sha256(open("/etc/machine-id", "rb").read()).hexdigest()[:16] if os.path.exists("/etc/machine-id") else "none"
    ev += [E("host", platform.platform()), E("cpu", cpu + ", " + str(os.cpu_count()) + " cores"), E("memory", mem), E("machine id (hashed)", mid)]
    man, bad = root / "MANIFEST.json", []
    if man.exists():
        files = json.loads(man.read_text())["files"]; bad = [f for f, h in files.items() if not (root / f).exists() or hashlib.sha256((root / f).read_bytes()).hexdigest() != h]; ev.append(E("software integrity", (str(len(files)) + " files match MANIFEST.json") if not bad else "CHANGED: " + ", ".join(bad[:6])))
    else: ev.append(E("software integrity", "no MANIFEST.json"))
    tpm = any(os.path.exists(p) for p in ("/dev/tpm0", "/dev/tpmrm0", "/sys/class/tpm/tpm0")); sb = None
    for p in Path("/sys/firmware/efi/efivars").glob("SecureBoot-*") if Path("/sys/firmware/efi/efivars").exists() else []:
        try: sb = p.read_bytes()[-1] == 1
        except Exception: pass
    ev += [E("TPM", "present" if tpm else "none found"), E("secure boot", "unknown" if sb is None else "on" if sb else "off")]
    if bad: return "FAIL", ev
    if not tpm: return "NOT_RUN", ev + [E("verdict", "No TPM or secure enclave on this host, so there is no hardware root of trust to attest. The software integrity result above is real but is not hardware attestation.")]
    exp = root / "feeds" / "expected_pcrs.json"
    if not shutil.which("tpm2_pcrread") or not exp.exists(): return "NOT_RUN", ev + [E("verdict", "A TPM is present, but attestation needs tpm2-tools and feeds/expected_pcrs.json (the PCR values you expect).")]
    out = subprocess.run(["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"], capture_output=True, text=True, timeout=20).stdout; want = json.loads(exp.read_text()); got = {m.group(1): m.group(2).lower() for m in re.finditer(r"^\s*(\d+)\s*:\s*0x([0-9A-Fa-f]+)", out, re.M)}
    diff = [k for k, v in want.items() if got.get(str(k)) != v.lower().replace("0x", "")]; ev.append(E("PCRs 0-7", "all match your expected values" if not diff and got else "MISMATCH at " + ",".join(diff)))
    return ("PASS" if not diff and got else "FAIL"), ev

def inventory(ctx):
    py = [{"ecosystem": "PyPI", "name": d.metadata["Name"], "version": d.version} for d in importlib.metadata.distributions() if d.metadata["Name"]]
    return py + [{"ecosystem": "npm", **p} for p in ctx.get("node_inventory", [])]
def threat(ctx):
    f = ctx["root"] / "feeds" / "threat_feed.json"
    if not f.exists(): return "NOT_RUN", [E("feed", "There is no feeds/threat_feed.json, so there is nothing to cross-reference. Supply an OSV or CISA KEV file.")]
    d = json.loads(f.read_text(encoding="utf-8")); osv = d.get("vulns", []) if isinstance(d, dict) else d; kev = d.get("vulnerabilities", []) if isinstance(d, dict) else []; inv = inventory(ctx); hits = []
    for p in inv:
        for v in osv:
            if affected(v, p["ecosystem"], p["name"], p["version"]): hits.append(E("AFFECTED", p["ecosystem"] + " " + p["name"] + " " + p["version"] + " ← " + v.get("id", "?")))
        for k in kev:
            prod = norm(k.get("product", ""))
            if len(prod) >= 4 and prod == norm(p["name"]): hits.append(E("NAME MATCH (needs review)", p["name"] + " " + p["version"] + " ← " + k.get("cveID", "?") + " known exploited"))
    return ("FAIL" if hits else "PASS"), [E("inventory", str(len(inv)) + " components (" + str(sum(1 for p in inv if p["ecosystem"] == "PyPI")) + " Python, " + str(sum(1 for p in inv if p["ecosystem"] == "npm")) + " Node)"), E("feed", str(len(osv)) + " OSV records, " + str(len(kev)) + " KEV records")] + hits[:20]

def signature(ctx):
    fd = ctx["root"] / "feeds"; feed, sig, key = fd / "threat_feed.json", fd / "threat_feed.sig.json", fd / "feed_signing_public.pem"
    miss = [p.name for p in (feed, sig, key) if not p.exists()]
    if miss: return "NOT_RUN", [E("missing", ", ".join(miss)), E("verdict", "Nothing to verify: the feed, its detached signature and your public key are all required.")]
    s = json.loads(sig.read_text()); digest = hashlib.sha256(feed.read_bytes()).hexdigest(); ev = []
    if s.get("feed_sha256") != digest: return "FAIL", [E("digest", "the feed's SHA-256 does not match the signed digest")]
    n, e = rsa_pub_from_pem(key.read_text()); ok = rsa_ok(n, e, base64.urlsafe_b64decode(s["sig"] + "=" * (-len(s["sig"]) % 4)), ("feed_sha256=" + digest + ";signed_at=" + s["signed_at"]).encode())
    age = (time.time() - calendar.timegm(time.strptime(s["signed_at"][:19], "%Y-%m-%dT%H:%M:%S"))) / 86400; mx = float(ctx.get("max_age_days", 7))
    ev += [E("signature (RSA-SHA256)", "valid" if ok else "INVALID"), E("freshness", str(round(age, 1)) + " days old, limit " + str(mx))]
    return ("PASS" if ok and age <= mx else "FAIL"), ev

FN = {"core": core, "extended": extended, "hardware": hardware, "threat": threat, "signature": signature}
def run_all(ctx):
    led, out, rejected = ctx["ledger"], [], False; led.append("VALIDATOR", "RUN_START", None)
    for sid, name in STAGES:
        if rejected: out.append({"id": sid, "name": name, "status": "SKIPPED", "evidence": [E("why", "an earlier stage failed, so the flowchart rejected the system")], "ms": 0}); continue
        t0 = time.perf_counter()
        try: st, ev = FN[sid](ctx)
        except Exception as e: st, ev = "FAIL", [E("error", type(e).__name__ + ": " + str(e)[:160])]
        r = {"id": sid, "name": name, "status": st, "evidence": ev, "ms": round((time.perf_counter() - t0) * 1000)}; out.append(r); led.append("VALIDATOR", "STAGE_" + st, None, stage=sid, evidence_sha3_512=sha3(canon(ev))[:48])
        rejected = st == "FAIL"
    verdict = "REJECT" if any(r["status"] == "FAIL" for r in out) else "VALIDATED" if all(r["status"] == "PASS" for r in out) else "INCOMPLETE"
    led.append("VALIDATOR", "RUN_" + verdict, None); return {"verdict": verdict, "ended": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "stages": out}


SKIP_NAMES = {"MANIFEST.json", "COLLABORATION.md", "lanes.json"}
def write_manifest(root):
    """Record the SHA-256 of every shipped file. Run after any change: python3 validator.py --manifest"""
    root = Path(root); files = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.is_file() and rel.parts[0] not in ("data", "feeds") and rel.name not in SKIP_NAMES and "__pycache__" not in rel.parts and ".pytest_cache" not in rel.parts: files[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
    (root / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=1), encoding="utf-8"); return len(files)

if __name__ == "__main__" and "--manifest" in sys.argv: print("MANIFEST.json written for", write_manifest(Path(__file__).resolve().parent), "files")
