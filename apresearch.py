#!/usr/bin/env python3
"""
apresearch - an offline exploit-intelligence MODEL for AP vulnerability research.

Companion to markovgen, for the vuln side. Where `searchsploit` does an exact keyword grep and
returns nothing for an unusual AP, this model REASONS over the whole local exploit-db to produce
its own research: it finds the nearest analogues by similarity, predicts the most likely
vulnerability CLASSES for the device, and deep-mines those neighbours' exploit code to extract the
concrete endpoints / parameters / payloads worth testing. It is built to run continuously at low
priority so the capture box's idle CPU is actually put to work.

Model (pure standard library, no deps):
  * Corpus  = exploit-db entries (files_exploits.csv), filtered to AP/router-relevant types.
  * Features= word tokens + char 4-grams (the n-grams give fuzzy vendor/model matching, e.g. a
    model string that never appears verbatim still matches similar hardware).
  * Vectors = TF-IDF, cached to disk; query = the AP fingerprint terms; ranking = cosine similarity.
  * Classes = weighted vuln-class signatures scored over the nearest neighbours.
  * Deep pass = read the top-K neighbours' exploit source and extract URL paths, parameter names
    and payload markers -> a concrete, prioritised "what to test on this AP" plan.

Modes:
  build            (re)build + cache the TF-IDF index (CPU-heavy; run once, refreshes rarely)
  predict TERMS... one-shot: rank analogues + classes + test plan for the given fingerprint terms
  serve            continuous low-priority loop: keep the model warm, re-run predictions from the
                   latest AP fingerprints (written by apvulnd), rotate the deep-mine set, refine.
"""
import os, re, sys, csv, json, math, time, glob
from collections import defaultdict, Counter

EDB_DIR   = "/usr/share/exploitdb"
CSV_PATH  = EDB_DIR + "/files_exploits.csv"
EXP_ROOT  = EDB_DIR + "/exploits"
MODEL_DIR = "/opt/apvuln/model"
INDEX     = MODEL_DIR + "/exploit_index.json"
FP_DIR    = "/opt/apvuln/fingerprints"      # apvulnd drops <bssid>.json fingerprints here
OUT_DIR   = "/opt/apvuln/research"          # model writes <bssid>.txt research plans here

# AP/router-relevant exploit-db types; keeps the corpus lean + on-topic
RELEVANT_TYPES = {"webapps", "remote", "hardware", "dos", "local"}

# vulnerability-class signatures (keyword -> class); scored over nearest neighbours
VULN_CLASSES = {
    "command-injection":  ["command inject", "os command", "rce", "remote code", "shell", "exec ", "ping diag"],
    "auth-bypass":        ["auth bypass", "authentication bypass", "unauthenticated", "bypass", "improper auth"],
    "default-credentials":["default cred", "default password", "hardcoded", "backdoor", "hard-coded"],
    "csrf":               ["csrf", "cross-site request"],
    "xss":                ["xss", "cross site scripting", "cross-site scripting"],
    "path-traversal":     ["traversal", "directory traversal", "arbitrary file read", "lfi", "file disclosure"],
    "buffer-overflow":    ["overflow", "stack overflow", "heap overflow", "bof"],
    "info-disclosure":    ["disclosure", "information disclos", "info leak", "sensitive", "config download"],
    "ssrf":               ["ssrf", "server-side request"],
    "injection-other":    ["sql inject", "sqli", "xml inject", "format string"],
}

_word = re.compile(r"[a-z0-9]+")


def tokenize(text):
    text = text.lower()
    toks = _word.findall(text)
    grams = []
    collapsed = re.sub(r"[^a-z0-9]", "", text)
    for i in range(len(collapsed) - 3):        # char 4-grams -> fuzzy model/vendor matching
        grams.append("#" + collapsed[i:i + 4])
    return toks + grams


def build_index():
    os.makedirs(MODEL_DIR, exist_ok=True)
    if not os.path.exists(CSV_PATH):
        sys.stderr.write(f"no exploit-db csv at {CSV_PATH}\n"); return None
    docs = []       # (id, type, platform, path, description)
    with open(CSV_PATH, encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            if row.get("type") in RELEVANT_TYPES:
                docs.append((row.get("id"), row.get("type"), row.get("platform"),
                             row.get("file"), row.get("description", "")))
    df = defaultdict(int)
    doc_tf = []
    for _id, typ, plat, path, desc in docs:
        tf = Counter(tokenize(desc + " " + (plat or "") + " " + (typ or "")))
        doc_tf.append(tf)
        for term in tf:
            df[term] += 1
    N = len(docs)
    idf = {t: math.log((N + 1) / (c + 1)) + 1 for t, c in df.items()}
    vectors = []
    for tf in doc_tf:
        v = {t: (1 + math.log(c)) * idf[t] for t, c in tf.items()}
        norm = math.sqrt(sum(w * w for w in v.values())) or 1.0
        vectors.append({"v": v, "norm": norm})
    index = {"docs": [{"id": d[0], "type": d[1], "platform": d[2], "path": d[3], "desc": d[4]}
                      for d in docs],
             "idf": idf, "vectors": vectors, "N": N, "built": time.time()}
    with open(INDEX, "w") as f:
        json.dump(index, f)
    sys.stderr.write(f"[apresearch] index built: {N} exploit-db entries -> {INDEX}\n")
    return index


def load_index(rebuild_if_stale_days=30):
    if os.path.exists(INDEX):
        try:
            idx = json.load(open(INDEX))
            if time.time() - idx.get("built", 0) < rebuild_if_stale_days * 86400:
                return idx
        except Exception:
            pass
    return build_index()


def query_vector(terms, idf):
    tf = Counter()
    for term in terms:
        tf.update(tokenize(term))
    v = {t: (1 + math.log(c)) * idf.get(t, 0.0) for t, c in tf.items()}
    v = {t: w for t, w in v.items() if w > 0}
    norm = math.sqrt(sum(w * w for w in v.values())) or 1.0
    return v, norm


def rank(index, terms, topk=25):
    qv, qn = query_vector(terms, index["idf"])
    if not qv:
        return []
    scored = []
    for i, vec in enumerate(index["vectors"]):
        dv = vec["v"]
        # iterate the smaller vector
        small, big = (qv, dv) if len(qv) < len(dv) else (dv, qv)
        dot = sum(w * big.get(t, 0.0) for t, w in small.items())
        if dot > 0:
            scored.append((dot / (qn * vec["norm"]), i))
    scored.sort(reverse=True)
    return [(s, index["docs"][i]) for s, i in scored[:topk]]


def predict_classes(neighbours):
    scores = defaultdict(float)
    for sim, doc in neighbours:
        d = doc["desc"].lower()
        for cls, kws in VULN_CLASSES.items():
            if any(k in d for k in kws):
                scores[cls] += sim
    return sorted(scores.items(), key=lambda x: -x[1])


def deep_mine(neighbours, limit=40):
    """Read the nearest exploits' source and extract concrete testables: URL paths, parameter
    names, and payload markers. This is the CPU-using 'make its own data' pass."""
    paths, params, payloads = Counter(), Counter(), Counter()
    url_re   = re.compile(r"""["'/]((?:/[A-Za-z0-9._~-]+){1,6}(?:\.(?:cgi|php|asp|aspx|lua|html?|json|xml))?)""")
    param_re = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_]{1,30})=|["']([A-Za-z_][A-Za-z0-9_]{1,30})["']\s*[:=]""")
    pay_re   = re.compile(r"(;|\||`|\$\(|%3B|%7C|\.\./|<script|' OR |UNION SELECT|nc -e|/bin/sh)", re.I)
    for _sim, doc in neighbours[:limit]:
        p = doc.get("path")
        if not p:
            continue
        fp = os.path.join(EXP_ROOT, p)
        if not os.path.isfile(fp):
            continue
        try:
            txt = open(fp, encoding="utf-8", errors="ignore").read()[:200000]
        except Exception:
            continue
        for m in url_re.findall(txt):
            if "/" in m and len(m) > 3:
                paths[m] += 1
        for a, b in param_re.findall(txt):
            (params.update([a]) if a else params.update([b]))
        for m in pay_re.findall(txt):
            payloads[m] += 1
    return paths.most_common(15), params.most_common(20), payloads.most_common(10)


def research(index, bssid, fp):
    terms = [fp.get(k, "") for k in ("vendor", "wps_manuf", "wps_model", "wps_modelnum",
                                     "wps_device", "ssid")]
    terms += ["router", "access point", "wireless", "gateway", "wifi"]
    terms = [t for t in terms if t]
    neigh = rank(index, terms, topk=25)
    classes = predict_classes(neigh)
    paths, params, payloads = deep_mine(neigh)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    out = [f"apresearch self-generated research plan for {bssid}", f"generated: {now}",
           f"fingerprint terms: {', '.join(terms)}", "=" * 72, ""]
    out.append("NEAREST EXPLOIT-DB ANALOGUES (fuzzy similarity, not exact search):")
    if neigh:
        for sim, d in neigh[:12]:
            out.append(f"  {sim:.3f}  [{d['type']}/{d['platform']}] {d['desc']}  ({d['path']})")
    else:
        out.append("  (no similarity signal - fingerprint too sparse; need more beacon/service data)")
    out.append("")
    out.append("PREDICTED VULNERABILITY CLASSES (ranked):")
    for cls, sc in classes[:8]:
        out.append(f"  {sc:5.2f}  {cls}")
    out.append("")
    out.append("SELF-GENERATED TEST PLAN (mined from nearest exploits' code):")
    out.append("  candidate endpoints to probe:")
    out += [f"    {c:3d}x  {p}" for p, c in paths] or ["    (none extracted)"]
    out.append("  candidate parameters:")
    out.append("    " + ", ".join(f"{p}({c})" for p, c in params) if params else "    (none)")
    out.append("  payload/technique markers seen in analogues:")
    out.append("    " + ", ".join(f"{p!r}({c})" for p, c in payloads) if payloads else "    (none)")
    out.append("")
    out.append("These are HYPOTHESES to test when the AP is reachable (apvulnd discovery), not "
               "confirmed vulns. No target was contacted to produce this - it is offline inference.")
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, bssid.replace(":", "") + ".txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    return classes, neigh


def load_fingerprints():
    fps = {}
    if os.path.isdir(FP_DIR):
        for fjson in glob.glob(FP_DIR + "/*.json"):
            try:
                d = json.load(open(fjson))
                fps[d.get("bssid", os.path.basename(fjson))] = d
            except Exception:
                pass
    return fps


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "predict"
    if mode == "build":
        build_index(); return
    index = load_index()
    if not index:
        sys.stderr.write("no index/corpus available\n"); sys.exit(2)
    if mode == "predict":
        terms = sys.argv[2:] or ["router", "access point", "wireless"]
        classes, neigh = research(index, "adhoc-query", {"vendor": " ".join(terms)})
        for cls, sc in classes[:8]:
            print(f"{sc:5.2f}  {cls}")
        return
    if mode == "serve":
        # continuous low-priority research: keep re-running over the latest fingerprints, so the
        # Pi's idle cores stay productive rather than wasted.
        while True:
            fps = load_fingerprints()
            if not fps:
                time.sleep(300); continue
            for bssid, fp in fps.items():
                research(index, bssid, fp)
            time.sleep(600)
    sys.stderr.write("usage: apresearch.py [build|predict TERMS...|serve]\n"); sys.exit(2)


if __name__ == "__main__":
    main()
