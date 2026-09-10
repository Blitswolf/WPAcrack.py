#!/usr/bin/env python3
"""
apvulnd - slow-time, low-priority AP vulnerability research for the wpacrack stack.

Runs on the capture box (kali-pie) using spare CPU only (systemd Nice=19 + idle IO). It is
RECON + RESEARCH, never an active attack: it does NOT brute WPS PINs or touch the AP, so it can
never trip a lockout. It analyses the beacon frames already sitting in the harvest library and
correlates the AP's fingerprint with the local exploit database.

For each authorized target BSSID it:
  * pulls the fingerprint from the newest capture's beacons (tshark): vendor (OUI), WPS presence
    + locked state + Manufacturer/Model/Device, RSN AKM (WPA2-PSK vs WPA3-SAE), pairwise cipher
    (CCMP/TKIP), and PMF (management-frame protection) capable/required;
  * derives a security posture with findings (e.g. WPS enabled+unlocked = PIN-attack exposure;
    TKIP = weak cipher; no PMF = deauth/evil-twin exposure; WPA2-only = no SAE);
  * runs `searchsploit` against the manufacturer/model for known public exploits;
  * writes a timestamped report to REPORT.txt.

Config is shared with wpacrack (wpacrack.conf: targets, library). Pure standard library + tshark
+ searchsploit. Intended to be invoked by a systemd timer, slowly.
"""
import os, re, sys, subprocess, datetime, json, socket, time, urllib.request, urllib.error

_HERE = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else "/opt/apvuln"
CONF_PATHS = ["/opt/wpacrack/wpacrack.conf", os.path.join(_HERE, "wpacrack.conf")]
LIBRARY = "/opt/wpacrack/library"
REPORT  = "/opt/apvuln/REPORT.txt"
FINDINGS_DIR = "/opt/apvuln/findings"
FP_DIR  = "/opt/apvuln/fingerprints"   # drop fingerprints here for the apresearch model to consume
AP_MGMT_IP = ""      # from conf: ap_mgmt_ip - the AP's management IP (for self-discovery when reachable)
TARGETS = []


def load_conf():
    global LIBRARY, TARGETS, AP_MGMT_IP
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        sys.stderr.write("no wpacrack.conf\n"); sys.exit(2)
    cfg = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); cfg[k.strip().lower()] = v.strip()
    LIBRARY = cfg.get("library", LIBRARY)
    AP_MGMT_IP = cfg.get("ap_mgmt_ip", AP_MGMT_IP)
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
            bssid, _, ch = tok.rpartition(":")
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid.strip()):
                TARGETS.append(bssid.strip().upper())


def run(cmd, timeout=120):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def latest_cap(bssid):
    d = os.path.join(LIBRARY, bssid.replace(":", ""))
    caps = [os.path.join(d, f) for f in os.listdir(d)] if os.path.isdir(d) else []
    caps = [c for c in caps if c.endswith(".cap")]
    return max(caps, key=os.path.getmtime) if caps else None


def tfield(cap, bssid, field):
    """Return the set of distinct values of a tshark field across this BSSID's beacons."""
    r = run(["tshark", "-r", cap, "-n", "-Y",
             f"wlan.fc.type_subtype==0x08 && wlan.bssid=={bssid}",
             "-T", "fields", "-e", field], timeout=90)
    if not r or not r.stdout:
        return []
    vals = {v.strip() for v in r.stdout.split("\n") if v.strip()}
    return sorted(vals)


def first(vals):
    return vals[0] if vals else ""


def fingerprint(cap, bssid):
    fp = {"bssid": bssid}
    fp["vendor"]       = first(tfield(cap, bssid, "wlan.bssid_resolved")) or "(unresolved OUI)"
    fp["ssid"]         = first(tfield(cap, bssid, "wlan.ssid"))
    # WPS information element
    fp["wps_manuf"]    = first(tfield(cap, bssid, "wps.manufacturer"))
    fp["wps_model"]    = first(tfield(cap, bssid, "wps.model_name"))
    fp["wps_modelnum"] = first(tfield(cap, bssid, "wps.model_number"))
    fp["wps_device"]   = first(tfield(cap, bssid, "wps.device_name"))
    fp["wps_locked"]   = first(tfield(cap, bssid, "wps.ap_setup_locked"))
    fp["wps_present"]  = bool(fp["wps_manuf"] or fp["wps_model"] or fp["wps_device"]
                              or tfield(cap, bssid, "wps.version"))
    # RSN / crypto posture
    akms   = tfield(cap, bssid, "wlan.rsn.akms.type")     # 2=PSK, 8=SAE(WPA3)
    pcs    = tfield(cap, bssid, "wlan.rsn.pcs.type")      # 2=TKIP, 4=CCMP
    fp["akm"]   = akms
    fp["cipher"] = pcs
    fp["mfpc"]  = first(tfield(cap, bssid, "wlan.rsn.capabilities.mfpc"))  # PMF capable
    fp["mfpr"]  = first(tfield(cap, bssid, "wlan.rsn.capabilities.mfpr"))  # PMF required
    return fp


def assess(fp):
    findings = []
    if fp["wps_present"]:
        locked = fp["wps_locked"] in ("1", "True", "true")
        if not locked:
            findings.append(("HIGH", "WPS enabled and NOT locked - vulnerable to WPS PIN attack "
                                     "(Pixie-Dust / online PIN brute). [not auto-attacked: opt-in]"))
        else:
            findings.append(("INFO", "WPS enabled but currently locked."))
    if "2" in fp["cipher"]:
        findings.append(("MEDIUM", "TKIP pairwise cipher offered - weak/deprecated; prefer CCMP-only."))
    if "8" not in fp["akm"] and fp["akm"]:
        findings.append(("LOW", "WPA2-PSK only (no WPA3/SAE) - offline PSK cracking of a captured "
                                "handshake is feasible; SAE would prevent it."))
    if fp["mfpr"] not in ("1", "True", "true"):
        findings.append(("LOW", "PMF (802.11w) not required - deauthentication and evil-twin/"
                                "handshake-capture attacks are possible."))
    if not findings:
        findings.append(("INFO", "No posture findings from beacon analysis."))
    return findings


def cve_lookup(fp):
    terms = [t for t in {fp.get("wps_manuf"), fp.get("wps_model"), fp.get("wps_device")} if t]
    hits = []
    for term in terms:
        r = run(["searchsploit", "--json", term], timeout=60)
        if r and r.stdout:
            try:
                data = json.loads(r.stdout)
                for e in data.get("RESULTS_EXPLOIT", [])[:8]:
                    hits.append(f"{e.get('Title')}  [{e.get('Path')}]")
            except Exception:
                pass
    return terms, hits


def write_fingerprint(bssid, fp):
    """Persist the fingerprint as JSON so the apresearch model can reason over it (and later run
    scaled-up on the other Pi)."""
    os.makedirs(FP_DIR, exist_ok=True)
    path = os.path.join(FP_DIR, bssid.replace(":", "") + ".json")
    # MERGE into any existing record so aprecon's RF enrichment (real M1 device fields, client
    # inventory, in-scope PNL) survives this hourly write, and a real value is never clobbered by
    # an empty beacon value.
    existing = {}
    try:
        if os.path.exists(path):
            existing = json.load(open(path))
    except Exception:
        existing = {}
    rec = dict(fp); rec["bssid"] = bssid
    for k, v in rec.items():
        if isinstance(v, str) and not v and existing.get(k):
            continue
        existing[k] = v
    try:
        json.dump(existing, open(path, "w"), indent=2)
    except Exception:
        pass


def discover(ip):
    """Bounded, non-destructive active enumeration of the AP management interface, ONLY when it is
    reachable. No login brute and no crash-fuzzing (lockout + CPE fragility); GETs are rate-limited
    to <=1/s. Engages once the PSK is recovered and wlan1 can associate."""
    import ssl
    open_ports = []
    for p in (80, 443, 22, 23, 53, 7547, 8080, 8443):
        s = socket.socket(); s.settimeout(1.5)
        try:
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    if not open_ports:
        return [f"  (AP mgmt {ip} not reachable - discovery pending PSK + wlan1 association)"]
    os.makedirs(FINDINGS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    ff = os.path.join(FINDINGS_DIR, ip.replace(".", "_") + "-" + ts + ".txt")
    run(["nmap", "-Pn", "-sV", "--host-timeout", "240s", "--max-rate", "20",
         "-p", ",".join(map(str, open_ports)),
         "--script", "banner,http-title,http-headers,http-server-header,ssl-cert",
         "-oN", ff, ip], timeout=300)
    lines = [f"  reachable ports: {open_ports}  (full nmap: {ff})"]
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    for p in open_ports:
        base = f"http://{ip}:{p}" if p in (80, 8080) else (f"https://{ip}:{p}" if p in (443, 8443) else None)
        if not base:
            continue
        for path in ("/", "/login", "/cgi-bin/", "/status", "/api"):
            try:
                req = urllib.request.Request(base + path, headers={"User-Agent": "apvulnd/1.0"})
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                body = resp.read(4096).decode("latin-1", "ignore")
                anom = "traceback" in body.lower() or "stack trace" in body.lower()
                lines.append(f"    {base}{path} -> {resp.status} srv={resp.headers.get('Server','')}"
                             + (" [ANOMALY]" if anom else ""))
            except urllib.error.HTTPError as e:
                lines.append(f"    {base}{path} -> {e.code}")
            except Exception:
                lines.append(f"    {base}{path} -> err")
            time.sleep(1)   # rate-limit: gentle on fragile CPE web backends
    return lines


def main():
    load_conf()
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = [f"apvulnd AP vulnerability research report", f"generated: {now}",
           f"library: {LIBRARY}", "=" * 72, ""]
    for bssid in TARGETS:
        cap = latest_cap(bssid)
        out.append(f"### AP {bssid}")
        if not cap:
            out.append("  no capture in library yet (waiting for harvester).\n")
            continue
        fp = fingerprint(cap, bssid)
        out.append(f"  ssid      : {fp['ssid']}")
        out.append(f"  vendor    : {fp['vendor']}")
        if fp["wps_present"]:
            out.append(f"  wps       : present  manuf='{fp['wps_manuf']}' model='{fp['wps_model']}"
                       f"' modelnum='{fp['wps_modelnum']}' device='{fp['wps_device']}' "
                       f"locked={fp['wps_locked'] or '?'}")
        else:
            out.append("  wps       : not advertised")
        out.append(f"  akm       : {fp['akm']}   cipher: {fp['cipher']}   "
                   f"pmf_cap={fp['mfpc'] or '?'} pmf_req={fp['mfpr'] or '?'}")
        out.append(f"  source    : {os.path.basename(cap)}")
        out.append("  findings  :")
        for sev, msg in assess(fp):
            out.append(f"    [{sev}] {msg}")
        terms, hits = cve_lookup(fp)
        if terms:
            out.append(f"  searchsploit ({', '.join(terms)}):")
            out.extend([f"    - {h}" for h in hits] or ["    (no public exploit-db matches)"])
        write_fingerprint(bssid, fp)
        if not hits:
            rf = f"/opt/apvuln/research/{bssid.replace(':', '')}.txt"
            out.append(f"  no exact exploit-db match -> apresearch model generating analogues, "
                       f"vuln-class predictions + a mined test plan: {rf}")
        if AP_MGMT_IP:
            out.append(f"  active discovery ({AP_MGMT_IP}):")
            out += discover(AP_MGMT_IP)
        out.append("")
    out.append("NOTE: recon/research only - no WPS PIN brute, no association, no lockout risk.")
    out.append("When the PSK is recovered and wlan1 can associate, extend to on-LAN scans (nmap/nuclei).")
    with open(REPORT, "w") as f:
        f.write("\n".join(out) + "\n")
    # world-readable copy for quick SSH viewing
    try:
        with open("/root/apvuln_REPORT.txt", "w") as f:
            f.write("\n".join(out) + "\n")
    except Exception:
        pass
    print(f"apvulnd: wrote {REPORT} ({len(TARGETS)} target(s))")


if __name__ == "__main__":
    main()
