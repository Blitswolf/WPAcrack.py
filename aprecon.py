#!/usr/bin/env python3
"""
aprecon.py — RF-side recon ENRICHMENT for the AP research model (kali-pie). Direction-1 intel:
turn the research model's *generic* fingerprint into a *specific* one, without needing LAN access.

Two sources, both scope-locked to the authorized BSSID and radio-lock-coordinated with the harvest:

  1. PASSIVE (zero risk, monitor RX only): sniff the target BSSID's channel for a window and extract
       * connected-client inventory  — client MACs -> OUI vendor (device types on the network)
       * probe-request PNLs           — other SSIDs those clients look for (network intel + twin fodder)

  2. WPS M1 device read (LOCKOUT-SAFE): the AP sends M1 first, carrying its real Manufacturer / Model
     Name / Model Number / Device Name / Serial / OS / UUID. We read M1 and ABORT before any PIN is
     guessed (the PIN check is at M4/M6), so this adds NO failed-auth and cannot trip a WPS lockout.
     Gated: skipped if the BSSID is inside the WPS module's cooldown (wps_state), or if disabled.

It MERGES the results into /opt/apvuln/fingerprints/<bssid>.json (never clobbering apvulnd's fields),
so `apresearch` reasons over a real device (e.g. "Netgear R7000") instead of "a wireless AP" — which
is what finally populates its analogues + test plan. Report -> /opt/apvuln/aprecon/<bssid>.txt.
"""
import os, sys, re, time, json, signal, shutil, subprocess, fcntl, datetime, glob

CONF_PATHS = ["/opt/wpacrack/wpacrack.conf",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf")]
WORK       = "/opt/wpacrack"
RADIO_LOCK = WORK + "/.radio.lock"
WPS_STATE  = WORK + "/wps_state"
FP_DIR     = "/opt/apvuln/fingerprints"
OUT_DIR    = "/opt/apvuln/aprecon"
LOG        = "/opt/apvuln/aprecon.log"
STATUS     = "/opt/apvuln/APRECON_STATUS.txt"

IFACE      = "wlan1"
ESSID      = ""            # authorized lab ESSID — used to scope PNL collection to the lab
TARGETS    = []
SNIFF_SECS = 45            # passive capture window per target
WPS_M1     = True          # attempt the lockout-safe M1 device read
M1_TIMEOUT = 40            # hard cap on the M1 read (aborted well before any PIN)
RADIO_WAIT = 4200          # patience for the shared radio (harvest capture pass can be long)
RADIO_POLL = 30

_radio_fd = None


def now(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    line = f"[{now()}] {msg}\n"
    try:
        with open(LOG, "a") as f: f.write(line)
    except Exception: pass
    sys.stderr.write(line)

def set_status(phase, detail=""):
    try:
        with open(STATUS, "w") as f:
            f.write(f"aprecon STATUS @ {now()}\n  phase : {phase}\n  detail: {detail}\n  iface : {IFACE}\n")
    except Exception: pass
    log(f"{phase}: {detail}")

def _val(v): return str(v).split("#")[0].strip()

def published_channel(bssid, hint, ttl=21600):
    """Read the harvest-published current channel for this BSSID (BSSID-anchored rediscovery); fall
    back to the config hint if missing/stale. Keeps aprecon on the AP's real channel after a 2.4
    auto-channel change or a 5GHz DFS move."""
    try:
        ch, ts = open(os.path.join(WORK, "channels", bssid.replace(":", ""))).read().split()
        if time.time() - float(ts) < ttl:
            return int(ch)
    except Exception:
        pass
    return hint

def run(cmd, timeout=60):
    try: return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e: log(f"run error {cmd}: {e}"); return None


def load_conf():
    global IFACE, TARGETS, WPS_M1, SNIFF_SECS, ESSID
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        log("FATAL: no wpacrack.conf"); sys.exit(2)
    cfg = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); cfg[k.strip().lower()] = v.strip()
    IFACE = _val(cfg.get("iface", IFACE)) or IFACE
    ESSID = _val(cfg.get("essid", ""))
    if "aprecon_sniff_secs" in cfg:
        try: SNIFF_SECS = int(_val(cfg["aprecon_sniff_secs"]))
        except Exception: pass
    if "aprecon_wps_m1" in cfg:
        WPS_M1 = _val(cfg["aprecon_wps_m1"]).lower() in ("1", "true", "yes", "on")
    TARGETS = []
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
            bssid, _, ch = tok.rpartition(":")
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid.strip()) and ch.strip().isdigit():
                TARGETS.append((bssid.strip().upper(), int(ch.strip())))
    if not TARGETS:
        log("FATAL: no authorized targets in wpacrack.conf — refusing to run"); sys.exit(2)


# ---------------- radio coexistence (share wlan1 with the harvest/WPS/eviltwin) ----------------
def acquire_radio():
    global _radio_fd
    try: _radio_fd = open(RADIO_LOCK, "w")
    except Exception: return True
    t0 = time.time()
    while time.time() - t0 < RADIO_WAIT:
        try:
            fcntl.flock(_radio_fd, fcntl.LOCK_EX | fcntl.LOCK_NB); return True
        except OSError:
            set_status("wait-radio", f"harvest holds the radio; waiting {int(time.time()-t0)}s for spare time")
            time.sleep(RADIO_POLL)
    return False

def release_radio():
    global _radio_fd
    if _radio_fd:
        try: fcntl.flock(_radio_fd, fcntl.LOCK_UN); _radio_fd.close()
        except Exception: pass
        _radio_fd = None

def ensure_monitor(ch):
    info = run(["iw", "dev", IFACE, "info"])
    if "type monitor" not in (getattr(info, "stdout", "") or ""):
        run(["ip", "link", "set", IFACE, "down"])
        run(["iw", "dev", IFACE, "set", "type", "monitor"])
        run(["ip", "link", "set", IFACE, "up"])
    run(["iw", "dev", IFACE, "set", "channel", str(ch)])


def in_wps_cooldown(bssid):
    """Respect the WPS module's per-target back-off — never poke a BSSID it is protecting."""
    p = os.path.join(WPS_STATE, bssid.replace(":", "") + ".mark")
    if not os.path.exists(p): return False
    try:
        kind, ts = open(p).read().strip().split()
        window = 86400 if kind == "lock" else 21600
        return (time.time() - float(ts)) < window
    except Exception:
        return False


# ---------------- passive client / PNL enumeration (monitor RX only) ----------------
def passive_sniff(bssid, ch):
    ensure_monitor(ch)
    pcap = f"/tmp/aprecon_{bssid.replace(':','')}.pcap"
    set_status("passive-sniff", f"{bssid} ch{ch} — {SNIFF_SECS}s monitor capture (RX only)")
    cap = shutil.which("dumpcap") or shutil.which("tcpdump")
    if not cap:
        log("no dumpcap/tcpdump — skipping passive sniff"); return {}, []
    if cap.endswith("dumpcap"):
        run([cap, "-i", IFACE, "-a", f"duration:{SNIFF_SECS}", "-w", pcap], timeout=SNIFF_SECS + 20)
    else:
        run(["timeout", str(SNIFF_SECS), cap, "-i", IFACE, "-w", pcap], timeout=SNIFF_SECS + 20)
    if not os.path.exists(pcap):
        return {}, []
    clients = {}
    # data frames to/from the BSSID -> the other address is a client; resolve its OUI vendor
    r = run(["tshark", "-r", pcap, "-n", "-N", "m", "-Y",
             f"wlan.bssid=={bssid} && wlan.fc.type==2",
             "-T", "fields", "-e", "wlan.sa", "-e", "wlan.sa_resolved",
             "-e", "wlan.da", "-e", "wlan.da_resolved"], timeout=60)
    for line in (getattr(r, "stdout", "") or "").splitlines():
        cols = line.split("\t")
        for i in (0, 2):
            if i + 1 < len(cols):
                mac, name = cols[i].strip().lower(), (cols[i + 1].strip() if i + 1 < len(cols) else "")
                if mac and mac != bssid.lower() and mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                    clients.setdefault(mac, name or "?")
    # probe requests -> PNL, SCOPED TO THE LAB: keep a probed SSID only if it IS the lab ESSID, or
    # the prober is a device we already saw on the authorized BSSID. Neighbours' networks (from
    # ambient probe requests of devices not on our network) are dropped as out-of-scope.
    pnl, dropped = set(), 0
    r2 = run(["tshark", "-r", pcap, "-n", "-Y",
              "wlan.fc.type_subtype==4 && wlan.ssid!=\"\"",
              "-T", "fields", "-e", "wlan.sa", "-e", "wlan.ssid"], timeout=60)
    for line in (getattr(r2, "stdout", "") or "").splitlines():
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        sa, s = cols[0].strip().lower(), cols[1].strip()
        if not s:
            continue
        try:
            ssid = bytes.fromhex(s).decode("utf-8", "replace") if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 else s
        except Exception:
            ssid = s
        if ssid == ESSID or sa in clients:      # in-scope: our AP's name, or a device on our network
            pnl.add(ssid)
        else:
            dropped += 1
    try: os.remove(pcap)
    except Exception: pass
    log(f"passive: {len(clients)} client(s), {len(pnl)} in-scope PNL, {dropped} out-of-scope neighbour PNL dropped for {bssid}")
    return clients, sorted(x for x in pnl if x)


# ---------------- WPS M1 device read (lockout-safe: abort before any PIN) ----------------
M1_FIELDS = {
    "wps_manuf":    re.compile(r"Manufacturer\s*:\s*(.+)", re.I),
    "wps_model":    re.compile(r"Model Name\s*:\s*(.+)", re.I),
    "wps_modelnum": re.compile(r"Model Number\s*:\s*(.+)", re.I),
    "wps_device":   re.compile(r"Device Name\s*:\s*(.+)", re.I),
    "wps_serial":   re.compile(r"Serial Number\s*:\s*(.+)", re.I),
    "wps_os":       re.compile(r"OS Version\s*:\s*(.+)", re.I),
    "wps_uuid":     re.compile(r"UUID\s*:\s*([0-9a-fx]+)", re.I),
}
# if reaver reaches these, it is about to (or did) guess a PIN -> stop immediately (lockout safety)
PIN_MARKERS = [re.compile(p, re.I) for p in
               [r"trying pin", r"sending m[46]", r"pin count", r"\bWPS PIN:", r"WPS transaction",
                r"rate limit", r"\block(ed|ing)\b"]]

def wps_m1_read(bssid, ch):
    """Read the AP's M1 device attributes with reaver, then ABORT before any PIN attempt. Returns a
    dict of any device fields recovered. Never sends a PIN guess -> cannot contribute to a lockout."""
    if not (WPS_M1 and shutil.which("reaver")):
        return {}
    if in_wps_cooldown(bssid):
        log(f"{bssid}: inside the WPS module's cooldown — skipping M1 read (protecting the AP)"); return {}
    ensure_monitor(ch)
    set_status("wps-m1", f"{bssid} ch{ch} — reading M1 device attributes (no PIN, lockout-safe)")
    got = {}
    try:
        p = subprocess.Popen(["reaver", "-i", IFACE, "-b", bssid, "-c", str(ch), "-vv", "-N"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        log(f"reaver spawn failed: {e}"); return {}
    t0 = time.time()
    try:
        for line in p.stdout:
            if any(rx.search(line) for rx in PIN_MARKERS):
                log("M1 read: reaver about to guess a PIN -> aborting now (lockout safety)"); break
            for key, rx in M1_FIELDS.items():
                m = rx.search(line)
                if m and key not in got:
                    got[key] = m.group(1).strip()
            # stop as soon as we have the identifying pair, or on timeout
            if ("wps_manuf" in got and "wps_model" in got) or (time.time() - t0 > M1_TIMEOUT):
                break
    except Exception as e:
        log(f"M1 read stream error: {e}")
    finally:
        try: p.terminate(); p.wait(timeout=5)
        except Exception:
            try: p.kill()
            except Exception: pass
    if got: log(f"M1 device attributes for {bssid}: {got}")
    else:   log(f"no M1 device attributes recovered for {bssid} (AP quiet / no association)")
    return got


# ---------------- merge into the research fingerprint ----------------
def enrich_fingerprint(bssid, m1, clients, pnl):
    os.makedirs(FP_DIR, exist_ok=True); os.makedirs(OUT_DIR, exist_ok=True)
    fp_path = os.path.join(FP_DIR, bssid.replace(":", "") + ".json")
    fp = {}
    if os.path.exists(fp_path):
        try: fp = json.load(open(fp_path))
        except Exception: fp = {}
    # merge M1 device fields only when we actually recovered a value (never clobber apvulnd's beacon data)
    for k, v in m1.items():
        if v: fp[k] = v
    if any(m1.get(k) for k in ("wps_manuf", "wps_model", "wps_device")):
        fp["wps_present"] = True
    fp["aprecon_clients"] = [{"mac": m, "vendor": n} for m, n in sorted(clients.items())]
    fp["aprecon_pnl"] = pnl
    fp["aprecon_ts"] = now()
    json.dump(fp, open(fp_path, "w"), indent=2)
    # human-readable report
    rep = [f"aprecon RF-enrichment for {bssid}", f"generated: {now()}",
           "=" * 60,
           "WPS M1 device attributes (active read, no PIN):"]
    if m1:
        rep += [f"  {k:12s}: {v}" for k, v in m1.items()]
    else:
        rep.append("  (none recovered this pass)")
    rep.append(f"\nConnected clients ({len(clients)}):")
    rep += [f"  {m}  {n}" for m, n in sorted(clients.items())] or ["  (none seen)"]
    rep.append(f"\nProbe-request PNL ({len(pnl)}):")
    rep += [f"  {s}" for s in pnl] or ["  (none seen)"]
    rep.append("\nMerged into the research fingerprint -> apresearch will reason over the real device.")
    open(os.path.join(OUT_DIR, bssid.replace(":", "") + ".txt"), "w").write("\n".join(rep) + "\n")
    log(f"fingerprint enriched -> {fp_path}")


def trigger_apresearch(bssid):
    """Ask the research model to regenerate intel for this now-enriched fingerprint (best-effort;
    the serve loop would pick it up within ~10min anyway)."""
    ar = "/opt/apvuln/apresearch.py"
    if os.path.exists(ar):
        run(["python3", ar, "research", bssid], timeout=180)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    load_conf()
    set_status("init", f"targets={TARGETS}")
    if not acquire_radio():
        log("could not get the radio within budget (harvest busy) — retry next run. STOP."); return
    def on_sig(s, f): release_radio(); sys.exit(0)
    signal.signal(signal.SIGTERM, on_sig)
    try:
        for bssid, ch in TARGETS:
            ch = published_channel(bssid, ch)   # follow the AP if it changed channel
            try:
                clients, pnl = passive_sniff(bssid, ch)
                m1 = wps_m1_read(bssid, ch)
                enrich_fingerprint(bssid, m1, clients, pnl)
                trigger_apresearch(bssid)
            except Exception:
                import traceback; log("aprecon error:\n" + traceback.format_exc())
    finally:
        release_radio()
        set_status("done", "radio released to harvest (monitor preserved); fingerprints enriched")


if __name__ == "__main__":
    main()
